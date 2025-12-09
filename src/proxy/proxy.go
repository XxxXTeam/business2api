package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// tlsConfig 全局 TLS 配置，跳过证书验证
var tlsConfig = &tls.Config{InsecureSkipVerify: true}

// ProxyNode 代理节点
type ProxyNode struct {
	Raw       string // 原始链接
	Protocol  string // vmess, vless, ss, trojan, http, socks5, hysteria2, anytls
	Name      string
	Server    string
	Port      int
	UUID      string // vmess/vless
	AlterId   int    // vmess
	Security  string // vmess 加密方式 / vless: none,tls,reality
	Network   string // tcp, ws, grpc, kcp, quic, httpupgrade, splithttp, xhttp
	Path      string // ws/http path
	Host      string // ws/http host
	TLS       bool
	SNI       string
	Password  string // ss/trojan/anytls password
	Method    string // ss method
	Type      string // kcp/quic header type (none, srtp, utp, wechat-video, dtls, wireguard)
	Healthy   bool
	LastCheck time.Time
	LocalPort int

	// Reality 相关
	Flow        string // xtls-rprx-vision
	Fingerprint string // chrome, firefox, safari, ios, android, edge, 360, qq, random
	PublicKey   string // reality pbk
	ShortId     string // reality sid
	SpiderX     string // reality spx

	// ALPN
	ALPN string // h2, http/1.1
}

// InstanceStatus 实例状态
type InstanceStatus int

const (
	InstanceStatusIdle    InstanceStatus = iota // 空闲可用
	InstanceStatusInUse                         // 使用中
	InstanceStatusStopped                       // 已停止
)

// XrayInstance xray 实例
type XrayInstance struct {
	server    *core.Instance
	localPort int
	node      *ProxyNode
	running   bool
	ctx       context.Context
	cancel    context.CancelFunc
	status    InstanceStatus
	lastUsed  time.Time
	proxyURL  string // 缓存的代理URL
	mu        sync.Mutex
}

// ProxyManager 代理管理器
type ProxyManager struct {
	mu             sync.RWMutex
	nodes          []*ProxyNode
	healthyNodes   []*ProxyNode
	currentIndex   int
	basePort       int
	instances      map[int]*XrayInstance
	instancePool   []*XrayInstance // 预启动的实例池
	maxPoolSize    int             // 最大实例池大小
	subscribeURLs  []string
	proxyFiles     []string
	lastUpdate     time.Time
	updateInterval time.Duration
	checkInterval  time.Duration
	healthCheckURL string
	stopChan       chan struct{}
	ready          bool       // 代理池是否就绪
	readyCond      *sync.Cond // 就绪条件变量
	healthChecking bool       // 是否正在健康检查
}

var Manager = &ProxyManager{
	basePort:       10800,
	instances:      make(map[int]*XrayInstance),
	instancePool:   make([]*XrayInstance, 0),
	maxPoolSize:    5, // 默认预启动5个实例
	updateInterval: 30 * time.Minute,
	checkInterval:  5 * time.Minute,
	healthCheckURL: "https://www.google.com/generate_204",
	stopChan:       make(chan struct{}),
}

func init() {
	Manager.readyCond = sync.NewCond(&Manager.mu)
}

// IsReady 检查代理池是否就绪
func (pm *ProxyManager) IsReady() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.ready
}
func (pm *ProxyManager) WaitReady(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		pm.mu.RLock()
		ready := pm.ready
		healthyCount := len(pm.healthyNodes)
		pm.mu.RUnlock()

		if ready || healthyCount > 0 {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.ready || len(pm.healthyNodes) > 0
}

// SetReady 设置就绪状态
func (pm *ProxyManager) SetReady(ready bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.ready = ready
	if ready {
		pm.readyCond.Broadcast()
	}
}

// SetMaxPoolSize 设置最大实例池大小
func (pm *ProxyManager) SetMaxPoolSize(size int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if size > 0 {
		pm.maxPoolSize = size
	}
}

// InitInstancePool 初始化实例池（按需启动指定数量的代理实例）
func (pm *ProxyManager) InitInstancePool(count int) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.healthyNodes) == 0 && len(pm.nodes) == 0 {
		return fmt.Errorf("没有可用的代理节点")
	}

	if count > pm.maxPoolSize {
		count = pm.maxPoolSize
	}

	nodes := pm.healthyNodes
	if len(nodes) == 0 {
		nodes = pm.nodes
	}

	log.Printf("🔧 初始化代理实例池: 目标 %d 个实例", count)

	for i := 0; i < count && i < len(nodes); i++ {
		node := nodes[i%len(nodes)]
		instance, err := pm.startInstanceLocked(node)
		if err != nil {
			log.Printf("⚠️ 启动实例 %d 失败: %v", i, err)
			continue
		}
		instance.status = InstanceStatusIdle
		pm.instancePool = append(pm.instancePool, instance)
	}

	log.Printf("✅ 实例池初始化完成: %d 个实例就绪", len(pm.instancePool))
	return nil
}

func (pm *ProxyManager) SetXrayPath(path string) {
}

// AddSubscribeURL 添加订阅链接
func (pm *ProxyManager) AddSubscribeURL(url string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.subscribeURLs = append(pm.subscribeURLs, url)
}

// AddProxyFile 添加代理文件
func (pm *ProxyManager) AddProxyFile(path string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.proxyFiles = append(pm.proxyFiles, path)
}

// LoadAll 加载所有代理源
func (pm *ProxyManager) LoadAll() error {
	var allNodes []*ProxyNode

	// 从订阅加载
	for _, url := range pm.subscribeURLs {
		nodes, err := pm.loadFromURL(url)
		if err != nil {
			log.Printf("⚠️ 加载订阅失败 %s: %v", url, err)
			continue
		}
		allNodes = append(allNodes, nodes...)
	}

	// 从文件加载
	for _, file := range pm.proxyFiles {
		nodes, err := pm.loadFromFile(file)
		if err != nil {
			log.Printf("⚠️ 加载文件失败 %s: %v", file, err)
			continue
		}
		allNodes = append(allNodes, nodes...)
	}

	pm.mu.Lock()
	pm.nodes = allNodes
	pm.lastUpdate = time.Now()
	pm.mu.Unlock()

	log.Printf("✅ 共加载 %d 个代理节点", len(allNodes))
	return nil
}

type SubscriptionInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   int64
}

// parseSubscriptionUserinfo 解析 subscription-userinfo 头
func parseSubscriptionUserinfo(header string) *SubscriptionInfo {
	if header == "" {
		return nil
	}
	info := &SubscriptionInfo{}
	parts := strings.Split(header, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		value, _ := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		switch key {
		case "upload":
			info.Upload = value
		case "download":
			info.Download = value
		case "total":
			info.Total = value
		case "expire":
			info.Expire = value
		}
	}
	return info
}

// getRemainingTraffic 获取剩余流量（字节）
func (si *SubscriptionInfo) getRemainingTraffic() int64 {
	if si == nil || si.Total == 0 {
		return -1 // 未知
	}
	return si.Total - si.Upload - si.Download
}

// loadFromURL 从URL加载（检查流量信息，过滤0流量订阅）
func (pm *ProxyManager) loadFromURL(urlStr string) ([]*ProxyNode, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 检查订阅流量信息
	userinfo := resp.Header.Get("subscription-userinfo")
	if userinfo == "" {
		userinfo = resp.Header.Get("Subscription-Userinfo")
	}
	if subInfo := parseSubscriptionUserinfo(userinfo); subInfo != nil {
		remaining := subInfo.getRemainingTraffic()
		// usedGB := float64(subInfo.Upload+subInfo.Download) / (1024 * 1024 * 1024)
		// totalGB := float64(subInfo.Total) / (1024 * 1024 * 1024)
		// remainGB := float64(remaining) / (1024 * 1024 * 1024)

		// log.Printf("📊 [订阅] 流量信息: 已用 %.2fGB / 总共 %.2fGB, 剩余 %.2fGB", usedGB, totalGB, remainGB)

		// 过滤0流量订阅
		if remaining == 0 {
			return nil, fmt.Errorf("订阅流量已耗尽")
		}
		if remaining > 0 && remaining < 100*1024*1024 {
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return pm.parseContent(string(body))
}

// loadFromFile 从文件加载
func (pm *ProxyManager) loadFromFile(path string) ([]*ProxyNode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return pm.parseContent(string(data))
}

func (pm *ProxyManager) parseContent(content string) ([]*ProxyNode, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(content))
	if err == nil {
		content = string(decoded)
	}

	var nodes []*ProxyNode
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		node := pm.parseLine(line)
		if node != nil {
			nodes = append(nodes, node)
		}
	}

	return nodes, nil
}

// tryBase64Decode 尝试多种 base64 解码方式
func tryBase64Decode(s string) []byte {
	s = strings.TrimSpace(s)
	// 尝试标准 base64
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded
	}
	// 尝试 URL-safe base64
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded
	}
	// 尝试无填充的标准 base64
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded
	}
	// 尝试无填充的 URL-safe base64
	if decoded, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return decoded
	}
	return nil
}

// parseLine 解析单行
func (pm *ProxyManager) parseLine(line string) *ProxyNode {
	if strings.HasPrefix(line, "vmess://") {
		return parseVmess(line)
	}
	if strings.HasPrefix(line, "vless://") {
		return parseVless(line)
	}
	if strings.HasPrefix(line, "ss://") {
		return parseSS(line)
	}
	if strings.HasPrefix(line, "trojan://") {
		return parseTrojan(line)
	}
	if strings.HasPrefix(line, "hysteria2://") || strings.HasPrefix(line, "hy2://") {
		return parseHysteria2(line)
	}
	if strings.HasPrefix(line, "anytls://") {
		return parseAnyTLS(line)
	}
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") || strings.HasPrefix(line, "socks5://") {
		return parseDirectProxy(line)
	}
	return nil
}

// getStringFromMap 安全获取 map 中的字符串值
func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		switch s := v.(type) {
		case string:
			return s
		case float64:
			return strconv.FormatFloat(s, 'f', -1, 64)
		case int:
			return strconv.Itoa(s)
		}
	}
	return ""
}

// getIntFromMap 安全获取 map 中的整数值
func getIntFromMap(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		case string:
			i, _ := strconv.Atoi(n)
			return i
		}
	}
	return 0
}

// parseVmess 解析 vmess 链接
func parseVmess(link string) *ProxyNode {
	// vmess://base64(json)
	data := strings.TrimPrefix(link, "vmess://")
	decoded := tryBase64Decode(data)
	if decoded == nil {
		return nil
	}

	var config map[string]interface{}
	if err := json.Unmarshal(decoded, &config); err != nil {
		return nil
	}

	node := &ProxyNode{
		Raw:      link,
		Protocol: "vmess",
	}

	node.Name = getStringFromMap(config, "ps")
	node.Server = getStringFromMap(config, "add")
	node.Port = getIntFromMap(config, "port")
	node.UUID = getStringFromMap(config, "id")
	node.AlterId = getIntFromMap(config, "aid")

	// 加密方式
	node.Security = getStringFromMap(config, "scy")
	if node.Security == "" {
		node.Security = "auto"
	}

	// 传输协议
	node.Network = getStringFromMap(config, "net")
	if node.Network == "" {
		node.Network = "tcp"
	}

	// 路径和 Host
	node.Path = getStringFromMap(config, "path")
	node.Host = getStringFromMap(config, "host")

	// TLS 设置（支持多种写法）
	tlsVal := getStringFromMap(config, "tls")
	if tlsVal != "" && tlsVal != "none" && tlsVal != "0" && tlsVal != "false" {
		node.TLS = true
	}
	node.SNI = getStringFromMap(config, "sni")
	if node.SNI == "" && node.TLS {
		node.SNI = node.Host
	}

	// Header 类型（kcp/quic）
	node.Type = getStringFromMap(config, "type")

	if node.Server == "" || node.Port == 0 || node.UUID == "" {
		return nil
	}
	return node
}

// parseVless 解析 vless 链接
func parseVless(link string) *ProxyNode {
	// vless://uuid@server:port?params#name
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	port, _ := strconv.Atoi(u.Port())
	// URL 解码名称
	name, _ := url.QueryUnescape(u.Fragment)

	node := &ProxyNode{
		Raw:      link,
		Protocol: "vless",
		UUID:     u.User.Username(),
		Server:   u.Hostname(),
		Port:     port,
		Name:     name,
	}

	query := u.Query()

	// 传输协议（支持更多类型）
	node.Network = query.Get("type")
	if node.Network == "" {
		node.Network = "tcp"
	}

	// 安全类型
	node.Security = query.Get("security")
	if node.Security == "" {
		node.Security = "none"
	}
	if node.Security == "tls" || node.Security == "reality" {
		node.TLS = true
	}

	// Flow（XTLS）
	node.Flow = query.Get("flow")

	// 路径（需要 URL 解码）
	if path := query.Get("path"); path != "" {
		node.Path, _ = url.QueryUnescape(path)
	}

	// Host
	node.Host = query.Get("host")
	if node.Host == "" {
		node.Host = query.Get("sni")
	}

	// SNI
	node.SNI = query.Get("sni")
	if node.SNI == "" && node.TLS && node.Security != "reality" {
		node.SNI = node.Host
		if node.SNI == "" {
			node.SNI = node.Server
		}
	}

	// Fingerprint（TLS/Reality 指纹）
	node.Fingerprint = query.Get("fp")
	if node.Fingerprint == "" {
		node.Fingerprint = query.Get("fingerprint")
	}

	// Reality 相关参数
	if node.Security == "reality" {
		node.PublicKey = query.Get("pbk")
		node.ShortId = query.Get("sid")
		node.SpiderX = query.Get("spx")
		// Reality 必须有 SNI
		if node.SNI == "" {
			node.SNI = query.Get("serverName")
		}
	}

	// ALPN
	node.ALPN = query.Get("alpn")

	// Header 类型（kcp/quic 等）
	node.Type = query.Get("headerType")

	// GRPC 服务名
	if serviceName := query.Get("serviceName"); serviceName != "" && node.Network == "grpc" {
		node.Path = serviceName
	}

	// xhttp/splithttp/httpupgrade 的额外参数
	if node.Network == "xhttp" || node.Network == "splithttp" || node.Network == "httpupgrade" {
		if node.Path == "" {
			node.Path = "/"
		}
	}

	if node.Server == "" || node.Port == 0 || node.UUID == "" {
		return nil
	}
	return node
}

// parseSS 解析 ss 链接
func parseSS(link string) *ProxyNode {
	// 支持多种格式:
	// ss://base64(method:password)@host:port#name (SIP002)
	// ss://base64(method:password@host:port)#name (旧格式)
	// ss://method:password@host:port#name (明文格式)
	origLink := link
	link = strings.TrimPrefix(link, "ss://")

	var name string
	if idx := strings.Index(link, "#"); idx != -1 {
		name = link[idx+1:]
		link = link[:idx]
	}
	name, _ = url.QueryUnescape(name)

	node := &ProxyNode{
		Protocol: "shadowsocks",
		Name:     name,
	}

	// 尝试解析 SIP002 格式: base64(method:password)@host:port
	if atIdx := strings.LastIndex(link, "@"); atIdx != -1 {
		userInfo := link[:atIdx]
		hostPort := link[atIdx+1:]

		// 尝试 base64 解码 userInfo
		if decoded := tryBase64Decode(userInfo); decoded != nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				node.Method = parts[0]
				node.Password = parts[1]
			}
		} else {
			// 可能是明文格式 method:password
			parts := strings.SplitN(userInfo, ":", 2)
			if len(parts) == 2 {
				node.Method = parts[0]
				node.Password = parts[1]
			}
		}

		// 解析 host:port（可能包含 IPv6）
		if strings.HasPrefix(hostPort, "[") {
			// IPv6: [::1]:port
			if endBracket := strings.Index(hostPort, "]:"); endBracket != -1 {
				node.Server = hostPort[1:endBracket]
				node.Port, _ = strconv.Atoi(hostPort[endBracket+2:])
			}
		} else {
			parts := strings.Split(hostPort, ":")
			if len(parts) >= 2 {
				node.Server = parts[0]
				node.Port, _ = strconv.Atoi(parts[len(parts)-1])
			}
		}
	} else {
		// 旧格式: 整个内容是 base64 编码
		decoded := tryBase64Decode(link)
		if decoded == nil {
			return nil
		}
		// method:password@host:port
		decodedStr := string(decoded)
		if atIdx := strings.LastIndex(decodedStr, "@"); atIdx != -1 {
			userInfo := decodedStr[:atIdx]
			hostPort := decodedStr[atIdx+1:]

			parts := strings.SplitN(userInfo, ":", 2)
			if len(parts) == 2 {
				node.Method = parts[0]
				node.Password = parts[1]
			}

			hpParts := strings.Split(hostPort, ":")
			if len(hpParts) >= 2 {
				node.Server = hpParts[0]
				node.Port, _ = strconv.Atoi(hpParts[len(hpParts)-1])
			}
		}
	}

	node.Raw = origLink
	// 验证必要字段
	if node.Server == "" || node.Port == 0 || node.Method == "" {
		return nil
	}
	return node
}

// parseTrojan 解析 trojan 链接
func parseTrojan(link string) *ProxyNode {
	// trojan://password@server:port?params#name
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)
	node := &ProxyNode{
		Raw:      link,
		Protocol: "trojan",
		Password: u.User.Username(),
		Server:   u.Hostname(),
		Port:     port,
		Name:     name,
		TLS:      true, // trojan 默认 TLS
	}

	query := u.Query()
	node.SNI = query.Get("sni")
	if node.SNI == "" {
		node.SNI = node.Server
	}
	if host := query.Get("host"); host != "" {
		node.Host = host
	}

	// 传输协议
	node.Network = query.Get("type")
	if node.Network == "" {
		node.Network = "tcp"
	}

	// 路径
	if path := query.Get("path"); path != "" {
		node.Path, _ = url.QueryUnescape(path)
	}

	// Fingerprint
	node.Fingerprint = query.Get("fp")

	// ALPN
	node.ALPN = query.Get("alpn")

	if node.Server == "" || node.Port == 0 || node.Password == "" {
		return nil
	}
	return node
}

// parseHysteria2 解析 hysteria2/hy2 链接
func parseHysteria2(link string) *ProxyNode {
	// hysteria2://password@server:port?params#name
	// hy2://password@server:port?params#name
	link = strings.Replace(link, "hy2://", "hysteria2://", 1)
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)

	node := &ProxyNode{
		Raw:      link,
		Protocol: "hysteria2",
		Password: u.User.Username(),
		Server:   u.Hostname(),
		Port:     port,
		Name:     name,
		TLS:      true, // hysteria2 默认 TLS
	}

	query := u.Query()
	node.SNI = query.Get("sni")
	if node.SNI == "" {
		node.SNI = node.Server
	}

	// ALPN
	node.ALPN = query.Get("alpn")
	if node.ALPN == "" {
		node.ALPN = "h3"
	}

	// Fingerprint
	node.Fingerprint = query.Get("pinSHA256")

	// obfs
	if obfs := query.Get("obfs"); obfs != "" {
		node.Type = obfs
		node.Path = query.Get("obfs-password")
	}

	if node.Server == "" || node.Port == 0 || node.Password == "" {
		return nil
	}
	return node
}

// parseAnyTLS 解析 anytls 链接
func parseAnyTLS(link string) *ProxyNode {
	// anytls://password@server:port?params#name
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	port, _ := strconv.Atoi(u.Port())
	name, _ := url.QueryUnescape(u.Fragment)

	node := &ProxyNode{
		Raw:      link,
		Protocol: "anytls",
		Password: u.User.Username(),
		Server:   u.Hostname(),
		Port:     port,
		Name:     name,
		TLS:      true,
	}

	query := u.Query()
	node.SNI = query.Get("sni")
	if node.SNI == "" {
		node.SNI = query.Get("serverName")
	}
	if node.SNI == "" {
		node.SNI = node.Server
	}

	// Fingerprint
	node.Fingerprint = query.Get("fp")
	if node.Fingerprint == "" {
		node.Fingerprint = query.Get("fingerprint")
	}

	// ALPN
	node.ALPN = query.Get("alpn")

	// insecure
	if query.Get("allowInsecure") == "1" || query.Get("insecure") == "1" {
		// 标记跳过证书验证
	}

	if node.Server == "" || node.Port == 0 || node.Password == "" {
		return nil
	}
	return node
}

// parseDirectProxy 解析直接代理
func parseDirectProxy(link string) *ProxyNode {
	u, err := url.Parse(link)
	if err != nil {
		return nil
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 80
		}
	}

	return &ProxyNode{
		Raw:       link,
		Protocol:  u.Scheme,
		Server:    u.Hostname(),
		Port:      port,
		LocalPort: port, // 直接代理使用原端口
		Healthy:   true,
	}
}

// startInstanceLocked 内部方法：启动实例（需要持有锁）
func (pm *ProxyManager) startInstanceLocked(node *ProxyNode) (*XrayInstance, error) {
	// xray-core 不支持的协议，直接跳过
	if node.Protocol == "hysteria2" || node.Protocol == "hy2" || node.Protocol == "anytls" {
		return nil, fmt.Errorf("协议 %s 不被 xray-core 支持", node.Protocol)
	}

	// 直接代理不需要 xray
	if node.Protocol == "http" || node.Protocol == "https" || node.Protocol == "socks5" {
		return &XrayInstance{
			node:     node,
			running:  true,
			status:   InstanceStatusIdle,
			proxyURL: node.Raw,
			lastUsed: time.Now(),
		}, nil
	}

	// 分配端口（带重试）
	var localPort int
	for retry := 0; retry < 3; retry++ {
		localPort = pm.allocatePort()
		if localPort != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if localPort == 0 {
		return nil, fmt.Errorf("无可用端口")
	}

	// 生成 xray 配置
	xrayConfig := pm.buildXrayConfig(node, localPort)
	if xrayConfig == nil {
		return nil, fmt.Errorf("生成配置失败")
	}

	// 启动内置 xray
	ctx, cancel := context.WithCancel(context.Background())
	server, err := core.New(xrayConfig)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("创建 xray 实例失败: %w", err)
	}

	if err := server.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("启动 xray 失败: %w", err)
	}

	// 等待端口可用并验证
	proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", localPort)
	for i := 0; i < 10; i++ {
		time.Sleep(50 * time.Millisecond)
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", localPort), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
	}

	instance := &XrayInstance{
		server:    server,
		localPort: localPort,
		node:      node,
		running:   true,
		ctx:       ctx,
		cancel:    cancel,
		status:    InstanceStatusIdle,
		lastUsed:  time.Now(),
		proxyURL:  proxyURL,
	}
	pm.instances[localPort] = instance
	node.LocalPort = localPort
	return instance, nil
}

func (pm *ProxyManager) StartXray(node *ProxyNode) (string, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	instance, err := pm.startInstanceLocked(node)
	if err != nil {
		return "", err
	}
	return instance.proxyURL, nil
}
func (pm *ProxyManager) buildXrayConfig(node *ProxyNode, localPort int) *core.Config {
	jsonConfig := pm.generateXrayConfig(node, localPort)

	config, err := core.LoadConfig("json", strings.NewReader(jsonConfig))
	if err != nil {
		log.Printf("⚠️ 解析配置失败: %v", err)
		return nil
	}
	return config
}
func (pm *ProxyManager) allocatePort() int {
	for port := pm.basePort; port < pm.basePort+1000; port++ {
		if _, exists := pm.instances[port]; exists {
			continue
		}
		if pm.isPortAvailable(port) {
			return port
		}
	}
	return 0
}

// isPortAvailable 检查端口是否可用
func (pm *ProxyManager) isPortAvailable(port int) bool {
	// 尝试绑定 TCP
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	ln.Close()
	time.Sleep(10 * time.Millisecond)

	ln2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	ln2.Close()
	return true
}

// generateXrayConfig 生成 xray 配置
func (pm *ProxyManager) generateXrayConfig(node *ProxyNode, localPort int) string {
	var outbound string
	// mux 多路复用配置
	muxConfig := `"mux": {"enabled": true, "concurrency": 8}`

	switch node.Protocol {
	case "vmess":
		outbound = fmt.Sprintf(`{
			"protocol": "vmess",
			"settings": {
				"vnext": [{
					"address": "%s",
					"port": %d,
					"users": [{
						"id": "%s",
						"alterId": %d,
						"security": "%s"
					}]
				}]
			},
			"streamSettings": %s,
			%s
		}`, node.Server, node.Port, node.UUID, node.AlterId, node.Security, pm.generateStreamSettings(node), muxConfig)

	case "vless":
		// VLESS 支持 flow（XTLS）
		flowStr := ""
		if node.Flow != "" {
			flowStr = fmt.Sprintf(`,"flow": "%s"`, node.Flow)
		}
		// 如果使用 flow，禁用 mux
		muxStr := muxConfig
		if node.Flow != "" {
			muxStr = `"mux": {"enabled": false}`
		}
		outbound = fmt.Sprintf(`{
			"protocol": "vless",
			"settings": {
				"vnext": [{
					"address": "%s",
					"port": %d,
					"users": [{
						"id": "%s",
						"encryption": "none"%s
					}]
				}]
			},
			"streamSettings": %s,
			%s
		}`, node.Server, node.Port, node.UUID, flowStr, pm.generateStreamSettings(node), muxStr)

	case "shadowsocks":
		outbound = fmt.Sprintf(`{
			"protocol": "shadowsocks",
			"settings": {
				"servers": [{
					"address": "%s",
					"port": %d,
					"method": "%s",
					"password": "%s"
				}]
			},
			%s
		}`, node.Server, node.Port, node.Method, node.Password, muxConfig)

	case "trojan":
		outbound = fmt.Sprintf(`{
			"protocol": "trojan",
			"settings": {
				"servers": [{
					"address": "%s",
					"port": %d,
					"password": "%s"
				}]
			},
			"streamSettings": %s,
			%s
		}`, node.Server, node.Port, node.Password, pm.generateStreamSettings(node), muxConfig)
	}
	return fmt.Sprintf(`{
		"log": {
			"access": "none",
			"error": "none",
			"loglevel": "none",
			"dnsLog": false
		},
		"inbounds": [{
			"port": %d,
			"listen": "127.0.0.1",
			"protocol": "socks",
			"settings": {
				"udp": true
			}
		}],
		"outbounds": [%s]
	}`, localPort, outbound)
}

// generateStreamSettings 生成传输设置
func (pm *ProxyManager) generateStreamSettings(node *ProxyNode) string {
	network := node.Network
	if network == "" {
		network = "tcp"
	}

	var settings string
	switch network {
	case "ws":
		host := node.Host
		if host == "" {
			host = node.Server
		}
		settings = fmt.Sprintf(`"wsSettings": {"path": "%s", "headers": {"Host": "%s"}}`, node.Path, host)

	case "grpc":
		settings = fmt.Sprintf(`"grpcSettings": {"serviceName": "%s", "multiMode": true}`, node.Path)

	case "kcp", "mkcp":
		headerType := "none"
		if node.Type != "" {
			headerType = node.Type
		}
		settings = fmt.Sprintf(`"kcpSettings": {
			"mtu": 1350, "tti": 50, "uplinkCapacity": 12, "downlinkCapacity": 100,
			"congestion": false, "readBufferSize": 2, "writeBufferSize": 2,
			"header": {"type": "%s"}
		}`, headerType)

	case "quic":
		headerType := "none"
		if node.Type != "" {
			headerType = node.Type
		}
		settings = fmt.Sprintf(`"quicSettings": {"security": "none", "key": "", "header": {"type": "%s"}}`, headerType)

	case "httpupgrade":
		host := node.Host
		if host == "" {
			host = node.Server
		}
		path := node.Path
		if path == "" {
			path = "/"
		}
		settings = fmt.Sprintf(`"httpupgradeSettings": {"path": "%s", "host": "%s"}`, path, host)

	case "splithttp", "xhttp":
		host := node.Host
		if host == "" {
			host = node.Server
		}
		path := node.Path
		if path == "" {
			path = "/"
		}
		settings = fmt.Sprintf(`"splithttpSettings": {"path": "%s", "host": "%s"}`, path, host)

	case "h2", "http":
		host := node.Host
		if host == "" {
			host = node.Server
		}
		path := node.Path
		if path == "" {
			path = "/"
		}
		settings = fmt.Sprintf(`"httpSettings": {"path": "%s", "host": ["%s"]}`, path, host)

	default:
		settings = ""
	}

	// 安全设置
	security := "none"
	securitySettings := ""

	if node.Security == "reality" {
		// Reality 配置
		security = "reality"
		fp := node.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		sni := node.SNI
		if sni == "" {
			sni = node.Server
		}
		securitySettings = fmt.Sprintf(`, "realitySettings": {
			"serverName": "%s",
			"fingerprint": "%s",
			"publicKey": "%s",
			"shortId": "%s",
			"spiderX": "%s"
		}`, sni, fp, node.PublicKey, node.ShortId, node.SpiderX)
	} else if node.TLS {
		// TLS 配置
		security = "tls"
		sni := node.SNI
		if sni == "" {
			sni = node.Server
		}
		fp := node.Fingerprint
		alpn := node.ALPN

		tlsConfig := fmt.Sprintf(`"serverName": "%s", "allowInsecure": true`, sni)
		if fp != "" {
			tlsConfig += fmt.Sprintf(`, "fingerprint": "%s"`, fp)
		}
		if alpn != "" {
			// 解析 ALPN（可能是逗号分隔）
			alpnList := strings.Split(alpn, ",")
			alpnJSON := ""
			for i, a := range alpnList {
				if i > 0 {
					alpnJSON += ","
				}
				alpnJSON += fmt.Sprintf(`"%s"`, strings.TrimSpace(a))
			}
			tlsConfig += fmt.Sprintf(`, "alpn": [%s]`, alpnJSON)
		}
		securitySettings = fmt.Sprintf(`, "tlsSettings": {%s}`, tlsConfig)
	}

	if settings != "" {
		return fmt.Sprintf(`{"network": "%s", "security": "%s", %s%s}`, network, security, settings, securitySettings)
	}
	return fmt.Sprintf(`{"network": "%s", "security": "%s"%s}`, network, security, securitySettings)
}

// StopXray 停止 xray 实例
func (pm *ProxyManager) StopXray(localPort int) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if instance, ok := pm.instances[localPort]; ok {
		if instance.server != nil {
			instance.server.Close()
		}
		if instance.cancel != nil {
			instance.cancel()
		}
		instance.running = false
		delete(pm.instances, localPort)
	}
}

// StopAll 停止所有实例
func (pm *ProxyManager) StopAll() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for port, instance := range pm.instances {
		if instance.server != nil {
			instance.server.Close()
		}
		if instance.cancel != nil {
			instance.cancel()
		}
		delete(pm.instances, port)
	}
	log.Printf("🛑 所有 xray 实例已停止")
}

// CheckHealth 检查节点健康状态
func (pm *ProxyManager) CheckHealth(node *ProxyNode) bool {
	proxyURL, err := pm.StartXray(node)
	if err != nil {
		return false
	}
	defer func() {
		if node.Protocol != "http" && node.Protocol != "https" && node.Protocol != "socks5" {
			pm.StopXray(node.LocalPort)
		}
	}()

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	if proxyURL != "" {
		proxy, _ := url.Parse(proxyURL)
		transport.Proxy = http.ProxyURL(proxy)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	resp, err := client.Get(pm.healthCheckURL)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 204 || resp.StatusCode == 200
}

func (pm *ProxyManager) CheckAllHealth() {
	// 防止重复执行
	pm.mu.Lock()
	if pm.healthChecking {
		pm.mu.Unlock()
		return
	}
	pm.healthChecking = true
	hasSubscribes := len(pm.subscribeURLs) > 0
	pm.mu.Unlock()
	if hasSubscribes {
		if err := pm.LoadAll(); err != nil {
			log.Printf("⚠️ 刷新订阅失败: %v", err)
		}
	}

	pm.mu.Lock()
	nodes := make([]*ProxyNode, len(pm.nodes))
	copy(nodes, pm.nodes)
	pm.mu.Unlock()

	if len(nodes) == 0 {
		pm.mu.Lock()
		pm.healthChecking = false
		pm.mu.Unlock()
		pm.SetReady(true)
		return
	}

	var healthy []*ProxyNode
	var checked int32
	var wg sync.WaitGroup
	var mu sync.Mutex

	total := len(nodes)
	log.Printf("🔍 开始检查 %d 个节点...", total)
	sem := make(chan struct{}, 64)

	for _, node := range nodes {
		wg.Add(1)
		go func(n *ProxyNode) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			n.Healthy = pm.CheckHealth(n)
			n.LastCheck = time.Now()

			current := int(atomic.AddInt32(&checked, 1))

			mu.Lock()
			if n.Healthy {
				healthy = append(healthy, n)
				pm.mu.Lock()
				pm.healthyNodes = append(pm.healthyNodes, n)
				if !pm.ready && len(pm.healthyNodes) > 0 {
					pm.ready = true
					pm.readyCond.Broadcast()
				}
				pm.mu.Unlock()
			}
			healthyCount := len(healthy)
			mu.Unlock()

			// 每 50 个或完成时输出进度
			if current%50 == 0 || current == total {
				log.Printf("🔍 进度: %d/%d, 健康: %d", current, total, healthyCount)
			}
		}(node)
	}

	wg.Wait()

	pm.mu.Lock()
	pm.healthyNodes = healthy
	pm.healthChecking = false
	pm.ready = len(healthy) > 0
	pm.readyCond.Broadcast()
	pm.mu.Unlock()

	log.Printf("✅ 健康检查完成: %d/%d 节点可用", len(healthy), len(nodes))
}

// GetFromPool 从实例池获取一个空闲实例
func (pm *ProxyManager) GetFromPool() *XrayInstance {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// 查找空闲实例
	for _, inst := range pm.instancePool {
		inst.mu.Lock()
		if inst.status == InstanceStatusIdle && inst.running {
			inst.status = InstanceStatusInUse
			inst.lastUsed = time.Now()
			inst.mu.Unlock()
			return inst
		}
		inst.mu.Unlock()
	}
	return nil
}

// ReturnToPool 归还实例到池
func (pm *ProxyManager) ReturnToPool(inst *XrayInstance) {
	if inst == nil {
		return
	}
	inst.mu.Lock()
	inst.status = InstanceStatusIdle
	inst.mu.Unlock()
}

// ReleaseByURL 通过proxyURL释放实例
func (pm *ProxyManager) ReleaseByURL(proxyURL string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, inst := range pm.instancePool {
		inst.mu.Lock()
		if inst.proxyURL == proxyURL && inst.status == InstanceStatusInUse {
			inst.status = InstanceStatusIdle
			inst.mu.Unlock()
			return
		}
		inst.mu.Unlock()
	}
}

// Next 获取下一个健康代理（优先从池中获取）
func (pm *ProxyManager) Next() string {
	// 首先尝试从池中获取
	if inst := pm.GetFromPool(); inst != nil {
		return inst.proxyURL
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.healthyNodes) == 0 {
		// 如果没有健康节点，尝试使用所有节点
		if len(pm.nodes) == 0 {
			return ""
		}
		node := pm.nodes[pm.currentIndex%len(pm.nodes)]
		pm.currentIndex++

		// 尝试启动新实例
		instance, err := pm.startInstanceLocked(node)
		if err != nil {
			log.Printf("⚠️ 启动代理失败: %v", err)
			return ""
		}
		instance.status = InstanceStatusInUse
		pm.instancePool = append(pm.instancePool, instance)
		return instance.proxyURL
	}

	node := pm.healthyNodes[pm.currentIndex%len(pm.healthyNodes)]
	pm.currentIndex++

	// 启动新实例
	instance, err := pm.startInstanceLocked(node)
	if err != nil {
		log.Printf("⚠️ 启动代理失败: %v", err)
		return ""
	}
	instance.status = InstanceStatusInUse

	// 控制池大小
	if len(pm.instancePool) < pm.maxPoolSize {
		pm.instancePool = append(pm.instancePool, instance)
	}
	return instance.proxyURL
}

// PoolStats 返回实例池统计
func (pm *ProxyManager) PoolStats() map[string]int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	idle, inUse := 0, 0
	for _, inst := range pm.instancePool {
		inst.mu.Lock()
		switch inst.status {
		case InstanceStatusIdle:
			idle++
		case InstanceStatusInUse:
			inUse++
		}
		inst.mu.Unlock()
	}
	return map[string]int{
		"idle":   idle,
		"in_use": inUse,
		"total":  len(pm.instancePool),
	}
}

// Count 获取代理数量
func (pm *ProxyManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if len(pm.healthyNodes) > 0 {
		return len(pm.healthyNodes)
	}
	return len(pm.nodes)
}

// HealthyCount 获取健康代理数量
func (pm *ProxyManager) HealthyCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.healthyNodes)
}

// TotalCount 获取总代理数量
func (pm *ProxyManager) TotalCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.nodes)
}

// StartAutoUpdate 启动自动更新和健康检查
func (pm *ProxyManager) StartAutoUpdate() {
	// 自动更新订阅
	go func() {
		for {
			time.Sleep(pm.updateInterval)
			if len(pm.subscribeURLs) > 0 || len(pm.proxyFiles) > 0 {
				if err := pm.LoadAll(); err != nil {
					log.Printf("⚠️ 自动更新代理失败: %v", err)
				}
			}
		}
	}()

	// 后台健康检查（启动时立即开始，不阻塞）
	go func() {
		// 延迟几秒后开始首次检查
		time.Sleep(3 * time.Second)
		pm.CheckAllHealth()

		// 定期检查
		for {
			time.Sleep(pm.checkInterval)
			pm.CheckAllHealth()
		}
	}()
}

// SetProxies 直接设置代理（兼容旧接口）
func (pm *ProxyManager) SetProxies(proxies []string) {
	var nodes []*ProxyNode
	for _, p := range proxies {
		if node := pm.parseLine(p); node != nil {
			nodes = append(nodes, node)
		}
	}
	pm.mu.Lock()
	pm.nodes = nodes
	pm.healthyNodes = nodes // 假设都健康
	pm.mu.Unlock()
	log.Printf("✅ 代理池已设置 %d 个代理", len(nodes))
}

const (
	autoRegisterURL      = "https://jgpyjc.top/api/v1/passport/auth/register"
	autoSubscribeBaseURL = "https://bb1.jgpyjc.top/api/v1/client/subscribe?token="
	autoRegisterInterval = 1 * time.Hour
)

// AutoSubscriber 自动订阅管理器
type AutoSubscriber struct {
	mu              sync.RWMutex
	currentToken    string
	subscribeURL    string
	lastRefresh     time.Time
	running         bool
	stopChan        chan struct{}
	proxyManager    *ProxyManager
	refreshInterval time.Duration
}

var autoSubscriber = &AutoSubscriber{
	refreshInterval: autoRegisterInterval,
	stopChan:        make(chan struct{}),
}

// randString 生成随机字符串
func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		r, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		out[i] = letters[r.Int64()]
	}
	return string(out)
}

// ungzipIfNeeded 解压 gzip 数据
func ungzipIfNeeded(data []byte, header http.Header) ([]byte, error) {
	ce := strings.ToLower(header.Get("Content-Encoding"))
	if ce == "gzip" || (len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b) {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	}
	return data, nil
}

// extractToken 从响应中提取 token
func extractToken(body []byte) string {
	var j interface{}
	if err := json.Unmarshal(body, &j); err != nil {
		return ""
	}

	var walk func(interface{}) string
	walk = func(x interface{}) string {
		switch v := x.(type) {
		case map[string]interface{}:
			for _, key := range []string{"token", "access_token", "data", "result", "auth", "jwt"} {
				if val, ok := v[key]; ok {
					if s, ok2 := val.(string); ok2 && s != "" {
						return s
					}
					if res := walk(val); res != "" {
						return res
					}
				}
			}
			// 检查 JWT 格式
			for _, val := range v {
				if s, ok := val.(string); ok && looksLikeJWT(s) {
					return s
				}
			}
		case []interface{}:
			for _, item := range v {
				if res := walk(item); res != "" {
					return res
				}
			}
		}
		return ""
	}
	return walk(j)
}

// looksLikeJWT 判断是否像 JWT
func looksLikeJWT(s string) bool {
	parts := strings.Count(s, ".")
	return parts >= 2 && len(s) > 30
}

// 常见邮箱域名
var emailDomains = []string{
	"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
	"protonmail.com", "mail.com", "zoho.com", "aol.com", "yandex.com",
	"163.com", "qq.com", "126.com", "sina.com", "foxmail.com",
}

// doAutoRegister 执行一次自动注册
func doAutoRegister() (email, password, token string, err error) {
	// 随机邮箱：随机用户名 + 随机域名
	domainIdx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(emailDomains))))
	email = randString(8+int(domainIdx.Int64()%5)) + "@" + emailDomains[domainIdx.Int64()]
	password = randString(20)

	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	form.Set("invite_code", "odtRDsfd")
	form.Set("email_code", "")

	req, err := http.NewRequest("POST", autoRegisterURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 10)")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://jgpyjc.top")
	req.Header.Set("Referer", "https://jgpyjc.top/")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return email, password, "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return email, password, "", err
	}

	body, err := ungzipIfNeeded(raw, resp.Header)
	if err != nil {
		body = raw
	}

	token = extractToken(body)
	if token == "" {
		s := strings.TrimSpace(string(body))
		if looksLikeJWT(s) {
			token = s
		}
	}

	if token == "" {
		return email, password, "", fmt.Errorf("未能从响应中提取 token: %s", string(body[:min(200, len(body))]))
	}
	return email, password, token, nil
}

// refreshSubscription 刷新订阅
func (as *AutoSubscriber) refreshSubscription() error {

	_, _, token, err := doAutoRegister()
	if err != nil {
		return fmt.Errorf("注册失败: %w", err)
	}

	subscribeURL := autoSubscribeBaseURL + token

	as.mu.Lock()
	as.currentToken = token
	as.subscribeURL = subscribeURL
	as.lastRefresh = time.Now()
	as.mu.Unlock()
	// 加载订阅到代理池
	if as.proxyManager != nil {
		if err := as.loadToProxyManager(); err != nil {
		}
	}

	return nil
}

func (as *AutoSubscriber) loadToProxyManager() error {
	as.mu.RLock()
	subURL := as.subscribeURL
	as.mu.RUnlock()

	if subURL == "" {
		return fmt.Errorf("订阅URL为空")
	}

	nodes, err := as.proxyManager.loadFromURL(subURL)
	if err != nil {
		return err
	}

	if len(nodes) == 0 {
		return fmt.Errorf("订阅中没有可用节点")
	}

	as.proxyManager.mu.Lock()
	as.proxyManager.nodes = append(as.proxyManager.nodes, nodes...)
	as.proxyManager.mu.Unlock()
	go as.proxyManager.CheckAllHealth()

	return nil
}
func (as *AutoSubscriber) Start(pm *ProxyManager) {
	as.mu.Lock()
	if as.running {
		as.mu.Unlock()
		return
	}
	as.running = true
	as.proxyManager = pm
	as.stopChan = make(chan struct{})
	as.mu.Unlock()
	go func() {
		if err := as.refreshSubscription(); err != nil {
		}

		ticker := time.NewTicker(as.refreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-as.stopChan:
				return
			case <-ticker.C:
				if err := as.refreshSubscription(); err != nil {
					log.Printf("❌ [自动订阅] 刷新失败: %v", err)
				}
			}
		}
	}()
}

func (as *AutoSubscriber) Stop() {
	as.mu.Lock()
	defer as.mu.Unlock()

	if as.running {
		close(as.stopChan)
		as.running = false
	}
}

func (as *AutoSubscriber) GetCurrentSubscribeURL() string {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.subscribeURL
}

func (as *AutoSubscriber) GetCurrentToken() string {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return as.currentToken
}
func (as *AutoSubscriber) IsExpired() bool {
	as.mu.RLock()
	defer as.mu.RUnlock()
	return time.Since(as.lastRefresh) > 2*time.Hour
}
func (pm *ProxyManager) StartAutoSubscribe() {
	autoSubscriber.Start(pm)
}
func (pm *ProxyManager) StopAutoSubscribe() {
	autoSubscriber.Stop()
}
func (pm *ProxyManager) GetAutoSubscribeURL() string {
	return autoSubscriber.GetCurrentSubscribeURL()
}
func (pm *ProxyManager) HasAutoSubscribe() bool {
	return autoSubscriber.GetCurrentToken() != ""
}
