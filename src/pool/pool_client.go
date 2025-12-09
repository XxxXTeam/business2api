package pool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"business2api/src/logger"

	"github.com/gorilla/websocket"
)

type BrowserRegisterResult struct {
	Success       bool
	Email         string
	FullName      string
	SecureCookies []Cookie
	Authorization string
	ConfigID      string
	CSESIDX       string
	Error         error
}

// RunBrowserRegisterFunc 注册函数类型
type RunBrowserRegisterFunc func(headless bool, proxy string, id int) *BrowserRegisterResult

var (
	RunBrowserRegister RunBrowserRegisterFunc
	ClientHeadless     bool
	ClientProxy        string
	GetClientProxy     func() string                    // 获取代理的函数
	ReleaseProxy       func(proxyURL string)            // 释放代理的函数
	DefaultProxyCount  = 3                              // 客户端模式默认启动的代理实例数
	IsProxyReady       func() bool                      // 检查代理是否就绪
	WaitProxyReady     func(timeout time.Duration) bool // 等待代理就绪
	GetHealthyCount    func() int                       // 获取健康代理数量
	proxyReadyTimeout  = 60 * time.Second               // 代理就绪超时时间
)

// PoolClient 号池客户端
type PoolClient struct {
	config    PoolServerConfig
	conn      *websocket.Conn
	send      chan []byte
	done      chan struct{}
	reconnect chan struct{}
	stopPump  chan struct{} // 停止当前pump
	mu        sync.Mutex
	writeMu   sync.Mutex // WebSocket写入锁
	isRunning bool
}

// NewPoolClient 创建号池客户端
func NewPoolClient(config PoolServerConfig) *PoolClient {
	return &PoolClient{
		config:    config,
		send:      make(chan []byte, 256),
		done:      make(chan struct{}),
		reconnect: make(chan struct{}, 1),
	}
}

// Start 启动客户端
func (pc *PoolClient) Start() error {
	pc.mu.Lock()
	pc.isRunning = true
	pc.mu.Unlock()

	// 连接循环
	for pc.isRunning {
		if err := pc.connect(); err != nil {
			logger.Warn("连接服务器失败: %v, 5秒后重试...", err)
			time.Sleep(5 * time.Second)
			continue
		}
		pc.work()
		select {
		case <-pc.done:
			return nil
		case <-pc.reconnect:
			log.Printf("[PoolClient] 准备重连...")
			time.Sleep(2 * time.Second)
		}
	}

	return nil
}
func (pc *PoolClient) Stop() {
	pc.mu.Lock()
	pc.isRunning = false
	pc.mu.Unlock()
	close(pc.done)
}

// connect 连接到服务器
func (pc *PoolClient) connect() error {
	u, err := url.Parse(pc.config.ServerAddr)
	if err != nil {
		return fmt.Errorf("解析服务器地址失败: %w", err)
	}
	wsScheme := "ws"
	if u.Scheme == "https" {
		wsScheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s/ws", wsScheme, u.Host)
	if pc.config.Secret != "" {
		wsURL += "?secret=" + pc.config.Secret
	}

	logger.Debug("连接到 %s", wsURL)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("WebSocket连接失败: %w", err)
	}

	pc.conn = conn

	// 发送就绪消息
	pc.sendMessage(WSMessage{
		Type:      WSMsgClientReady,
		Timestamp: time.Now().Unix(),
	})

	return nil
}
func (pc *PoolClient) work() {
	// 创建新的stopPump channel
	pc.stopPump = make(chan struct{})

	// 启动三个独立线程
	go pc.writePump()     // 消息发送
	go pc.heartbeatPump() // 独立心跳保活
	pc.readPump()         // 消息读取（阻塞）

	// readPump退出后，关闭stopPump通知其他线程退出
	close(pc.stopPump)
}

// heartbeatPump 独立心跳保活线程，只要连接存在就周期发心跳
func (pc *PoolClient) heartbeatPump() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pc.done:
			return
		case <-pc.stopPump:
			return
		case <-ticker.C:
			// 发送心跳保持连接活跃
			pc.writeMu.Lock()
			pc.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err := pc.conn.WriteMessage(websocket.PingMessage, nil)
			pc.writeMu.Unlock()
			if err != nil {
				logger.Debug("[PoolClient] 心跳发送失败: %v", err)
				return
			}
		}
	}
}
func (pc *PoolClient) writePump() {
	// 任务请求间隔60秒
	taskTicker := time.NewTicker(60 * time.Second)
	defer taskTicker.Stop()

	for {
		select {
		case <-pc.done:
			return
		case <-pc.stopPump:
			return
		case message := <-pc.send:
			pc.writeMu.Lock()
			pc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			err := pc.conn.WriteMessage(websocket.TextMessage, message)
			pc.writeMu.Unlock()
			if err != nil {
				log.Printf("[PoolClient] 发送消息失败: %v", err)
				pc.triggerReconnect()
				return
			}
		case <-taskTicker.C:
			// 定期请求任务
			pc.sendMessage(WSMessage{
				Type:      WSMsgRequestTask,
				Timestamp: time.Now().Unix(),
			})
		}
	}
}

// readPump 读取消息
func (pc *PoolClient) readPump() {
	defer func() {
		pc.conn.Close()
		pc.triggerReconnect()
	}()

	// 延长读取超时到240秒（4分钟），确保不会因为任务执行而断开
	pc.conn.SetReadDeadline(time.Now().Add(240 * time.Second))
	pc.conn.SetPongHandler(func(string) error {
		pc.conn.SetReadDeadline(time.Now().Add(240 * time.Second))
		return nil
	})

	for {
		_, message, err := pc.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[PoolClient] 读取错误: %v", err)
			}
			return
		}

		// 收到消息时重置读取超时
		pc.conn.SetReadDeadline(time.Now().Add(240 * time.Second))

		var msg WSMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		pc.handleMessage(msg)
	}
}

// handleMessage 处理服务器消息
func (pc *PoolClient) handleMessage(msg WSMessage) {
	switch msg.Type {
	case WSMsgHeartbeat:
		// 立即响应心跳
		pc.sendMessage(WSMessage{
			Type:      WSMsgHeartbeatAck,
			Timestamp: time.Now().Unix(),
		})

	case WSMsgTaskRegister:
		// 注册任务（独立心跳线程已保活，无需额外处理）
		go pc.handleRegisterTask(msg.Data)

	case WSMsgTaskRefresh:
		// 续期任务
		go pc.handleRefreshTask(msg.Data)

	case WSMsgStatus:
		// 状态同步
		logger.Debug("收到状态同步: %v", msg.Data)
	}
}

// handleRegisterTask 处理注册任务
func (pc *PoolClient) handleRegisterTask(data map[string]interface{}) {
	count := 1
	if c, ok := data["count"].(float64); ok {
		count = int(c)
	}

	logger.Info("收到注册任务: %d 个账号", count)
	if GetHealthyCount != nil && GetHealthyCount() >= 1 {
	} else if WaitProxyReady != nil {
		if !WaitProxyReady(proxyReadyTimeout) {
			logger.Warn("代理未就绪，使用静态代理: %s", ClientProxy)
		}
	}

	for i := 0; i < count; i++ {
		// 获取代理（优先使用代理池）
		currentProxy := ClientProxy
		if GetClientProxy != nil {
			currentProxy = GetClientProxy()
		}
		logger.Info("[注册 %d] 使用代理: %s", i, currentProxy)
		result := RunBrowserRegister(ClientHeadless, currentProxy, i)

		// 任务完成后释放代理
		if ReleaseProxy != nil && currentProxy != "" && currentProxy != ClientProxy {
			ReleaseProxy(currentProxy)
		}

		if result.Success {
			// 上传账号到服务器
			if err := pc.uploadAccount(result, true); err != nil {
				logger.Error("上传注册结果失败: %v", err)
				pc.sendRegisterResult(false, "", err.Error())
			} else {
				logger.Info("✅ 注册成功: %s", result.Email)
				pc.sendRegisterResult(true, result.Email, "")
			}
		} else {
			errMsg := "未知错误"
			if result.Error != nil {
				errMsg = result.Error.Error()
			}
			logger.Warn("❌ 注册失败: %s", errMsg)
			pc.sendRegisterResult(false, "", errMsg)
		}
	}
}

// handleRefreshTask 处理续期任务
func (pc *PoolClient) handleRefreshTask(data map[string]interface{}) {
	email, _ := data["email"].(string)
	if email == "" {
		logger.Warn("续期任务缺少email")
		return
	}

	logger.Info("收到续期任务: %s", email)

	// 检查代理：如果已有健康代理则不等待
	if GetHealthyCount != nil && GetHealthyCount() >= 1 {
		// 已有健康代理，直接开始
	} else if WaitProxyReady != nil {
		if !WaitProxyReady(proxyReadyTimeout) {
			logger.Warn("代理未就绪，使用静态代理: %s", Proxy)
		}
	}

	// 构建临时账号对象
	acc := &Account{
		Data: AccountData{
			Email: email,
		},
	}

	// 从data中提取cookies
	if cookiesData, ok := data["cookies"].([]interface{}); ok {
		for _, c := range cookiesData {
			if cm, ok := c.(map[string]interface{}); ok {
				acc.Data.Cookies = append(acc.Data.Cookies, Cookie{
					Name:   getString(cm, "name"),
					Value:  getString(cm, "value"),
					Domain: getString(cm, "domain"),
				})
			}
		}
	}

	if auth, ok := data["authorization"].(string); ok {
		acc.Data.Authorization = auth
	}
	if configID, ok := data["config_id"].(string); ok {
		acc.ConfigID = configID
	}
	if csesidx, ok := data["csesidx"].(string); ok {
		acc.CSESIDX = csesidx
	}

	// 获取代理（优先使用代理池）
	currentProxy := Proxy
	if GetClientProxy != nil {
		currentProxy = GetClientProxy()
	}

	// 执行浏览器刷新
	result := RefreshCookieWithBrowser(acc, BrowserRefreshHeadless, currentProxy)

	// 任务完成后释放代理
	if ReleaseProxy != nil && currentProxy != "" && currentProxy != Proxy {
		ReleaseProxy(currentProxy)
	}

	if result.Success {
		logger.Info("✅ 账号续期成功: %s", email)

		// 使用刷新后的新值（如果有的话）
		authorization := acc.Data.Authorization
		if result.Authorization != "" {
			authorization = result.Authorization
		}
		configID := acc.ConfigID
		if result.ConfigID != "" {
			configID = result.ConfigID
		}
		csesidx := acc.CSESIDX
		if result.CSESIDX != "" {
			csesidx = result.CSESIDX
		}

		// 上传更新后的账号数据到服务器
		uploadReq := &AccountUploadRequest{
			Email:         email,
			Cookies:       result.SecureCookies,
			Authorization: authorization,
			ConfigID:      configID,
			CSESIDX:       csesidx,
			IsNew:         false,
		}
		logger.Info("[%s] 上传续期数据: configID=%s, csesidx=%s, auth长度=%d",
			email, configID, csesidx, len(authorization))
		if err := pc.uploadAccountData(uploadReq); err != nil {
			logger.Warn("上传续期数据失败: %v", err)
		}
		pc.sendRefreshResult(email, true, result.SecureCookies, "")
	} else {
		errMsg := "未知错误"
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		logger.Warn("❌ 账号续期失败 %s: %s", email, errMsg)
		pc.sendRefreshResult(email, false, nil, errMsg)
	}
}

// sendMessage 发送消息
func (pc *PoolClient) sendMessage(msg WSMessage) {
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	select {
	case pc.send <- data:
	default:
		logger.Warn("发送队列已满")
	}
}

// uploadAccount 上传注册结果到服务器
func (pc *PoolClient) uploadAccount(result *BrowserRegisterResult, isNew bool) error {
	// 构建cookie字符串
	var cookieStr string
	for i, c := range result.SecureCookies {
		if i > 0 {
			cookieStr += "; "
		}
		cookieStr += c.Name + "=" + c.Value
	}

	req := &AccountUploadRequest{
		Email:         result.Email,
		FullName:      result.FullName,
		Cookies:       result.SecureCookies,
		CookieString:  cookieStr,
		Authorization: result.Authorization,
		ConfigID:      result.ConfigID,
		CSESIDX:       result.CSESIDX,
		IsNew:         isNew,
	}
	return pc.uploadAccountData(req)
}

// uploadAccountData 上传账号数据到服务器
func (pc *PoolClient) uploadAccountData(req *AccountUploadRequest) error {
	u, err := url.Parse(pc.config.ServerAddr)
	if err != nil {
		return err
	}

	uploadURL := fmt.Sprintf("%s://%s/pool/upload-account", u.Scheme, u.Host)

	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequest("POST", uploadURL, bytes.NewReader(data))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if pc.config.Secret != "" {
		httpReq.Header.Set("X-Pool-Secret", pc.config.Secret)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if success, ok := result["success"].(bool); !ok || !success {
		errMsg, _ := result["error"].(string)
		return fmt.Errorf("上传失败: %s", errMsg)
	}

	logger.Debug("账号数据已上传: %s", req.Email)
	return nil
}

// sendRegisterResult 发送注册结果
func (pc *PoolClient) sendRegisterResult(success bool, email, errMsg string) {
	pc.sendMessage(WSMessage{
		Type:      WSMsgRegisterResult,
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"success": success,
			"email":   email,
			"error":   errMsg,
		},
	})
}

// sendRefreshResult 发送续期结果
func (pc *PoolClient) sendRefreshResult(email string, success bool, cookies []Cookie, errMsg string) {
	pc.sendMessage(WSMessage{
		Type:      WSMsgRefreshResult,
		Timestamp: time.Now().Unix(),
		Data: map[string]interface{}{
			"email":   email,
			"success": success,
			"cookies": cookies,
			"error":   errMsg,
		},
	})
}

// triggerReconnect 触发重连
func (pc *PoolClient) triggerReconnect() {
	select {
	case pc.reconnect <- struct{}{}:
	default:
	}
}

// getString 安全获取字符串
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
