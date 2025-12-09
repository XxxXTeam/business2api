package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"business2api/src/flow"
	"business2api/src/logger"
	"business2api/src/pool"
	"business2api/src/proxy"
	"business2api/src/register"
	"business2api/src/utils"
)

// ==================== 配置结构 ====================

type PoolConfig struct {
	TargetCount            int  `json:"target_count"`              // 目标账号数量
	MinCount               int  `json:"min_count"`                 // 最小账号数，低于此值触发注册
	CheckIntervalMinutes   int  `json:"check_interval_minutes"`    // 检查间隔(分钟)
	RegisterThreads        int  `json:"register_threads"`          // 注册线程数
	RegisterHeadless       bool `json:"register_headless"`         // 无头模式
	RefreshOnStartup       bool `json:"refresh_on_startup"`        // 启动时刷新账号
	RefreshCooldownSec     int  `json:"refresh_cooldown_sec"`      // 刷新冷却时间(秒)
	UseCooldownSec         int  `json:"use_cooldown_sec"`          // 使用冷却时间(秒)
	MaxFailCount           int  `json:"max_fail_count"`            // 最大连续失败次数
	EnableBrowserRefresh   bool `json:"enable_browser_refresh"`    // 启用浏览器刷新401账号
	BrowserRefreshHeadless bool `json:"browser_refresh_headless"`  // 浏览器刷新无头模式
	BrowserRefreshMaxRetry int  `json:"browser_refresh_max_retry"` // 浏览器刷新最大重试次数(0=禁用)
	AutoDelete401          bool `json:"auto_delete_401"`           // 401时自动删除账号
}

// FlowConfig Flow 服务配置
type FlowConfigSection struct {
	Enable          bool     `json:"enable"`            // 是否启用 Flow
	Tokens          []string `json:"tokens"`            // Flow ST Tokens
	Proxy           string   `json:"proxy"`             // Flow 专用代理
	Timeout         int      `json:"timeout"`           // 超时时间
	PollInterval    int      `json:"poll_interval"`     // 轮询间隔
	MaxPollAttempts int      `json:"max_poll_attempts"` // 最大轮询次数
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Proxy          string   `json:"proxy"`            // 单个代理 (http/socks5)
	Subscribes     []string `json:"subscribes"`       // 订阅链接列表
	Files          []string `json:"files"`            // 代理文件列表
	HealthCheck    bool     `json:"health_check"`     // 是否启用健康检查
	CheckOnStartup bool     `json:"check_on_startup"` // 启动时检查
}

type AppConfig struct {
	APIKeys        []string              `json:"api_keys"`        // API 密钥列表
	ListenAddr     string                `json:"listen_addr"`     // 监听地址
	DataDir        string                `json:"data_dir"`        // 数据目录
	Pool           PoolConfig            `json:"pool"`            // 号池配置
	Proxy          string                `json:"proxy"`           // 代理 (兼容旧配置)
	ProxySubscribe string                `json:"proxy_subscribe"` // 代理订阅链接 (兼容旧配置)
	ProxyPool      ProxyConfig           `json:"proxy_pool"`      // 代理池配置
	DefaultConfig  string                `json:"default_config"`  // 默认 configId
	PoolServer     pool.PoolServerConfig `json:"pool_server"`     // 号池服务器配置
	Debug          bool                  `json:"debug"`           // 调试模式
	Flow           FlowConfigSection     `json:"flow"`            // Flow 配置
}

// PoolMode 号池模式
type PoolMode int

const (
	PoolModeLocal  PoolMode = iota // 本地模式
	PoolModeServer                 // 服务器模式（提供号池服务）
	PoolModeClient                 // 客户端模式（使用远程号池）
)

var (
	poolMode         PoolMode
	remotePoolClient *pool.RemotePoolClient
	flowClient       *flow.FlowClient
	flowHandler      *flow.GenerationHandler
	flowTokenPool    *flow.TokenPool
)

// APIStats API 调用统计
type APIStats struct {
	mu              sync.RWMutex
	startTime       time.Time              // 服务启动时间
	totalRequests   int64                  // 总请求数
	successRequests int64                  // 成功请求数
	failedRequests  int64                  // 失败请求数
	inputTokens     int64                  // 输入 tokens
	outputTokens    int64                  // 输出 tokens
	imageGenerated  int64                  // 生成的图片数
	videoGenerated  int64                  // 生成的视频数
	requestTimes    []time.Time            // 最近请求时间（用于计算 RPM）
	modelStats      map[string]*ModelStats // 每个模型的统计
	hourlyStats     [24]HourlyStats        // 24小时统计
	lastHour        int                    // 上次记录的小时
}

// ModelStats 模型统计
type ModelStats struct {
	Requests     int64 `json:"requests"`
	Success      int64 `json:"success"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	Images       int64 `json:"images"`
}

// HourlyStats 小时统计
type HourlyStats struct {
	Hour         int   `json:"hour"`
	Requests     int64 `json:"requests"`
	Success      int64 `json:"success"`
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

var apiStats = &APIStats{
	startTime:    time.Now(),
	requestTimes: make([]time.Time, 0, 1000),
	modelStats:   make(map[string]*ModelStats),
	lastHour:     time.Now().Hour(),
}

// RecordRequest 记录请求
func (s *APIStats) RecordRequest(success bool, inputTokens, outputTokens, images, videos int64) {
	s.RecordRequestWithModel("", success, inputTokens, outputTokens, images, videos)
}

// RecordRequestWithModel 记录请求（带模型）
func (s *APIStats) RecordRequestWithModel(model string, success bool, inputTokens, outputTokens, images, videos int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.totalRequests++
	if success {
		s.successRequests++
	} else {
		s.failedRequests++
	}
	s.inputTokens += inputTokens
	s.outputTokens += outputTokens
	s.imageGenerated += images
	s.videoGenerated += videos

	// 记录请求时间（保留最近1000条）
	now := time.Now()
	s.requestTimes = append(s.requestTimes, now)
	if len(s.requestTimes) > 1000 {
		s.requestTimes = s.requestTimes[len(s.requestTimes)-1000:]
	}

	// 模型统计
	if model != "" {
		if s.modelStats[model] == nil {
			s.modelStats[model] = &ModelStats{}
		}
		ms := s.modelStats[model]
		ms.Requests++
		if success {
			ms.Success++
		}
		ms.InputTokens += inputTokens
		ms.OutputTokens += outputTokens
		ms.Images += images
	}

	// 小时统计
	currentHour := now.Hour()
	if currentHour != s.lastHour {
		// 新的小时，重置该小时统计
		s.hourlyStats[currentHour] = HourlyStats{Hour: currentHour}
		s.lastHour = currentHour
	}
	hs := &s.hourlyStats[currentHour]
	hs.Requests++
	if success {
		hs.Success++
	}
	hs.InputTokens += inputTokens
	hs.OutputTokens += outputTokens
}

// GetRPM 计算最近一分钟的 RPM
func (s *APIStats) GetRPM() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	oneMinuteAgo := time.Now().Add(-time.Minute)
	count := 0
	for i := len(s.requestTimes) - 1; i >= 0; i-- {
		if s.requestTimes[i].After(oneMinuteAgo) {
			count++
		} else {
			break
		}
	}
	return float64(count)
}

// GetStats 获取统计数据
func (s *APIStats) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uptime := time.Since(s.startTime)
	avgRPM := float64(0)
	if uptime.Minutes() > 0 {
		avgRPM = float64(s.totalRequests) / uptime.Minutes()
	}

	return map[string]interface{}{
		"uptime":           uptime.String(),
		"uptime_seconds":   int64(uptime.Seconds()),
		"total_requests":   s.totalRequests,
		"success_requests": s.successRequests,
		"failed_requests":  s.failedRequests,
		"success_rate":     fmt.Sprintf("%.2f%%", float64(s.successRequests)/float64(max(s.totalRequests, 1))*100),
		"input_tokens":     s.inputTokens,
		"output_tokens":    s.outputTokens,
		"total_tokens":     s.inputTokens + s.outputTokens,
		"images_generated": s.imageGenerated,
		"videos_generated": s.videoGenerated,
		"current_rpm":      s.GetRPM(),
		"average_rpm":      fmt.Sprintf("%.2f", avgRPM),
	}
}

// GetDetailedStats 获取详细统计数据
func (s *APIStats) GetDetailedStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	uptime := time.Since(s.startTime)
	avgRPM := float64(0)
	if uptime.Minutes() > 0 {
		avgRPM = float64(s.totalRequests) / uptime.Minutes()
	}

	// 转换模型统计
	modelStatsMap := make(map[string]interface{})
	for model, ms := range s.modelStats {
		modelStatsMap[model] = map[string]interface{}{
			"requests":      ms.Requests,
			"success":       ms.Success,
			"success_rate":  fmt.Sprintf("%.2f%%", float64(ms.Success)/float64(max(ms.Requests, 1))*100),
			"input_tokens":  ms.InputTokens,
			"output_tokens": ms.OutputTokens,
			"total_tokens":  ms.InputTokens + ms.OutputTokens,
			"images":        ms.Images,
		}
	}

	// 转换小时统计
	hourlyStatsArr := make([]map[string]interface{}, 0, 24)
	for i := 0; i < 24; i++ {
		hs := s.hourlyStats[i]
		if hs.Requests > 0 {
			hourlyStatsArr = append(hourlyStatsArr, map[string]interface{}{
				"hour":          i,
				"requests":      hs.Requests,
				"success":       hs.Success,
				"input_tokens":  hs.InputTokens,
				"output_tokens": hs.OutputTokens,
			})
		}
	}

	return map[string]interface{}{
		"uptime":           uptime.String(),
		"uptime_seconds":   int64(uptime.Seconds()),
		"total_requests":   s.totalRequests,
		"success_requests": s.successRequests,
		"failed_requests":  s.failedRequests,
		"success_rate":     fmt.Sprintf("%.2f%%", float64(s.successRequests)/float64(max(s.totalRequests, 1))*100),
		"input_tokens":     s.inputTokens,
		"output_tokens":    s.outputTokens,
		"total_tokens":     s.inputTokens + s.outputTokens,
		"images_generated": s.imageGenerated,
		"videos_generated": s.videoGenerated,
		"current_rpm":      s.GetRPM(),
		"average_rpm":      fmt.Sprintf("%.2f", avgRPM),
		"models":           modelStatsMap,
		"hourly":           hourlyStatsArr,
	}
}

func max(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

var appConfig = AppConfig{
	ListenAddr: ":8000",
	DataDir:    "./data",
	Pool: PoolConfig{
		TargetCount:            50,
		MinCount:               10,
		CheckIntervalMinutes:   30,
		RegisterThreads:        1,
		RegisterHeadless:       true,
		RefreshOnStartup:       true,
		RefreshCooldownSec:     240, // 4分钟
		UseCooldownSec:         15,  // 15秒
		MaxFailCount:           3,
		EnableBrowserRefresh:   true, // 默认启用浏览器刷新
		BrowserRefreshHeadless: true,
		BrowserRefreshMaxRetry: 1, // 浏览器刷新最多重试1次
	},
}
var (
	DataDir       string
	Proxy         string
	ListenAddr    string
	DefaultConfig string
	JwtTTL        = 270 * time.Second
)

// 保存默认配置到文件
func saveDefaultConfig(configPath string) error {
	// 确保目录存在
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(appConfig, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

func loadAppConfig() {
	// 尝试加载配置文件
	configPath := "config/config.json"
	if data, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(data, &appConfig); err != nil {
			logger.Warn("⚠️ 解析配置文件失败: %v，使用默认配置", err)
		} else {
			logger.Info("✅ 加载配置文件: %s", configPath)
		}
	} else if os.IsNotExist(err) {
		// 配置文件不存在，创建默认配置
		logger.Warn("⚠️ 配置文件不存在，创建默认配置: %s", configPath)
		if err := saveDefaultConfig(configPath); err != nil {
			logger.Error("❌ 创建默认配置失败: %v", err)
		}
	}
	if v := os.Getenv("DATA_DIR"); v != "" {
		appConfig.DataDir = v
	}
	if v := os.Getenv("PROXY"); v != "" {
		appConfig.Proxy = v
	}
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		appConfig.ListenAddr = v
	}
	if v := os.Getenv("CONFIG_ID"); v != "" {
		appConfig.DefaultConfig = v
	}
	if v := os.Getenv("API_KEY"); v != "" {
		appConfig.APIKeys = append(appConfig.APIKeys, v)
	}

	// 设置全局变量
	DataDir = appConfig.DataDir
	Proxy = appConfig.Proxy
	ListenAddr = appConfig.ListenAddr
	DefaultConfig = appConfig.DefaultConfig

	// 应用调试模式
	logger.SetDebugMode(appConfig.Debug)

	// 应用号池配置
	pool.SetCooldowns(appConfig.Pool.RefreshCooldownSec, appConfig.Pool.UseCooldownSec)
	if appConfig.Pool.MaxFailCount > 0 {
		pool.MaxFailCount = appConfig.Pool.MaxFailCount
	}
	pool.EnableBrowserRefresh = appConfig.Pool.EnableBrowserRefresh
	pool.BrowserRefreshHeadless = appConfig.Pool.BrowserRefreshHeadless
	if appConfig.Pool.BrowserRefreshMaxRetry >= 0 {
		pool.BrowserRefreshMaxRetry = appConfig.Pool.BrowserRefreshMaxRetry
	}
	pool.AutoDelete401 = appConfig.Pool.AutoDelete401
	pool.DataDir = DataDir
	pool.DefaultConfig = DefaultConfig
	pool.Proxy = Proxy
	register.DataDir = DataDir
	register.TargetCount = appConfig.Pool.TargetCount
	register.MinCount = appConfig.Pool.MinCount
	register.CheckInterval = time.Duration(appConfig.Pool.CheckIntervalMinutes) * time.Minute
	register.Threads = appConfig.Pool.RegisterThreads
	register.Headless = appConfig.Pool.RegisterHeadless
	register.Proxy = Proxy

	// 初始化代理池
	initProxyPool()

	if pool.EnableBrowserRefresh && pool.BrowserRefreshMaxRetry > 0 {
		logger.Info("🌐 浏览器刷新已启用 (headless=%v, 最大重试=%d)", pool.BrowserRefreshHeadless, pool.BrowserRefreshMaxRetry)
	} else if pool.EnableBrowserRefresh {
		logger.Info("🌐 浏览器刷新已禁用 (max_retry=0)")
		pool.EnableBrowserRefresh = false
	}

	// 初始化 Flow 客户端
	initFlowClient()
}

// initFlowClient 初始化 Flow 客户端
func initFlowClient() {
	if !appConfig.Flow.Enable {
		logger.Info("📹 Flow 服务已禁用")
		return
	}

	cfg := flow.FlowConfig{
		Proxy:           appConfig.Flow.Proxy,
		Timeout:         appConfig.Flow.Timeout,
		PollInterval:    appConfig.Flow.PollInterval,
		MaxPollAttempts: appConfig.Flow.MaxPollAttempts,
	}
	if cfg.Proxy == "" {
		cfg.Proxy = Proxy
	}

	flowClient = flow.NewFlowClient(cfg)

	// 初始化 Token 池
	flowTokenPool = flow.NewTokenPool(DataDir, flowClient)

	// 从 data/at 目录加载 Token
	loadedFromDir, err := flowTokenPool.LoadFromDir()
	if err != nil {
		logger.Warn("⚠️ 从 data/at 加载 Flow Token 失败: %v", err)
	}

	// 添加配置文件中的 Tokens（兼容旧配置）
	for i, st := range appConfig.Flow.Tokens {
		token := &flow.FlowToken{
			ID: fmt.Sprintf("flow_token_%d", i),
			ST: st,
		}
		flowClient.AddToken(token)
	}

	totalTokens := loadedFromDir + len(appConfig.Flow.Tokens)
	if totalTokens == 0 {
		logger.Info("📹 Flow 服务已启用但无可用 Token (请将 cookie 放入 data/at/ 目录)")
		flowHandler = flow.NewGenerationHandler(flowClient)
		return
	}

	// 启动 AT 刷新 worker (每 30 分钟刷新一次)
	flowTokenPool.StartRefreshWorker(30 * time.Minute)

	// 启动文件监听 (自动加载新增 Token)
	if err := flowTokenPool.StartWatcher(); err != nil {
		logger.Warn("⚠️ Flow 文件监听启动失败: %v", err)
	}

	flowHandler = flow.NewGenerationHandler(flowClient)
	logger.Info("📹 Flow 服务已启用，共 %d 个 Token (目录: %d, 配置: %d)", totalTokens, loadedFromDir, len(appConfig.Flow.Tokens))
}

func initProxyPool() {
	// 添加订阅链接（新配置）
	for _, sub := range appConfig.ProxyPool.Subscribes {
		proxy.Manager.AddSubscribeURL(sub)
	}
	// 兼容旧配置
	if appConfig.ProxySubscribe != "" {
		proxy.Manager.AddSubscribeURL(appConfig.ProxySubscribe)
	}

	// 添加代理文件
	for _, file := range appConfig.ProxyPool.Files {
		proxy.Manager.AddProxyFile(file)
	}
	if err := proxy.Manager.LoadAll(); err != nil {
		logger.Warn("⚠️ 加载代理失败: %v", err)
	}

	// 当有代理配置时，默认开启健康检查（除非明确关闭）
	hasProxyConfig := len(appConfig.ProxyPool.Subscribes) > 0 || len(appConfig.ProxyPool.Files) > 0 || appConfig.ProxySubscribe != ""
	shouldHealthCheck := hasProxyConfig || appConfig.ProxyPool.HealthCheck

	if shouldHealthCheck && appConfig.ProxyPool.CheckOnStartup {
		go func() {
			proxy.Manager.CheckAllHealth()
			// 健康检查完成后初始化实例池
			if proxy.Manager.HealthyCount() > 0 {
				poolSize := appConfig.Pool.RegisterThreads
				if poolSize <= 0 {
					poolSize = pool.DefaultProxyCount
				}
				if poolSize > 10 {
					poolSize = 10
				}
				proxy.Manager.SetMaxPoolSize(poolSize)
				if err := proxy.Manager.InitInstancePool(poolSize); err != nil {
					logger.Warn("⚠️ 初始化代理实例池失败: %v", err)
				} else {
					logger.Info("✅ 代理实例池初始化完成: %d 个实例", poolSize)
				}
			}
		}()
	} else if proxy.Manager.TotalCount() > 0 {
		// 不需要健康检查时直接标记就绪
		proxy.Manager.SetReady(true)
	}
	if proxy.Manager.TotalCount() == 0 {
		if appConfig.ProxyPool.Proxy != "" {
			proxy.Manager.SetProxies([]string{appConfig.ProxyPool.Proxy})
		} else if Proxy != "" {
			proxy.Manager.SetProxies([]string{Proxy})
		}
	}
	if proxy.Manager.TotalCount() == 0 || AutoSubscribeEnabled {
		logger.Info("🔄 启动自动订阅服务（每小时注册获取代理）...")
		proxy.Manager.StartAutoSubscribe()
	}

	if proxy.Manager.TotalCount() > 0 {
		proxy.Manager.StartAutoUpdate()
		logger.Info("✅ 代理池已初始化: %d 个节点, %d 个健康",
			proxy.Manager.TotalCount(), proxy.Manager.HealthyCount())
	}
	register.GetProxy = func() string {
		if proxy.Manager.Count() > 0 {
			return proxy.Manager.Next()
		}
		return Proxy
	}
}

var BaseModels = []string{
	// Gemini 文本模型
	"gemini-2.5-flash",
	"gemini-2.5-pro",
	"gemini-3-pro-preview",
	"gemini-3-pro",
	// Gemini 图片生成
	"gemini-2.5-flash-image",
	"gemini-2.5-pro-image",
	"gemini-3-pro-preview-image",
	"gemini-3-pro-image",
	// Gemini 视频生成
	"gemini-2.5-flash-video",
	"gemini-2.5-pro-video",
	"gemini-3-pro-preview-video",
	"gemini-3-pro-video",
	// Gemini 搜索
	"gemini-2.5-flash-search",
	"gemini-2.5-pro-search",
	"gemini-3-pro-preview-search",
	"gemini-3-pro-search",
}
var FlowModels = []string{
	// Flow 图片生成模型
	"gemini-2.5-flash-image-landscape",
	"gemini-2.5-flash-image-portrait",
	"gemini-3.0-pro-image-landscape",
	"gemini-3.0-pro-image-portrait",
	"imagen-4.0-generate-preview-landscape",
	"imagen-4.0-generate-preview-portrait",
	// Flow 文生视频 (T2V)
	"veo_3_1_t2v_fast_portrait",
	"veo_3_1_t2v_fast_landscape",
	"veo_2_1_fast_d_15_t2v_portrait",
	"veo_2_1_fast_d_15_t2v_landscape",
	"veo_2_0_t2v_portrait",
	"veo_2_0_t2v_landscape",
	// Flow 图生视频 (I2V)
	"veo_3_1_i2v_s_fast_fl_portrait",
	"veo_3_1_i2v_s_fast_fl_landscape",
	"veo_2_1_fast_d_15_i2v_portrait",
	"veo_2_1_fast_d_15_i2v_landscape",
	"veo_2_0_i2v_portrait",
	"veo_2_0_i2v_landscape",
	// Flow 多图生成视频 (R2V)
	"veo_3_0_r2v_fast_portrait",
	"veo_3_0_r2v_fast_landscape",
}

func GetAvailableModels() []string {
	if flowHandler != nil {
		// Flow 已启用，返回全部模型
		return append(BaseModels, FlowModels...)
	}
	// Flow 未启用，只返回基础模型
	return BaseModels
}

// 模型名称映射到 Google API 的 modelId
var modelMapping = map[string]string{
	"gemini-2.5-flash":     "gemini-2.5-flash",
	"gemini-2.5-pro":       "gemini-2.5-pro",
	"gemini-3-pro-preview": "gemini-3-pro-preview",
	"gemini-3-pro":         "gemini-3-pro",
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getCommonHeaders(jwt, origAuth string) map[string]string {
	headers := map[string]string{
		"accept":             "*/*",
		"accept-encoding":    "gzip, deflate, br, zstd",
		"accept-language":    "zh-CN,zh;q=0.9,en;q=0.8",
		"authorization":      "Bearer " + jwt,
		"content-type":       "application/json",
		"origin":             "https://business.gemini.google",
		"referer":            "https://business.gemini.google/",
		"user-agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
		"x-server-timeout":   "1800",
		"sec-ch-ua":          `"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`,
		"sec-ch-ua-mobile":   "?0",
		"sec-ch-ua-platform": `"Windows"`,
		"sec-fetch-dest":     "empty",
		"sec-fetch-mode":     "cors",
		"sec-fetch-site":     "cross-site",
	}
	// 同时携带原始 authorization
	if origAuth != "" {
		headers["x-original-authorization"] = origAuth
	}
	return headers
}

func createSession(jwt, configID, origAuth string) (string, error) {
	return createSessionWithRetry(jwt, configID, origAuth, 3)
}

// createSessionWithRetry 创建session带重试（处理400错误）
func createSessionWithRetry(jwt, configID, origAuth string, maxRetries int) (string, error) {
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		if retry > 0 {
			// 等待后重试
			waitTime := time.Duration(retry*500) * time.Millisecond
			time.Sleep(waitTime)
			logger.Info("🔄 createSession 重试 %d/%d", retry+1, maxRetries)
		}

		sessionName, err := createSessionOnce(jwt, configID, origAuth)
		if err == nil {
			return sessionName, nil
		}

		lastErr = err
		errMsg := err.Error()

		// 400错误可以重试
		if strings.Contains(errMsg, "400") {
			logger.Warn("⚠️ createSession 400 错误，尝试重试...")
			continue
		}

		// 401/403 不重试
		if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "403") {
			return "", err
		}

		// 其他错误继续重试
	}

	return "", lastErr
}

// createSessionOnce 单次创建session
func createSessionOnce(jwt, configID, origAuth string) (string, error) {
	body := map[string]interface{}{
		"configId":         configID,
		"additionalParams": map[string]string{"token": "-"},
		"createSessionRequest": map[string]interface{}{
			"session": map[string]string{"name": "", "displayName": ""},
		},
	}

	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetCreateSession", bytes.NewReader(bodyBytes))

	for k, v := range getCommonHeaders(jwt, origAuth) {
		req.Header.Set(k, v)
	}

	resp, err := utils.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("createSession 请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := utils.ReadResponseBody(resp)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("createSession 失败: %d %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		Session struct {
			Name string `json:"name"`
		} `json:"session"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("解析 session 响应失败: %w", err)
	}

	return result.Session.Name, nil
}
func uploadContextFile(jwt, configID, sessionName, mimeType, base64Content, origAuth string) (string, error) {
	ext := "jpg"
	if parts := strings.Split(mimeType, "/"); len(parts) == 2 {
		ext = parts[1]
	}
	fileName := fmt.Sprintf("upload_%d_%s.%s", time.Now().Unix(), uuid.New().String()[:6], ext)

	body := map[string]interface{}{
		"configId":         configID,
		"additionalParams": map[string]string{"token": "-"},
		"addContextFileRequest": map[string]interface{}{
			"name":         sessionName,
			"fileName":     fileName,
			"mimeType":     mimeType,
			"fileContents": base64Content,
		},
	}

	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetAddContextFile", bytes.NewReader(bodyBytes))

	for k, v := range getCommonHeaders(jwt, origAuth) {
		req.Header.Set(k, v)
	}

	resp, err := utils.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("上传文件请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := utils.ReadResponseBody(resp)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("上传文件失败: %d %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		AddContextFileResponse struct {
			FileID string `json:"fileId"`
		} `json:"addContextFileResponse"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("解析上传响应失败: %w", err)
	}

	if result.AddContextFileResponse.FileID == "" {
		return "", fmt.Errorf("上传成功但 fileId 为空，响应: %s", string(respBody))
	}

	return result.AddContextFileResponse.FileID, nil
}
func uploadContextFileByURL(jwt, configID, sessionName, imageURL, origAuth string) (string, error) {
	body := map[string]interface{}{
		"configId":         configID,
		"additionalParams": map[string]string{"token": "-"},
		"addContextFileRequest": map[string]interface{}{
			"name":    sessionName,
			"fileUri": imageURL,
		},
	}

	bodyBytes, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetAddContextFile", bytes.NewReader(bodyBytes))

	for k, v := range getCommonHeaders(jwt, origAuth) {
		req.Header.Set(k, v)
	}

	resp, err := utils.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("上传文件请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := utils.ReadResponseBody(resp)
	if err != nil {
		return "", fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("URL上传文件失败: %d %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		AddContextFileResponse struct {
			FileID string `json:"fileId"`
		} `json:"addContextFileResponse"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("解析上传响应失败: %w", err)
	}

	if result.AddContextFileResponse.FileID == "" {
		return "", fmt.Errorf("URL上传成功但 fileId 为空，响应: %s", string(respBody))
	}

	return result.AddContextFileResponse.FileID, nil
}

type Message struct {
	Role       string      `json:"role"`
	Content    interface{} `json:"content"`                // string 或 []ContentPart
	Name       string      `json:"name,omitempty"`         // 函数名称（tool角色时）
	ToolCalls  []ToolCall  `json:"tool_calls,omitempty"`   // 工具调用（assistant角色时）
	ToolCallID string      `json:"tool_call_id,omitempty"` // 工具调用ID（tool角色时）
}

type ContentPart struct {
	Type     string    `json:"type"`
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

type ImageURL struct {
	URL string `json:"url"`
}

// OpenAI格式的工具定义
type ToolDef struct {
	Type     string      `json:"type"` // "function"
	Function FunctionDef `json:"function"`
}

type FunctionDef struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// 工具调用结果
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature float64   `json:"temperature"`
	TopP        float64   `json:"top_p"`
	Tools       []ToolDef `json:"tools,omitempty"`       // 工具定义
	ToolChoice  string    `json:"tool_choice,omitempty"` // "auto", "none", "required"
}

type ChatChoice struct {
	Index        int                    `json:"index"`
	Delta        map[string]interface{} `json:"delta,omitempty"`
	Message      map[string]interface{} `json:"message,omitempty"`
	FinishReason *string                `json:"finish_reason"`
	Logprobs     interface{}            `json:"logprobs"` // OpenAI兼容
}

type ChatChunk struct {
	ID                string       `json:"id"`
	Object            string       `json:"object"`
	Created           int64        `json:"created"`
	Model             string       `json:"model"`
	SystemFingerprint string       `json:"system_fingerprint,omitempty"`
	Choices           []ChatChoice `json:"choices"`
}

func createChunk(id string, created int64, model string, delta map[string]interface{}, finishReason *string) string {
	if delta == nil {
		delta = map[string]interface{}{}
	}
	chunk := ChatChunk{
		ID:      id,
		Object:  "chat.completion.chunk",
		Created: created,
		Model:   model,
		Choices: []ChatChoice{{
			Index:        0,
			Delta:        delta,
			FinishReason: finishReason,
			Logprobs:     nil,
		}},
	}
	data, _ := json.Marshal(chunk)
	return string(data)
}

func extractContentFromReply(replyMap map[string]interface{}, jwt, session, configID, origAuth string) (text string, imageData string, imageMime string, reasoning string) {
	groundedContent, ok := replyMap["groundedContent"].(map[string]interface{})
	if !ok {
		return
	}
	content, ok := groundedContent["content"].(map[string]interface{})
	if !ok {
		return
	}
	if thought, ok := content["thought"].(bool); ok && thought {
		if t, ok := content["text"].(string); ok && t != "" {
			reasoning = t
		}
		return
	}
	if t, ok := content["text"].(string); ok && t != "" {
		text = t
	}
	if inlineData, ok := content["inlineData"].(map[string]interface{}); ok {
		if mime, ok := inlineData["mimeType"].(string); ok {
			imageMime = mime
		}
		if data, ok := inlineData["data"].(string); ok {
			imageData = data
		}
	}
	if file, ok := content["file"].(map[string]interface{}); ok {
		fileId, _ := file["fileId"].(string)
		mimeType, _ := file["mimeType"].(string)
		if fileId != "" {
			fileType := "文件"
			if strings.HasPrefix(mimeType, "image/") {
				fileType = "图片"
			} else if strings.HasPrefix(mimeType, "video/") {
				fileType = "视频"
			}
			data, err := downloadGeneratedFile(jwt, fileId, session, configID, origAuth)
			if err != nil {
				logger.Error("❌ 下载%s失败: %v", fileType, err)
			} else {
				imageData = data
				imageMime = mimeType
			}
		}
	}

	return
}
func downloadGeneratedFile(jwt, fileId, session, configID, origAuth string) (string, error) {
	return downloadGeneratedFileWithRetry(jwt, fileId, session, configID, origAuth, 3)
}
func downloadGeneratedFileWithRetry(jwt, fileId, session, configID, origAuth string, maxRetries int) (string, error) {
	// 参数验证
	if jwt == "" {
		return "", fmt.Errorf("JWT 为空，无法下载文件")
	}
	if session == "" {
		return "", fmt.Errorf("session 为空，无法下载文件")
	}
	if configID == "" {
		return "", fmt.Errorf("configID 为空，无法下载文件")
	}
	var lastErr error
	currentJWT := jwt
	currentOrigAuth := origAuth

	for retry := 0; retry < maxRetries; retry++ {
		result, err := downloadGeneratedFileOnce(currentJWT, fileId, session, configID, currentOrigAuth)
		if err == nil {
			return result, nil
		}

		lastErr = err
		errMsg := err.Error()

		if strings.Contains(errMsg, "401") || strings.Contains(errMsg, "403") ||
			strings.Contains(errMsg, "UNAUTHENTICATED") || strings.Contains(errMsg, "SESSION_COOKIE_INVALID") {
			logger.Warn("⚠️ 下载文件认证失败 (尝试 %d/%d): %v，尝试切换账号...", retry+1, maxRetries, err)
			newAcc := pool.Pool.Next()
			if newAcc != nil {
				newJWT, newConfigID, jwtErr := newAcc.GetJWT()
				if jwtErr == nil {
					logger.Info("✅ 切换到新账号: %s", newAcc.Data.Email)
					currentJWT = newJWT
					currentOrigAuth = newAcc.Data.Authorization
					_ = newConfigID
					continue
				}
			}
			logger.Error("❌ 无法获取新账号，重试当前账号...")
		}

		// 其他错误，等待后重试
		logger.Error("❌ 下载文件失败 (尝试 %d/%d): %v", retry+1, maxRetries, err)
		time.Sleep(500 * time.Millisecond)
	}

	return "", fmt.Errorf("下载文件失败，已重试 %d 次: %w", maxRetries, lastErr)
}

// downloadGeneratedFileOnce 单次下载文件尝试
func downloadGeneratedFileOnce(jwt, fileId, session, configID, origAuth string) (string, error) {

	// 步骤1: 使用 widgetListSessionFileMetadata 获取文件下载 URL
	listBody := map[string]interface{}{
		"configId":         configID,
		"additionalParams": map[string]string{"token": "-"},
		"listSessionFileMetadataRequest": map[string]interface{}{
			"name":   session,
			"filter": "file_origin_type = AI_GENERATED",
		},
	}
	listBodyBytes, _ := json.Marshal(listBody)

	listReq, _ := http.NewRequest("POST", "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetListSessionFileMetadata", bytes.NewReader(listBodyBytes))
	for k, v := range getCommonHeaders(jwt, origAuth) {
		listReq.Header.Set(k, v)
	}

	listResp, err := utils.HTTPClient.Do(listReq)
	if err != nil {
		return "", fmt.Errorf("获取文件元数据失败: %w", err)
	}
	defer listResp.Body.Close()

	listRespBody, _ := utils.ReadResponseBody(listResp)

	if listResp.StatusCode != 200 {
		return "", fmt.Errorf("获取文件元数据失败: HTTP %d: %s", listResp.StatusCode, string(listRespBody))
	}

	// 解析响应，查找匹配的 fileId
	var listResult struct {
		ListSessionFileMetadataResponse struct {
			FileMetadata []struct {
				FileID      string `json:"fileId"`
				Session     string `json:"session"` // 包含完整的 projects 路径
				DownloadURI string `json:"downloadUri"`
			} `json:"fileMetadata"`
		} `json:"listSessionFileMetadataResponse"`
	}
	if err := json.Unmarshal(listRespBody, &listResult); err != nil {
		return "", fmt.Errorf("解析文件元数据失败: %w", err)
	}

	// 查找匹配的文件，获取完整 session 路径
	var fullSession string
	for _, meta := range listResult.ListSessionFileMetadataResponse.FileMetadata {
		if meta.FileID == fileId {
			fullSession = meta.Session // 如: projects/372889301682/locations/global/collections/...
			break
		}
	}

	if fullSession == "" {
		return "", fmt.Errorf("未找到 fileId=%s 的文件信息", fileId)
	}

	downloadURL := fmt.Sprintf("https://biz-discoveryengine.googleapis.com/download/v1alpha/%s:downloadFile?fileId=%s&alt=media", fullSession, fileId)
	downloadReq, _ := http.NewRequest("GET", downloadURL, nil)
	for k, v := range getCommonHeaders(jwt, origAuth) {
		downloadReq.Header.Set(k, v)
	}

	downloadResp, err := utils.HTTPClient.Do(downloadReq)
	if err != nil {
		return "", fmt.Errorf("下载图片失败: %w", err)
	}
	defer downloadResp.Body.Close()

	imgBody, _ := utils.ReadResponseBody(downloadResp)

	if downloadResp.StatusCode != 200 {
		return "", fmt.Errorf("下载图片失败: HTTP %d: %s", downloadResp.StatusCode, string(imgBody))
	}

	// 响应是原始二进制图片数据，需要转为 base64
	return base64.StdEncoding.EncodeToString(imgBody), nil
}

// 将图片转换为 Markdown 格式的 data URI
func formatImageAsMarkdown(mimeType, base64Data string) string {
	return fmt.Sprintf("![image](data:%s;base64,%s)", mimeType, base64Data)
}

// 媒体信息（图片/视频）
type MediaInfo struct {
	MimeType  string
	Data      string // base64 数据
	URL       string // 原始 URL（如果有）
	IsURL     bool   // 是否使用 URL 直接上传
	MediaType string // "image" 或 "video"
}

// 别名，保持向后兼容
type ImageInfo = MediaInfo

// 解析消息内容，支持文本、图片和视频
func parseMessageContent(msg Message) (string, []MediaInfo) {
	var textContent string
	var medias []MediaInfo

	switch content := msg.Content.(type) {
	case string:
		textContent = content
	case []interface{}:
		for _, part := range content {
			partMap, ok := part.(map[string]interface{})
			if !ok {
				continue
			}

			partType, _ := partMap["type"].(string)
			switch partType {
			case "text":
				if text, ok := partMap["text"].(string); ok {
					textContent += text
				}
			case "image_url":
				if imgURL, ok := partMap["image_url"].(map[string]interface{}); ok {
					if urlStr, ok := imgURL["url"].(string); ok {
						media := parseMediaURL(urlStr, "image")
						if media != nil {
							medias = append(medias, *media)
						}
					}
				}
			case "video_url":
				// 支持视频 URL
				if videoURL, ok := partMap["video_url"].(map[string]interface{}); ok {
					if urlStr, ok := videoURL["url"].(string); ok {
						media := parseMediaURL(urlStr, "video")
						if media != nil {
							medias = append(medias, *media)
						}
					}
				}
			case "file":
				// 支持通用文件类型
				if fileData, ok := partMap["file"].(map[string]interface{}); ok {
					if urlStr, ok := fileData["url"].(string); ok {
						mediaType := "image" // 默认图片
						if mime, ok := fileData["mime_type"].(string); ok {
							if strings.HasPrefix(mime, "video/") {
								mediaType = "video"
							}
						}
						media := parseMediaURL(urlStr, mediaType)
						if media != nil {
							medias = append(medias, *media)
						}
					}
				}
			}
		}
	}

	return textContent, medias
}

// 解析媒体 URL（图片或视频）
func parseMediaURL(urlStr, defaultType string) *MediaInfo {
	// 处理 base64 数据
	if strings.HasPrefix(urlStr, "data:") {
		// data:image/jpeg;base64,/9j/4AAQ... 或 data:video/mp4;base64,...
		parts := strings.SplitN(urlStr, ",", 2)
		if len(parts) != 2 {
			return nil
		}

		base64Data := parts[1]
		var mediaType string
		var mimeType string

		// 检测媒体类型
		if strings.Contains(parts[0], "video/") {
			mediaType = "video"
			// 视频格式处理
			if strings.Contains(parts[0], "video/mp4") {
				mimeType = "video/mp4"
			} else if strings.Contains(parts[0], "video/webm") {
				mimeType = "video/webm"
			} else if strings.Contains(parts[0], "video/quicktime") || strings.Contains(parts[0], "video/mov") {
				// MOV 格式，尝试作为 mp4 上传
				mimeType = "video/mp4"
				logger.Debug("ℹ️ MOV 视频将作为 MP4 上传")
			} else if strings.Contains(parts[0], "video/avi") || strings.Contains(parts[0], "video/x-msvideo") {
				mimeType = "video/mp4"
				logger.Debug("ℹ️ AVI 视频将作为 MP4 上传")
			} else {
				// 其他视频格式默认作为 mp4
				mimeType = "video/mp4"
				logger.Debug("ℹ️ 未知视频格式 %s 将作为 MP4 上传", parts[0])
			}
		} else {
			mediaType = "image"
			// 图片格式处理
			if strings.Contains(parts[0], "image/png") {
				mimeType = "image/png"
			} else if strings.Contains(parts[0], "image/jpeg") {
				mimeType = "image/jpeg"
			} else {
				// 其他图片格式需要转换为 PNG
				converted, err := convertBase64ToPNG(base64Data)
				if err != nil {
					logger.Warn("⚠️ %s base64 转换失败: %v", parts[0], err)
					mimeType = "image/jpeg" // 回退
				} else {
					logger.Info("✅ %s base64 已转换为 PNG", parts[0])
					base64Data = converted
					mimeType = "image/png"
				}
			}
		}

		return &MediaInfo{
			MimeType:  mimeType,
			Data:      base64Data,
			IsURL:     false,
			MediaType: mediaType,
		}
	}

	// URL 媒体 - 优先尝试直接使用 URL 上传
	mediaType := defaultType
	lowerURL := strings.ToLower(urlStr)
	if strings.HasSuffix(lowerURL, ".mp4") || strings.HasSuffix(lowerURL, ".webm") ||
		strings.HasSuffix(lowerURL, ".mov") || strings.HasSuffix(lowerURL, ".avi") ||
		strings.HasSuffix(lowerURL, ".mkv") || strings.HasSuffix(lowerURL, ".m4v") {
		mediaType = "video"
	}

	return &MediaInfo{
		URL:       urlStr,
		IsURL:     true,
		MediaType: mediaType,
	}
}

func downloadImage(urlStr string) (string, string, error) {
	return downloadMedia(urlStr, "image")
}

// downloadMedia 下载媒体文件（图片或视频）
func downloadMedia(urlStr, mediaType string) (string, string, error) {
	resp, err := utils.HTTPClient.Get(urlStr)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// 检查上游返回的状态码
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return "", "", fmt.Errorf("UPSTREAM_%d: 上游返回状态码 %d 多媒体下载失败", resp.StatusCode, resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("UPSTREAM_%d: 上游返回状态码 %d", resp.StatusCode, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	mimeType := resp.Header.Get("Content-Type")

	if mediaType == "video" || strings.HasPrefix(mimeType, "video/") {
		// 视频处理
		if mimeType == "" {
			mimeType = "video/mp4"
		}
		// 规范化视频 MIME 类型
		mimeType = normalizeVideoMimeType(mimeType)
		return base64.StdEncoding.EncodeToString(data), mimeType, nil
	}

	// 图片处理
	if mimeType == "" {
		mimeType = "image/jpeg"
	}
	needConvert := !strings.Contains(mimeType, "jpeg") && !strings.Contains(mimeType, "png")
	if needConvert {
		converted, err := convertToPNG(data)
		if err != nil {
			logger.Warn("⚠️ %s 转换失败: %v，尝试原格式", mimeType, err)
		} else {
			logger.Info("✅ %s 已转换为 PNG", mimeType)
			return base64.StdEncoding.EncodeToString(converted), "image/png", nil
		}
	}

	return base64.StdEncoding.EncodeToString(data), mimeType, nil
}

// normalizeVideoMimeType 规范化视频 MIME 类型
func normalizeVideoMimeType(mimeType string) string {
	switch {
	case strings.Contains(mimeType, "mp4"):
		return "video/mp4"
	case strings.Contains(mimeType, "webm"):
		return "video/webm"
	case strings.Contains(mimeType, "quicktime"), strings.Contains(mimeType, "mov"):
		logger.Debug("ℹ️ MOV 视频将作为 MP4 上传")
		return "video/mp4"
	case strings.Contains(mimeType, "avi"), strings.Contains(mimeType, "x-msvideo"):
		logger.Debug("ℹ️ AVI 视频将作为 MP4 上传")
		return "video/mp4"
	case strings.Contains(mimeType, "x-matroska"), strings.Contains(mimeType, "mkv"):
		logger.Debug("ℹ️ MKV 视频将作为 MP4 上传")
		return "video/mp4"
	case strings.Contains(mimeType, "3gpp"):
		return "video/3gpp"
	default:
		logger.Debug("ℹ️ 未知视频格式 %s 将作为 MP4 上传", mimeType)
		return "video/mp4"
	}
}

// convertToPNG 将图片转换为 PNG 格式
func convertToPNG(data []byte) ([]byte, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("解码图片失败: %w", err)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, fmt.Errorf("编码 PNG 失败: %w", err)
	}

	return buf.Bytes(), nil
}

// convertBase64ToPNG 将 base64 图片转换为 PNG
func convertBase64ToPNG(base64Data string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return "", fmt.Errorf("解码 base64 失败: %w", err)
	}

	converted, err := convertToPNG(data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(converted), nil
}

const maxRetries = 3

// convertMessagesToPrompt 将多轮对话转换为Gemini格式的prompt
// extractSystemPrompt 提取并返回系统提示词
func extractSystemPrompt(messages []Message) string {
	for _, msg := range messages {
		if msg.Role == "system" {
			text, _ := parseMessageContent(msg)
			return text
		}
	}
	return ""
}

// convertMessagesToPrompt 将多轮对话转换为带系统提示词的prompt
// 支持OpenAI/Claude/Gemini格式的messages
func convertMessagesToPrompt(messages []Message) string {
	var dialogParts []string
	var systemPrompt string

	for _, msg := range messages {
		text, _ := parseMessageContent(msg)
		if text == "" && msg.Role != "assistant" {
			continue
		}

		switch msg.Role {
		case "system":
			// 支持多个system消息拼接
			if systemPrompt != "" {
				systemPrompt += "\n" + text
			} else {
				systemPrompt = text
			}
		case "user", "human": // Claude使用human
			dialogParts = append(dialogParts, fmt.Sprintf("Human: %s", text))
		case "assistant":
			// 检查是否有工具调用
			if len(msg.ToolCalls) > 0 {
				for _, tc := range msg.ToolCalls {
					dialogParts = append(dialogParts, fmt.Sprintf("Assistant: [调用工具 %s(%s)]", tc.Function.Name, tc.Function.Arguments))
				}
			} else if text != "" {
				dialogParts = append(dialogParts, fmt.Sprintf("Assistant: %s", text))
			}
		case "tool", "tool_result": // Claude使用tool_result
			dialogParts = append(dialogParts, fmt.Sprintf("Tool Result [%s]: %s", msg.Name, text))
		}
	}

	// 组合最终prompt，系统提示词使用更强的格式
	var result strings.Builder
	if systemPrompt != "" {
		// 使用更明确的系统提示词格式，确保生效
		result.WriteString("<system>\n")
		result.WriteString(systemPrompt)
		result.WriteString("\n</system>\n\n")
	}
	if len(dialogParts) > 0 {
		result.WriteString(strings.Join(dialogParts, "\n\n"))
	}
	// 添加Assistant前缀引导回复
	result.WriteString("\n\nAssistant:")
	return result.String()
}

// ==================== Gemini API 兼容 ====================

// GeminiRequest Gemini generateContent API 请求格式
type GeminiRequest struct {
	Contents          []GeminiContent          `json:"contents"`
	SystemInstruction *GeminiContent           `json:"systemInstruction,omitempty"`
	GenerationConfig  map[string]interface{}   `json:"generationConfig,omitempty"`
	GeminiTools       []map[string]interface{} `json:"tools,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text       string            `json:"text,omitempty"`
	InlineData *GeminiInlineData `json:"inlineData,omitempty"`
}

type GeminiInlineData struct {
	MimeType string `json:"mimeType"`
	Data     string `json:"data"`
}

// handleGeminiGenerate 处理Gemini generateContent API格式的请求
func handleGeminiGenerate(c *gin.Context) {
	action := c.Param("action")
	if action == "" {
		c.JSON(400, gin.H{"error": gin.H{"code": 400, "message": "Missing model action", "status": "INVALID_ARGUMENT"}})
		return
	}

	action = strings.TrimPrefix(action, "/")

	var model string
	var isStream bool
	if idx := strings.LastIndex(action, ":"); idx > 0 {
		model = action[:idx]
		actionType := action[idx+1:]
		isStream = actionType == "streamGenerateContent"
	} else {
		model = action
	}

	if model == "" {
		model = GetAvailableModels()[0]
	}

	var geminiReq GeminiRequest
	if err := c.ShouldBindJSON(&geminiReq); err != nil {
		c.JSON(400, gin.H{"error": gin.H{"code": 400, "message": err.Error(), "status": "INVALID_ARGUMENT"}})
		return
	}

	var messages []Message

	// 处理systemInstruction
	if geminiReq.SystemInstruction != nil && len(geminiReq.SystemInstruction.Parts) > 0 {
		var sysText string
		for _, part := range geminiReq.SystemInstruction.Parts {
			if part.Text != "" {
				sysText += part.Text
			}
		}
		if sysText != "" {
			messages = append(messages, Message{Role: "system", Content: sysText})
		}
	}

	// 处理contents
	for _, content := range geminiReq.Contents {
		role := content.Role
		if role == "model" {
			role = "assistant"
		}

		var textParts []string
		var contentParts []interface{}

		for _, part := range content.Parts {
			if part.Text != "" {
				textParts = append(textParts, part.Text)
			}
			if part.InlineData != nil {
				contentParts = append(contentParts, map[string]interface{}{
					"type": "image_url",
					"image_url": map[string]string{
						"url": fmt.Sprintf("data:%s;base64,%s", part.InlineData.MimeType, part.InlineData.Data),
					},
				})
			}
		}

		if len(contentParts) > 0 {
			if len(textParts) > 0 {
				contentParts = append([]interface{}{map[string]interface{}{"type": "text", "text": strings.Join(textParts, "\n")}}, contentParts...)
			}
			messages = append(messages, Message{Role: role, Content: contentParts})
		} else if len(textParts) > 0 {
			messages = append(messages, Message{Role: role, Content: strings.Join(textParts, "\n")})
		}
	}

	stream := isStream || c.Query("alt") == "sse"

	// 转换Gemini工具格式
	var tools []ToolDef
	for _, gt := range geminiReq.GeminiTools {
		if funcDecls, ok := gt["functionDeclarations"].([]interface{}); ok {
			for _, fd := range funcDecls {
				if funcMap, ok := fd.(map[string]interface{}); ok {
					name, _ := funcMap["name"].(string)
					desc, _ := funcMap["description"].(string)
					params, _ := funcMap["parameters"].(map[string]interface{})
					tools = append(tools, ToolDef{
						Type: "function",
						Function: FunctionDef{
							Name:        name,
							Description: desc,
							Parameters:  params,
						},
					})
				}
			}
		}
	}

	req := ChatRequest{
		Model:    model,
		Messages: messages,
		Stream:   stream,
		Tools:    tools,
	}

	streamChat(c, req)
}

// ==================== Claude API 兼容 ====================

type ClaudeRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	System      string    `json:"system,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Stream      bool      `json:"stream"`
	Temperature float64   `json:"temperature,omitempty"`
	Tools       []ToolDef `json:"tools,omitempty"`
}

// handleClaudeMessages 处理Claude Messages API格式的请求
func handleClaudeMessages(c *gin.Context) {
	var claudeReq ClaudeRequest
	if err := c.ShouldBindJSON(&claudeReq); err != nil {
		c.JSON(400, gin.H{"type": "error", "error": gin.H{"type": "invalid_request_error", "message": err.Error()}})
		return
	}

	req := ChatRequest{
		Model:       claudeReq.Model,
		Messages:    claudeReq.Messages,
		Stream:      claudeReq.Stream,
		Temperature: claudeReq.Temperature,
		Tools:       claudeReq.Tools,
	}

	// 如果Claude格式有单独的system字段，插入到messages开头
	if claudeReq.System != "" {
		systemMsg := Message{Role: "system", Content: claudeReq.System}
		req.Messages = append([]Message{systemMsg}, req.Messages...)
	}

	if req.Model == "" {
		req.Model = GetAvailableModels()[0]
	}

	streamChat(c, req)
}

// buildToolsSpec 将OpenAI格式的工具定义转换为Gemini的toolsSpec
func buildToolsSpec(tools []ToolDef, isImageModel, isVideoModel, isSearchModel bool) map[string]interface{} {
	toolsSpec := make(map[string]interface{})

	// 基础工具
	if isImageModel {
		toolsSpec["imageGenerationSpec"] = map[string]interface{}{}
	} else if isVideoModel {
		toolsSpec["videoGenerationSpec"] = map[string]interface{}{}
	} else if isSearchModel {
		// 搜索模型只启用 webGroundingSpec
		toolsSpec["webGroundingSpec"] = map[string]interface{}{}
	} else {
		// 普通模型启用所有内置工具
		toolsSpec["webGroundingSpec"] = map[string]interface{}{}
		toolsSpec["toolRegistry"] = "default_tool_registry"
		toolsSpec["imageGenerationSpec"] = map[string]interface{}{}
		toolsSpec["videoGenerationSpec"] = map[string]interface{}{}
	}

	// 注意: Google stream_assist_request.tools_spec 不支持 functionDeclarations 字段
	// 自定义工具暂不支持，忽略 tools 参数
	_ = tools

	return toolsSpec
}

// extractToolCalls 从Gemini响应中提取工具调用
func extractToolCalls(dataList []map[string]interface{}) []ToolCall {
	var toolCalls []ToolCall

	for _, data := range dataList {
		streamResp, ok := data["streamAssistResponse"].(map[string]interface{})
		if !ok {
			continue
		}
		answer, ok := streamResp["answer"].(map[string]interface{})
		if !ok {
			continue
		}
		replies, ok := answer["replies"].([]interface{})
		if !ok {
			continue
		}

		for _, reply := range replies {
			replyMap, ok := reply.(map[string]interface{})
			if !ok {
				continue
			}
			groundedContent, ok := replyMap["groundedContent"].(map[string]interface{})
			if !ok {
				continue
			}
			content, ok := groundedContent["content"].(map[string]interface{})
			if !ok {
				continue
			}

			// 检查functionCall
			if fc, ok := content["functionCall"].(map[string]interface{}); ok {
				name, _ := fc["name"].(string)
				args, _ := fc["args"].(map[string]interface{})
				argsBytes, _ := json.Marshal(args)

				toolCalls = append(toolCalls, ToolCall{
					ID:   "call_" + uuid.New().String()[:8],
					Type: "function",
					Function: FunctionCall{
						Name:      name,
						Arguments: string(argsBytes),
					},
				})
			}
		}
	}

	return toolCalls
}

// needsConversationContext 检查是否需要对话上下文（多轮对话）
func needsConversationContext(messages []Message) bool {
	// 检查是否有多轮对话标志：存在assistant或tool消息
	for _, msg := range messages {
		if msg.Role == "assistant" || msg.Role == "tool" || msg.Role == "tool_result" {
			return true
		}
	}
	return false
}

// handleFlowRequest 处理 Flow 模型请求
func handleFlowRequest(c *gin.Context, req ChatRequest, chatID string, createdTime int64) {
	if flowHandler == nil {
		c.JSON(503, gin.H{"error": gin.H{
			"message": "Flow 服务未启用，请在配置文件中启用并添加 Token",
			"type":    "service_unavailable",
		}})
		return
	}

	// 解析消息内容和图片
	var prompt string
	var imageBytes [][]byte

	for _, msg := range req.Messages {
		if msg.Role == "user" || msg.Role == "human" {
			text, images := parseMessageContent(msg)
			if text != "" {
				prompt = text
			}
			// 提取图片数据
			for _, img := range images {
				if img.Data != "" {
					imgData, err := base64.StdEncoding.DecodeString(img.Data)
					if err == nil {
						imageBytes = append(imageBytes, imgData)
					}
				}
			}
		}
	}

	if prompt == "" {
		c.JSON(400, gin.H{"error": gin.H{
			"message": "Prompt cannot be empty",
			"type":    "invalid_request_error",
		}})
		return
	}

	flowReq := flow.GenerationRequest{
		Model:  req.Model,
		Prompt: prompt,
		Images: imageBytes,
		Stream: req.Stream,
	}

	if req.Stream {
		// 流式响应
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("X-Accel-Buffering", "no")
		c.Status(200)

		flusher, ok := c.Writer.(http.Flusher)
		if !ok {
			c.JSON(500, gin.H{"error": "Streaming not supported"})
			return
		}

		result, _ := flowHandler.HandleGeneration(flowReq, func(chunk string) {
			c.Writer.WriteString(chunk)
			flusher.Flush()
		})

		// 发送 [DONE]
		c.Writer.WriteString("data: [DONE]\n\n")
		flusher.Flush()

		if result != nil && !result.Success && result.Error != "" {
			logger.Error("❌ [Flow] 生成失败: %s", result.Error)
		}
	} else {
		// 非流式响应
		result, err := flowHandler.HandleGeneration(flowReq, nil)
		if err != nil {
			c.JSON(500, gin.H{"error": gin.H{
				"message": err.Error(),
				"type":    "internal_error",
			}})
			return
		}

		if !result.Success {
			c.JSON(500, gin.H{"error": gin.H{
				"message": result.Error,
				"type":    "generation_failed",
			}})
			return
		}

		// 构建响应
		content := result.URL
		if result.Type == "image" {
			content = fmt.Sprintf("![Generated Image](%s)", result.URL)
		} else if result.Type == "video" {
			content = fmt.Sprintf("<video src='%s' controls></video>", result.URL)
		}

		c.JSON(200, gin.H{
			"id":      chatID,
			"object":  "chat.completion",
			"created": createdTime,
			"model":   req.Model,
			"choices": []gin.H{{
				"index": 0,
				"message": gin.H{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			}},
		})
	}
}

func streamChat(c *gin.Context, req ChatRequest) {
	chatID := "chatcmpl-" + uuid.New().String()
	createdTime := time.Now().Unix()
	clientIP := c.ClientIP()

	// 统计变量
	var statsSuccess bool
	var statsInputTokens int64
	var statsOutputTokens int64
	var statsImages int64
	var statsVideos int64
	statsModel := req.Model
	defer func() {
		apiStats.RecordRequestWithModel(statsModel, statsSuccess, statsInputTokens, statsOutputTokens, statsImages, statsVideos)
	}()

	// 入站日志
	logger.Info("📥 [%s] 请求: model=%s ", clientIP, req.Model)

	// 检查是否是 Flow 模型
	if flow.IsFlowModel(req.Model) {
		handleFlowRequest(c, req, chatID, createdTime)
		return
	}
	// 解析消息：支持多轮对话拼接和系统提示词
	var textContent string
	var images []MediaInfo
	// 提取系统提示词
	systemPrompt := extractSystemPrompt(req.Messages)
	if needsConversationContext(req.Messages) {
		// 多轮对话：拼接所有消息（包含system）
		textContent = convertMessagesToPrompt(req.Messages)
		// 只从最后一条用户消息提取图片
		for i := len(req.Messages) - 1; i >= 0; i-- {
			if req.Messages[i].Role == "user" || req.Messages[i].Role == "human" {
				_, images = parseMessageContent(req.Messages[i])
				break
			}
		}
	} else {
		lastMsg := req.Messages[len(req.Messages)-1]
		userText, userImages := parseMessageContent(lastMsg)
		images = userImages
		if systemPrompt != "" {
			textContent = fmt.Sprintf("<system>\n%s\n</system>\n\nHuman: %s\n\nAssistant:", systemPrompt, userText)
		} else {
			textContent = userText
		}
	}
	var respBody []byte
	var lastErr error
	var lastErrStatusCode int // 保存最后一次错误的 HTTP 状态码
	var lastErrBody []byte    // 保存最后一次错误的响应体
	var usedAcc *pool.Account
	var usedJWT, usedOrigAuth, usedConfigID, usedSession string
	isLongRunning := !req.Stream && (strings.Contains(req.Model, "video") ||
		strings.Contains(req.Model, "imagen") ||
		strings.Contains(req.Model, "image"))

	var heartbeatDone chan struct{}
	if isLongRunning {
		heartbeatDone = make(chan struct{})
		c.Header("Content-Type", "application/json")
		c.Header("Transfer-Encoding", "chunked")
		c.Status(200)
		writer := c.Writer
		flusher, ok := writer.(http.Flusher)
		if ok {
			flusher.Flush() // 先发送头部
		}
		go func() {
			defer func() {
				if r := recover(); r != nil {
				}
			}()
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-heartbeatDone:
					return
				case <-ticker.C:
					if _, err := writer.Write([]byte(" ")); err != nil {
						return
					}
					if flusher, ok := writer.(http.Flusher); ok {
						flusher.Flush()
					}
				}
			}
		}()
	}
	defer func() {
		if heartbeatDone != nil {
			select {
			case <-heartbeatDone:
			default:
				close(heartbeatDone)
			}
		}
	}()

	for retry := 0; retry < maxRetries; retry++ {
		acc := pool.Pool.Next()
		if acc == nil {
			c.JSON(500, gin.H{"error": "没有可用账号"})
			return
		}
		usedAcc = acc
		logger.Info("📤 [%s] 使用账号: %s", clientIP, acc.Data.Email)

		if retry > 0 {
			logger.Info("🔄 第 %d 次重试，切换账号: %s", retry+1, acc.Data.Email)
		}

		jwt, configID, err := acc.GetJWT()
		if err != nil {
			logger.Error("❌ [%s] 获取 JWT 失败: %v", acc.Data.Email, err)
			lastErr = err
			continue
		}

		session, err := createSession(jwt, configID, acc.Data.Authorization)
		if err != nil {
			logger.Error("❌ [%s] 创建 Session 失败: %v", acc.Data.Email, err)
			// 401 错误标记账号需要刷新
			if strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "UNAUTHENTICATED") {
				//		pool.Pool.MarkNeedsRefresh(acc)
			}
			lastErr = err
			continue
		}

		// 上传媒体文件并获取 fileIds
		var fileIds []string
		uploadFailed := false
		for _, media := range images {
			var fileId string
			var err error

			mediaTypeName := "图片"
			if media.MediaType == "video" {
				mediaTypeName = "视频"
			}

			if media.IsURL {
				// 优先尝试 URL 直接上传
				fileId, err = uploadContextFileByURL(jwt, configID, session, media.URL, acc.Data.Authorization)
				if err != nil {
					// URL 上传失败，回退到下载后上传
					mediaData, mimeType, dlErr := downloadMedia(media.URL, media.MediaType)
					if dlErr != nil {
						logger.Warn("⚠️ [%s] %s下载失败: %v", acc.Data.Email, mediaTypeName, dlErr)
						if strings.Contains(dlErr.Error(), "UPSTREAM_401") || strings.Contains(dlErr.Error(), "UPSTREAM_403") {
							c.JSON(500, gin.H{"error": gin.H{
								"message": dlErr.Error(),
								"type":    "upstream_error",
								"code":    "media_download_failed",
							}})
							return
						}
						uploadFailed = true
						break
					}
					fileId, err = uploadContextFile(jwt, configID, session, mimeType, mediaData, acc.Data.Authorization)
				}
			} else {
				fileId, err = uploadContextFile(jwt, configID, session, media.MimeType, media.Data, acc.Data.Authorization)
			}
			if err != nil {
				logger.Warn("⚠️ [%s] %s上传失败: %v", acc.Data.Email, mediaTypeName, err)
				uploadFailed = true
				break
			}
			fileIds = append(fileIds, fileId)
		}
		if uploadFailed {
			lastErr = fmt.Errorf("媒体上传失败")
			continue
		}
		// 构建 query parts（只包含文本）
		queryParts := []map[string]interface{}{}
		if textContent != "" {
			queryParts = append(queryParts, map[string]interface{}{"text": textContent})
		}

		// 检查模型类型后缀
		isImageModel := strings.HasSuffix(req.Model, "-image")
		isVideoModel := strings.HasSuffix(req.Model, "-video")
		isSearchModel := strings.HasSuffix(req.Model, "-search")
		actualModel := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(req.Model, "-image"), "-video"), "-search")

		// 构建 toolsSpec（支持自定义工具）
		toolsSpec := buildToolsSpec(req.Tools, isImageModel, isVideoModel, isSearchModel)

		body := map[string]interface{}{
			"configId":         configID,
			"additionalParams": map[string]string{"token": "-"},
			"streamAssistRequest": map[string]interface{}{
				"session":              session,
				"query":                map[string]interface{}{"parts": queryParts},
				"filter":               "",
				"fileIds":              fileIds,
				"answerGenerationMode": "NORMAL",
				"toolsSpec":            toolsSpec,
				"languageCode":         "zh-CN",
				"userMetadata":         map[string]string{"timeZone": "Asia/Shanghai"},
				"assistSkippingMode":   "REQUEST_ASSIST",
			},
		}

		// 设置模型 ID（去掉 -image 后缀）
		if targetModelID, ok := modelMapping[actualModel]; ok && targetModelID != "" {
			body["streamAssistRequest"].(map[string]interface{})["assistGenerationConfig"] = map[string]interface{}{
				"modelId": targetModelID,
			}
		}

		bodyBytes, _ := json.Marshal(body)
		httpReq, _ := http.NewRequest("POST", "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global/widgetStreamAssist", bytes.NewReader(bodyBytes))

		for k, v := range getCommonHeaders(jwt, acc.Data.Authorization) {
			httpReq.Header.Set(k, v)
		}

		resp, err := utils.HTTPClient.Do(httpReq)
		if err != nil {
			logger.Error("❌ [%s] 请求失败: %v", acc.Data.Email, err)
			lastErr = err
			continue
		}

		if resp.StatusCode != 200 {
			body, _ := utils.ReadResponseBody(resp)
			resp.Body.Close()
			logger.Error("❌ [%s] Google 报错: %d %s (重试 %d/%d)", acc.Data.Email, resp.StatusCode, string(body), retry+1, maxRetries)
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
			lastErrStatusCode = resp.StatusCode
			lastErrBody = body
			// 401/403 无权限，标记需要刷新
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				logger.Warn("⚠️ [%s] %d 无权限，标记需要刷新", acc.Data.Email, resp.StatusCode)
				pool.Pool.MarkNeedsRefresh(acc)
			}
			// 429 限流，延长使用冷却时间（3倍冷却）
			if resp.StatusCode == 429 {
				cooldownTime := pool.UseCooldown * 3
				acc.Mu.Lock()
				acc.LastUsed = time.Now().Add(cooldownTime)
				acc.Mu.Unlock()
				logger.Info("⏳ [%s] 429 限流，账号进入延长冷却 %v", acc.Data.Email, cooldownTime)
				// 429不计入重试次数，等待后继续尝试其他账号
				pool.Pool.MarkUsed(acc, false)
				time.Sleep(1 * time.Second) // 短暂等待后切换账号
				retry--                     // 不计入重试次数
				continue
			}
			pool.Pool.MarkUsed(acc, false) // 标记失败
			continue
		}

		// 成功，读取响应
		respBody, _ = utils.ReadResponseBody(resp)
		resp.Body.Close()

		// Debug 模式输出上游响应
		if logger.IsDebug() {
			respSnippet := string(respBody)
			if len(respSnippet) > 2000 {
				respSnippet = respSnippet[:2000] + "..."
			}
			logger.Debug("[%s] 上游响应: %s", acc.Data.Email, respSnippet)
		}

		// 快速检查是否是认证错误响应
		if bytes.Contains(respBody, []byte("uToken")) && !bytes.Contains(respBody, []byte("streamAssistResponse")) {
			logger.Warn("[%s] 收到认证响应，标记需要刷新", acc.Data.Email)
			pool.Pool.MarkNeedsRefresh(acc)
			lastErr = fmt.Errorf("认证失败，需要刷新账号")
			continue
		}

		// 检查是否有实际内容（非空返回）
		hasText := bytes.Contains(respBody, []byte(`"text"`))
		hasFile := bytes.Contains(respBody, []byte(`"file"`))
		hasInlineData := bytes.Contains(respBody, []byte(`"inlineData"`))
		hasThought := bytes.Contains(respBody, []byte(`"thought"`))
		hasFunctionCall := bytes.Contains(respBody, []byte(`"functionCall"`))
		hasContent := hasText || hasFile || hasInlineData || hasFunctionCall

		// 响应完全为空或只有思考内容
		if !hasContent {
			if hasThought {
				logger.Warn("[%s] 响应只有思考内容，无实际输出，重试 (%d/%d)", acc.Data.Email, retry+1, maxRetries)
				lastErr = fmt.Errorf("空返回，只有思考内容")
			} else {
				logger.Warn("[%s] 响应无有效内容 (text/file/inlineData/functionCall)，重试 (%d/%d)", acc.Data.Email, retry+1, maxRetries)
				lastErr = fmt.Errorf("空返回，无有效内容")
			}
			pool.Pool.MarkUsed(acc, false)
			continue
		}

		usedJWT = jwt
		usedOrigAuth = acc.Data.Authorization
		usedConfigID = configID
		usedSession = session // 保存创建的 session 作为回退
		usedAcc = acc
		lastErr = nil
		pool.Pool.MarkUsed(acc, true) // 标记成功
		break
	}

	if lastErr != nil {
		logger.Error("❌ 所有重试均失败: %v", lastErr)
		// 如果有 HTTP 错误响应体，原样透传
		if lastErrStatusCode > 0 && len(lastErrBody) > 0 {
			c.Data(lastErrStatusCode, "application/json", lastErrBody)
		} else {
			c.JSON(500, gin.H{"error": lastErr.Error()})
		}
		return
	}

	_ = usedAcc

	// 检查空响应
	if len(respBody) == 0 {
		logger.Error("❌ 响应为空")
		c.JSON(500, gin.H{"error": "Empty response from Google"})
		return
	}

	// 解析响应：支持多种格式
	var dataList []map[string]interface{}
	var parseErr error

	// 1. 尝试标准 JSON 数组
	if parseErr = json.Unmarshal(respBody, &dataList); parseErr != nil {
		logger.Warn("⚠️ JSON 数组解析失败: %v, 响应前100字符: %s", parseErr, string(respBody[:min(100, len(respBody))]))

		// 2. 尝试修复不完整的 JSON 数组
		dataList = utils.ParseIncompleteJSONArray(respBody)
		if dataList == nil {
			// 3. 尝试 NDJSON 格式
			logger.Warn("⚠️ 尝试 NDJSON 格式...")
			dataList = utils.ParseNDJSON(respBody)
		}

		if len(dataList) == 0 {
			// 输出完整响应用于调试
			respStr := string(respBody)
			if len(respStr) > 500 {
				logger.Error("❌ 所有解析方式均失败, 响应长度: %d, 前500字符: %s", len(respBody), respStr[:500])
				logger.Error("❌ 后200字符: %s", respStr[len(respStr)-200:])
			} else {
				logger.Error("❌ 所有解析方式均失败, 响应长度: %d, 完整响应: %s", len(respBody), respStr)
			}
			c.JSON(500, gin.H{"error": "JSON Parse Error"})
			return
		}
		logger.Info("✅ 备用解析成功，共 %d 个对象", len(dataList))
	}

	// 检查是否有有效响应
	if len(dataList) > 0 {
		hasValidResponse := false
		hasFileContent := false
		for _, data := range dataList {
			if streamResp, ok := data["streamAssistResponse"].(map[string]interface{}); ok {
				hasValidResponse = true
				// 检查是否有文件内容
				if answer, ok := streamResp["answer"].(map[string]interface{}); ok {
					if replies, ok := answer["replies"].([]interface{}); ok {
						for _, reply := range replies {
							if replyMap, ok := reply.(map[string]interface{}); ok {
								if gc, ok := replyMap["groundedContent"].(map[string]interface{}); ok {
									if content, ok := gc["content"].(map[string]interface{}); ok {
										if _, ok := content["file"]; ok {
											hasFileContent = true
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if !hasValidResponse {
			logger.Warn("⚠️ 响应中没有 streamAssistResponse，响应内容: %v", dataList[0])
		}
		logger.Debug("📊 响应统计: %d 个数据块, 有效响应=%v, 包含文件=%v", len(dataList), hasValidResponse, hasFileContent)
	}

	// 从响应中提取 session（用于下载图片）
	var respSession string
	for _, data := range dataList {
		if streamResp, ok := data["streamAssistResponse"].(map[string]interface{}); ok {
			if sessionInfo, ok := streamResp["sessionInfo"].(map[string]interface{}); ok {
				if s, ok := sessionInfo["session"].(string); ok && s != "" {
					respSession = s
					break
				}
			}
		}
	}

	// 如果响应中没有 session，使用请求时创建的 session 作为回退
	if respSession == "" {
		if usedSession != "" {
			logger.Warn("⚠️ 响应中未找到 session，使用请求时创建的 session: %s", usedSession)
			respSession = usedSession
		} else {
			logger.Warn("⚠️ 响应中未找到 session 且无回退 session，图片/视频下载可能失败")
		}
	} else {
	}

	// 待下载的文件信息
	type PendingFile struct {
		FileID   string
		MimeType string
	}

	if req.Stream {
		// 流式响应：文本/思考实时输出，图片最后处理
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")

		writer := c.Writer
		flusher, _ := writer.(http.Flusher)

		// 发送 role
		chunk := createChunk(chatID, createdTime, req.Model, map[string]interface{}{"role": "assistant"}, nil)
		fmt.Fprintf(writer, "data: %s\n\n", chunk)
		flusher.Flush()

		// 收集待下载的文件和工具调用
		var pendingFiles []PendingFile
		hasToolCalls := false
		for _, data := range dataList {
			streamResp, ok := data["streamAssistResponse"].(map[string]interface{})
			if !ok {
				continue
			}
			answer, ok := streamResp["answer"].(map[string]interface{})
			if !ok {
				continue
			}
			replies, ok := answer["replies"].([]interface{})
			if !ok {
				continue
			}
			for _, reply := range replies {
				replyMap, ok := reply.(map[string]interface{})
				if !ok {
					continue
				}
				groundedContent, ok := replyMap["groundedContent"].(map[string]interface{})
				if !ok {
					continue
				}
				content, ok := groundedContent["content"].(map[string]interface{})
				if !ok {
					continue
				}
				// 检查是否是思考内容
				if thought, ok := content["thought"].(bool); ok && thought {
					if t, ok := content["text"].(string); ok && t != "" {
						chunk := createChunk(chatID, createdTime, req.Model, map[string]interface{}{"reasoning_content": t}, nil)
						fmt.Fprintf(writer, "data: %s\n\n", chunk)
						flusher.Flush()
					}
					continue
				}
				// 输出文本（实时）
				if t, ok := content["text"].(string); ok && t != "" {
					chunk := createChunk(chatID, createdTime, req.Model, map[string]interface{}{"content": t}, nil)
					fmt.Fprintf(writer, "data: %s\n\n", chunk)
					flusher.Flush()
				}

				// 处理 inlineData（直接有 base64 数据的图片）
				if inlineData, ok := content["inlineData"].(map[string]interface{}); ok {
					mime, _ := inlineData["mimeType"].(string)
					data, _ := inlineData["data"].(string)
					if mime != "" && data != "" {
						imgMarkdown := formatImageAsMarkdown(mime, data)
						chunk := createChunk(chatID, createdTime, req.Model, map[string]interface{}{"content": imgMarkdown}, nil)
						fmt.Fprintf(writer, "data: %s\n\n", chunk)
						flusher.Flush()
					}
				}

				// 收集需要下载的文件（图片/视频）
				if file, ok := content["file"].(map[string]interface{}); ok {
					fileId, _ := file["fileId"].(string)
					mimeType, _ := file["mimeType"].(string)
					if fileId != "" {
						pendingFiles = append(pendingFiles, PendingFile{FileID: fileId, MimeType: mimeType})
					}
				}
				if fc, ok := content["functionCall"].(map[string]interface{}); ok {
					hasToolCalls = true
					name, _ := fc["name"].(string)
					args, _ := fc["args"].(map[string]interface{})
					argsBytes, _ := json.Marshal(args)

					toolCall := ToolCall{
						ID:   "call_" + uuid.New().String()[:8],
						Type: "function",
						Function: FunctionCall{
							Name:      name,
							Arguments: string(argsBytes),
						},
					}
					chunk := createChunk(chatID, createdTime, req.Model, map[string]interface{}{
						"tool_calls": []map[string]interface{}{{
							"index": 0,
							"id":    toolCall.ID,
							"type":  "function",
							"function": map[string]interface{}{
								"name":      toolCall.Function.Name,
								"arguments": toolCall.Function.Arguments,
							},
						}},
					}, nil)
					fmt.Fprintf(writer, "data: %s\n\n", chunk)
					flusher.Flush()
				}
			}
		}
		if len(pendingFiles) > 0 {
			logger.Info("📥 开始下载 %d 个文件...", len(pendingFiles))
			type downloadResult struct {
				Index    int
				Data     string
				MimeType string
				Err      error
			}
			results := make(chan downloadResult, len(pendingFiles))
			var wg sync.WaitGroup
			for i, pf := range pendingFiles {
				wg.Add(1)
				go func(idx int, file PendingFile) {
					defer wg.Done()
					data, err := downloadGeneratedFile(usedJWT, file.FileID, respSession, usedConfigID, usedOrigAuth)
					results <- downloadResult{Index: idx, Data: data, MimeType: file.MimeType, Err: err}
				}(i, pf)
			}
			go func() {
				wg.Wait()
				close(results)
			}()
			downloaded := make([]downloadResult, len(pendingFiles))
			for r := range results {
				downloaded[r.Index] = r
			}

			// 按顺序输出
			for i, r := range downloaded {
				if r.Err != nil {
					logger.Error("❌ 下载文件[%d]失败: %v", i, r.Err)
					continue
				}
				imgMarkdown := formatImageAsMarkdown(r.MimeType, r.Data)
				chunk := createChunk(chatID, createdTime, req.Model, map[string]interface{}{"content": imgMarkdown}, nil)
				fmt.Fprintf(writer, "data: %s\n\n", chunk)
				flusher.Flush()
			}
		}

		// 发送结束
		finishReason := "stop"
		if hasToolCalls {
			finishReason = "tool_calls"
		}
		finalChunk := createChunk(chatID, createdTime, req.Model, nil, &finishReason)
		fmt.Fprintf(writer, "data: %s\n\n", finalChunk)
		fmt.Fprintf(writer, "data: [DONE]\n\n")
		flusher.Flush()

		// 更新统计
		statsSuccess = true
		statsImages = int64(len(pendingFiles))
	} else {
		// 非流式响应
		var fullContent strings.Builder
		var fullReasoning strings.Builder
		replyCount := 0
		hasFile := false

		for _, data := range dataList {
			streamResp, ok := data["streamAssistResponse"].(map[string]interface{})
			if !ok {
				continue
			}
			answer, ok := streamResp["answer"].(map[string]interface{})
			if !ok {
				continue
			}
			replies, ok := answer["replies"].([]interface{})
			if !ok {
				continue
			}

			for _, reply := range replies {
				replyMap, ok := reply.(map[string]interface{})
				if !ok {
					continue
				}
				replyCount++
				if gc, ok := replyMap["groundedContent"].(map[string]interface{}); ok {
					if content, ok := gc["content"].(map[string]interface{}); ok {
						if _, ok := content["file"]; ok {
							hasFile = true
						}
					}
				}

				text, imageData, imageMime, reasoning := extractContentFromReply(replyMap, usedJWT, respSession, usedConfigID, usedOrigAuth)
				if reasoning != "" {
					fullReasoning.WriteString(reasoning)
				}
				if text != "" {
					fullContent.WriteString(text)
				}
				if imageData != "" && imageMime != "" {
					fullContent.WriteString(formatImageAsMarkdown(imageMime, imageData))
				}
			}
		}
		toolCalls := extractToolCalls(dataList)
		// 调试日志
		logger.Debug("📊 非流式响应统计: %d 个 reply, 包含文件=%v, content长度=%d, reasoning长度=%d, 工具调用=%d",
			replyCount, hasFile, fullContent.Len(), fullReasoning.Len(), len(toolCalls))

		// 构建响应消息
		message := gin.H{
			"role":    "assistant",
			"content": fullContent.String(),
		}
		if fullReasoning.Len() > 0 {
			message["reasoning_content"] = fullReasoning.String()
		}
		finishReason := "stop"
		if len(toolCalls) > 0 {
			message["tool_calls"] = toolCalls
			message["content"] = nil
			finishReason = "tool_calls"
		}

		// 构建最终响应（完全符合OpenAI格式）
		response := gin.H{
			"id":                 chatID,
			"object":             "chat.completion",
			"created":            createdTime,
			"model":              req.Model,
			"system_fingerprint": "fp_gemini_" + req.Model,
			"choices": []gin.H{{
				"index":         0,
				"message":       message,
				"logprobs":      nil,
				"finish_reason": finishReason,
			}},
			"usage": gin.H{
				"prompt_tokens":     0,
				"completion_tokens": 0,
				"total_tokens":      0,
			},
		}
		if isLongRunning && heartbeatDone != nil {
			close(heartbeatDone) // 停止心跳
			jsonBytes, _ := json.Marshal(response)
			c.Writer.Write(jsonBytes)
		} else {
			c.JSON(200, response)
		}

		// 更新统计
		statsSuccess = true
		statsOutputTokens = int64(fullContent.Len() / 4) // 粗略估算输出 tokens
		if hasFile {
			statsImages = 1
		}
	}
}
func apiKeyAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(appConfig.APIKeys) == 0 {
			c.Next()
			return
		}
		authHeader := c.GetHeader("Authorization")
		apiKey := ""

		if strings.HasPrefix(authHeader, "Bearer ") {
			apiKey = strings.TrimPrefix(authHeader, "Bearer ")
		} else {
			apiKey = c.GetHeader("X-API-Key")
		}

		if apiKey == "" {
			c.JSON(401, gin.H{"error": "Missing API key"})
			c.Abort()
			return
		}

		// 验证 API Key
		valid := false
		for _, key := range appConfig.APIKeys {
			if key == apiKey {
				valid = true
				break
			}
		}

		if !valid {
			c.JSON(401, gin.H{"error": "Invalid API key"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// runBrowserRefreshMode 有头浏览器刷新模式
func runBrowserRefreshMode(email string) {
	loadAppConfig()
	utils.InitHTTPClient(Proxy)

	// 强制有头模式
	pool.BrowserRefreshHeadless = false
	logger.Info("🌐 有头浏览器刷新模式")

	if err := pool.Pool.Load(DataDir); err != nil {
		log.Fatalf("❌ 加载账号失败: %v", err)
	}

	if pool.Pool.TotalCount() == 0 {
		log.Fatal("❌ 没有可用账号")
	}

	// 查找目标账号
	var targetAcc *pool.Account
	pool.Pool.WithLock(func(ready, pending []*pool.Account) {
		if email != "" {
			// 指定邮箱
			for _, acc := range ready {
				if acc.Data.Email == email {
					targetAcc = acc
					break
				}
			}
			if targetAcc == nil {
				for _, acc := range pending {
					if acc.Data.Email == email {
						targetAcc = acc
						break
					}
				}
			}
		} else {
			// 使用第一个账号
			if len(ready) > 0 {
				targetAcc = ready[0]
			} else if len(pending) > 0 {
				targetAcc = pending[0]
			}
		}
	})

	if targetAcc == nil {
		if email != "" {
			log.Fatalf("❌ 找不到账号: %s", email)
		}
		log.Fatal("❌ 没有可用账号")
	}
	result := register.RefreshCookieWithBrowser(targetAcc, false, Proxy)

	if result.Success {

		if len(result.NewCookies) > 0 {
		}
		if len(result.ResponseHeaders) > 0 {
		}

		// 更新账号数据
		targetAcc.Mu.Lock()
		targetAcc.Data.Cookies = result.SecureCookies
		if result.Authorization != "" {
			targetAcc.Data.Authorization = result.Authorization
		}
		if result.ConfigID != "" {
			targetAcc.ConfigID = result.ConfigID
			targetAcc.Data.ConfigID = result.ConfigID
		}
		if result.CSESIDX != "" {
			targetAcc.CSESIDX = result.CSESIDX
			targetAcc.Data.CSESIDX = result.CSESIDX
		}
		// 保存响应头
		if len(result.ResponseHeaders) > 0 {
			targetAcc.Data.ResponseHeaders = result.ResponseHeaders
		}
		targetAcc.Mu.Unlock()

		// 保存到文件
		if err := targetAcc.SaveToFile(); err != nil {
			logger.Warn("⚠️ 保存失败: %v", err)
		} else {
			logger.Info("💾 已保存到: %s", targetAcc.FilePath)
		}
	} else {
		logger.Error("❌ 刷新失败: %v", result.Error)
	}
}

var AutoSubscribeEnabled bool

func init() {
	// 设置环境变量禁用 quic-go 的警告
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	filterStdout()
}
func filterStdout() {
	// 创建管道
	r, w, err := os.Pipe()
	if err != nil {
		return
	}
	origStdout := os.Stdout
	os.Stdout = w
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if err != nil {
				break
			}
			line := string(buf[:n])
			// 过滤特定日志
			if strings.Contains(line, "REALITY localAddr:") ||
				strings.Contains(line, "DialTLSContext") ||
				strings.Contains(line, "sys_conn.go") ||
				strings.Contains(line, "failed to sufficiently increase receive buffer size") {
				continue // 丢弃
			}
			origStdout.Write(buf[:n])
		}
	}()
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)

	var refreshEmail string
	var refreshMode bool

	// 解析命令行参数
	for i, arg := range os.Args[1:] {
		switch arg {
		case "--debug", "-d":
			register.RegisterDebug = true
			logger.Info("🔧 调试模式已启用，将保存截图到 data/screenshots/")
		case "--once":
			register.RegisterOnce = true
			logger.Info("🔧 单次运行模式")
		case "--auto":
			AutoSubscribeEnabled = true
		case "--refresh":
			refreshMode = true
			// 检查下一个参数是否是邮箱
			if i+2 < len(os.Args) && !strings.HasPrefix(os.Args[i+2], "-") {
				refreshEmail = os.Args[i+2]
			}
		case "--help", "-h":
			fmt.Println(`用法: ./business2api [选项]

选项:
  --debug, -d           调试模式，保存注册过程截图
  --auto                自动订阅模式，每小时注册获取代理
  --refresh [email]     有头浏览器刷新账号（不指定email则使用第一个账号）
  --help, -h            显示帮助`)
			os.Exit(0)
		}
	}

	// 刷新模式：直接执行浏览器刷新后退出
	if refreshMode {
		runBrowserRefreshMode(refreshEmail)
		return
	}

	loadAppConfig()
	utils.InitHTTPClient(Proxy)
	if appConfig.PoolServer.Enable {
		switch appConfig.PoolServer.Mode {
		case "client":
			runAsClient()
			return
		case "server":
			runAsServer()
			return
		}
	}

	// 本地模式
	runLocalMode()
}
func runAsClient() {
	logger.Info("🔌 启动客户端模式...")

	// 代理实例池由异步健康检查完成后初始化
	// 设置代理就绪检查回调
	pool.IsProxyReady = func() bool {
		return proxy.Manager.IsReady()
	}
	pool.WaitProxyReady = func(timeout time.Duration) bool {
		logger.Info("⏳ 等待代理就绪...")
		result := proxy.Manager.WaitReady(timeout)
		if result {
			logger.Info("✅ 代理已就绪")
		} else {
			logger.Warn("⚠️ 代理等待超时")
		}
		return result
	}

	pool.RunBrowserRegister = func(headless bool, proxyURL string, id int) *pool.BrowserRegisterResult {
		result := register.RunBrowserRegister(headless, proxyURL, id)
		return &pool.BrowserRegisterResult{
			Success:       result.Success,
			Email:         result.Email,
			FullName:      result.FullName,
			SecureCookies: result.Cookies,
			Authorization: result.Authorization,
			ConfigID:      result.ConfigID,
			CSESIDX:       result.CSESIDX,
			Error:         result.Error,
		}
	}
	pool.RefreshCookieWithBrowser = func(acc *pool.Account, headless bool, proxyURL string) *pool.BrowserRefreshResult {
		result := register.RefreshCookieWithBrowser(acc, headless, proxyURL)
		return &pool.BrowserRefreshResult{
			Success:         result.Success,
			SecureCookies:   result.SecureCookies,
			ConfigID:        result.ConfigID,
			CSESIDX:         result.CSESIDX,
			Authorization:   result.Authorization,
			ResponseHeaders: result.ResponseHeaders,
			Error:           result.Error,
		}
	}
	pool.ClientHeadless = appConfig.Pool.RegisterHeadless
	pool.ClientProxy = Proxy
	pool.GetClientProxy = func() string {
		if proxy.Manager.Count() > 0 {
			return proxy.Manager.Next()
		}
		return Proxy
	}
	pool.ReleaseProxy = func(proxyURL string) {
		proxy.Manager.ReleaseByURL(proxyURL)
		logger.Debug("释放代理: %s", proxyURL)
	}
	pool.GetHealthyCount = func() int {
		return proxy.Manager.HealthyCount()
	}
	go func() {
		proxy.Manager.CheckAllHealth()
		if proxy.Manager.HealthyCount() > 0 {
			poolSize := appConfig.Pool.RegisterThreads
			if poolSize <= 0 {
				poolSize = pool.DefaultProxyCount
			}
			if poolSize > 10 {
				poolSize = 10
			}
			proxy.Manager.SetMaxPoolSize(poolSize)
			proxy.Manager.InitInstancePool(poolSize)
		}
	}()
	client := pool.NewPoolClient(appConfig.PoolServer)
	if err := client.Start(); err != nil {
		log.Fatalf("❌ 客户端启动失败: %v", err)
	}
}

var poolServer *pool.PoolServer

func runAsServer() {
	logger.Info("🖥️ 启动服务器模式...")

	// 加载账号
	dataDir := appConfig.PoolServer.DataDir
	if dataDir == "" {
		dataDir = DataDir
	}
	if err := pool.Pool.Load(dataDir); err != nil {
		log.Fatalf("❌ 加载账号失败: %v", err)
	}
	poolServer = pool.NewPoolServer(pool.Pool, appConfig.PoolServer)
	poolServer.StartBackground() // 启动后台任务分发和心跳检测
	pool.Pool.StartPoolManager()
	runAPIServer()
}

// runAPIServer 启动 API 服务
func runAPIServer() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	setupAPIRoutes(r)
	logger.Info("🚀 API 服务启动于 %s，账号: ready=%d, pending=%d", ListenAddr, pool.Pool.ReadyCount(), pool.Pool.PendingCount())
	if err := r.Run(ListenAddr); err != nil {
		log.Fatalf("❌ API 服务启动失败: %v", err)
	}
}

func setupAPIRoutes(r *gin.Engine) {
	// 请求日志中间件
	r.Use(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		method := c.Request.Method
		clientIP := c.ClientIP()

		c.Next()

		latency := time.Since(start)
		statusCode := c.Writer.Status()

		if statusCode >= 400 {
			logger.Error("❌ %s %s %s %d %v", clientIP, method, path, statusCode, latency)
		} else {
			logger.Info("✅ %s %s %s %d %v", clientIP, method, path, statusCode, latency)
		}
	})

	r.GET("/", func(c *gin.Context) {
		stats := apiStats.GetStats()
		c.JSON(200, gin.H{
			"status":  "running",
			"service": "business2api",
			"version": "2.1.6",
			// 统计数据
			"uptime":           stats["uptime"],
			"total_requests":   stats["total_requests"],
			"success_requests": stats["success_requests"],
			"failed_requests":  stats["failed_requests"],
			"success_rate":     stats["success_rate"],
			"input_tokens":     stats["input_tokens"],
			"output_tokens":    stats["output_tokens"],
			"total_tokens":     stats["total_tokens"],
			"images_generated": stats["images_generated"],
			"videos_generated": stats["videos_generated"],
			"current_rpm":      stats["current_rpm"],
			"average_rpm":      stats["average_rpm"],
			"pool": gin.H{
				"ready":   pool.Pool.ReadyCount(),
				"pending": pool.Pool.PendingCount(),
				"total":   pool.Pool.TotalCount(),
			},
			// Flow 状态
			"flow_enabled": flowHandler != nil,
		})
	})

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"time":    time.Now().UTC().Format(time.RFC3339),
			"ready":   pool.Pool.ReadyCount(),
			"pending": pool.Pool.PendingCount(),
			"mode":    map[PoolMode]string{PoolModeLocal: "local", PoolModeServer: "server", PoolModeClient: "client"}[poolMode],
		})
	})

	// WebSocket 端点（服务端模式下用于客户端连接）
	r.GET("/ws", func(c *gin.Context) {
		if poolServer == nil {
			c.JSON(503, gin.H{"error": "WebSocket 服务未启用，仅在服务端模式下可用"})
			return
		}
		poolServer.HandleWS(c.Writer, c.Request)
	})

	// Pool 内部端点（客户端上传账号等，使用 X-Pool-Secret 鉴权）
	poolGroup := r.Group("/pool")
	poolGroup.Use(func(c *gin.Context) {
		if poolServer == nil {
			c.JSON(503, gin.H{"error": "Pool 服务未启用"})
			c.Abort()
			return
		}
		secret := appConfig.PoolServer.Secret
		if secret != "" && c.GetHeader("X-Pool-Secret") != secret {
			c.JSON(401, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		c.Next()
	})
	poolGroup.POST("/upload-account", func(c *gin.Context) {
		poolServer.HandleUploadAccount(c.Writer, c.Request)
	})

	apiGroup := r.Group("/")
	apiGroup.Use(apiKeyAuth())

	// Gemini 风格模型列表 /v1beta/models
	apiGroup.GET("/v1beta/models", func(c *gin.Context) {
		var models []gin.H
		for _, m := range GetAvailableModels() {
			models = append(models, gin.H{
				"name":                       "models/" + m,
				"version":                    "001",
				"displayName":                m,
				"description":                "Gemini model: " + m,
				"inputTokenLimit":            1048576,
				"outputTokenLimit":           8192,
				"supportedGenerationMethods": []string{"generateContent", "countTokens"},
				"temperature":                1.0,
				"topP":                       0.95,
				"topK":                       64,
			})
		}
		c.JSON(200, gin.H{"models": models})
	})

	// OpenAI 风格模型列表
	apiGroup.GET("/v1/models", func(c *gin.Context) {
		now := time.Now().Unix()
		var models []gin.H
		for _, m := range GetAvailableModels() {
			models = append(models, gin.H{
				"id":         m,
				"object":     "model",
				"created":    now,
				"owned_by":   "google",
				"permission": []interface{}{},
			})
		}
		c.JSON(200, gin.H{"object": "list", "data": models})
	})

	apiGroup.POST("/v1/chat/completions", func(c *gin.Context) {
		var req ChatRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		if req.Model == "" {
			req.Model = GetAvailableModels()[0]
		}
		streamChat(c, req)
	})

	apiGroup.POST("/v1/messages", handleClaudeMessages)

	// Gemini 单模型详情 GET /v1beta/models/{model}
	apiGroup.GET("/v1beta/models/:model", func(c *gin.Context) {
		modelName := c.Param("model")
		// 移除 "models/" 前缀（如果有）
		modelName = strings.TrimPrefix(modelName, "models/")

		// 检查模型是否存在
		found := false
		for _, m := range GetAvailableModels() {
			if m == modelName {
				found = true
				break
			}
		}
		if !found {
			c.JSON(404, gin.H{"error": gin.H{
				"code":    404,
				"message": "Model not found: " + modelName,
				"status":  "NOT_FOUND",
			}})
			return
		}

		c.JSON(200, gin.H{
			"name":                       "models/" + modelName,
			"version":                    "001",
			"displayName":                modelName,
			"description":                "Gemini model: " + modelName,
			"inputTokenLimit":            1048576,
			"outputTokenLimit":           8192,
			"supportedGenerationMethods": []string{"generateContent", "countTokens"},
			"temperature":                1.0,
			"topP":                       0.95,
			"topK":                       64,
		})
	})

	// Gemini generateContent/streamGenerateContent
	apiGroup.POST("/v1beta/models/*action", handleGeminiGenerate)
	apiGroup.POST("/v1/models/*action", handleGeminiGenerate)

	admin := r.Group("/admin")
	admin.Use(apiKeyAuth())
	admin.POST("/register", func(c *gin.Context) {
		var req struct {
			Count int `json:"count"`
		}
		if err := c.ShouldBindJSON(&req); err != nil || req.Count <= 0 {
			req.Count = appConfig.Pool.TargetCount - pool.Pool.TotalCount()
		}
		if req.Count <= 0 {
			c.JSON(200, gin.H{"message": "账号数量已足够", "count": pool.Pool.TotalCount()})
			return
		}
		if poolMode == PoolModeServer {
			// 服务端模式：注册任务会通过 WS 分发给客户端
			c.JSON(200, gin.H{"message": "注册任务已加入队列，将通过 WS 分发给客户端", "target": req.Count})
			return
		}
		if err := register.StartRegister(req.Count); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"message": "注册已启动", "target": req.Count})
	})

	admin.POST("/refresh", func(c *gin.Context) {
		pool.Pool.Load(DataDir)
		c.JSON(200, gin.H{
			"message": "刷新完成",
			"ready":   pool.Pool.ReadyCount(),
			"pending": pool.Pool.PendingCount(),
		})
	})

	admin.GET("/status", func(c *gin.Context) {
		stats := pool.Pool.Stats()
		stats["target"] = appConfig.Pool.TargetCount
		stats["min"] = appConfig.Pool.MinCount
		stats["is_registering"] = atomic.LoadInt32(&register.IsRegistering) == 1
		stats["register_stats"] = register.Stats.Get()
		stats["mode"] = map[PoolMode]string{PoolModeLocal: "local", PoolModeServer: "server", PoolModeClient: "client"}[poolMode]
		c.JSON(200, stats)
	})

	// 详细API统计
	admin.GET("/stats", func(c *gin.Context) {
		detailed := apiStats.GetDetailedStats()
		detailed["pool"] = pool.Pool.Stats()
		detailed["proxy_pool"] = proxy.Manager.PoolStats()
		c.JSON(200, detailed)
	})

	admin.POST("/force-refresh", func(c *gin.Context) {
		count := pool.Pool.ForceRefreshAll()
		c.JSON(200, gin.H{
			"message": "已触发强制刷新",
			"count":   count,
		})
	})

	admin.POST("/config/cooldown", func(c *gin.Context) {
		var req struct {
			RefreshCooldownSec int `json:"refresh_cooldown_sec"`
			UseCooldownSec     int `json:"use_cooldown_sec"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		pool.SetCooldowns(req.RefreshCooldownSec, req.UseCooldownSec)
		c.JSON(200, gin.H{
			"message":              "冷却配置已更新",
			"refresh_cooldown_sec": int(pool.RefreshCooldown.Seconds()),
			"use_cooldown_sec":     int(pool.UseCooldown.Seconds()),
		})
	})

	admin.POST("/browser-refresh", func(c *gin.Context) {
		var req struct {
			Email string `json:"email"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		if req.Email == "" {
			c.JSON(400, gin.H{"error": "需要提供 email"})
			return
		}

		var targetAcc *pool.Account
		pool.Pool.WithLock(func(ready, pending []*pool.Account) {
			for _, acc := range ready {
				if acc.Data.Email == req.Email {
					targetAcc = acc
					break
				}
			}
			if targetAcc == nil {
				for _, acc := range pending {
					if acc.Data.Email == req.Email {
						targetAcc = acc
						break
					}
				}
			}
		})

		if targetAcc == nil {
			c.JSON(404, gin.H{"error": "账号未找到", "email": req.Email})
			return
		}

		go func() {
			logger.Info("🔄 手动触发浏览器刷新: %s", req.Email)
			result := register.RefreshCookieWithBrowser(targetAcc, pool.BrowserRefreshHeadless, Proxy)
			if result.Success {
				targetAcc.Mu.Lock()
				// 更新完整信息
				targetAcc.Data.Cookies = result.SecureCookies
				if result.Authorization != "" {
					targetAcc.Data.Authorization = result.Authorization
				}
				if result.CSESIDX != "" {
					targetAcc.CSESIDX = result.CSESIDX
					targetAcc.Data.CSESIDX = result.CSESIDX
				}
				if result.ConfigID != "" {
					targetAcc.ConfigID = result.ConfigID
					targetAcc.Data.ConfigID = result.ConfigID
				}
				targetAcc.Data.Timestamp = time.Now().Format(time.RFC3339)
				targetAcc.FailCount = 0
				targetAcc.Mu.Unlock()

				if err := targetAcc.SaveToFile(); err != nil {
					logger.Error("❌ [%s] 保存刷新后的数据失败: %v", req.Email, err)
				} else {
					logger.Info("✅ [%s] 刷新数据已保存到文件", req.Email)
				}
				pool.Pool.MarkNeedsRefresh(targetAcc)
				logger.Info("✅ 手动浏览器刷新成功: %s", req.Email)
			} else {
				logger.Error("❌ 手动浏览器刷新失败: %s - %v", req.Email, result.Error)
			}
		}()

		c.JSON(200, gin.H{
			"message": "浏览器刷新已触发",
			"email":   req.Email,
		})
	})

	// Flow Token 管理
	admin.GET("/flow/status", func(c *gin.Context) {
		if flowTokenPool == nil {
			c.JSON(200, gin.H{
				"enabled": false,
				"message": "Flow 服务未启用",
			})
			return
		}
		stats := flowTokenPool.Stats()
		stats["enabled"] = flowHandler != nil
		c.JSON(200, stats)
	})

	admin.POST("/flow/add-token", func(c *gin.Context) {
		if flowTokenPool == nil {
			c.JSON(503, gin.H{"error": "Flow 服务未启用"})
			return
		}
		var req struct {
			Cookie string `json:"cookie"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		if req.Cookie == "" {
			c.JSON(400, gin.H{"error": "需要提供 cookie"})
			return
		}
		tokenID, err := flowTokenPool.AddFromCookie(req.Cookie)
		if err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"message":  "Token 添加成功",
			"token_id": tokenID,
			"total":    flowTokenPool.Count(),
		})
	})

	admin.POST("/flow/remove-token", func(c *gin.Context) {
		if flowTokenPool == nil {
			c.JSON(503, gin.H{"error": "Flow 服务未启用"})
			return
		}
		var req struct {
			TokenID string `json:"token_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		if err := flowTokenPool.RemoveToken(req.TokenID); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"message": "Token 已移除",
			"total":   flowTokenPool.Count(),
		})
	})

	admin.POST("/flow/reload", func(c *gin.Context) {
		if flowTokenPool == nil {
			c.JSON(503, gin.H{"error": "Flow 服务未启用"})
			return
		}
		loaded, err := flowTokenPool.LoadFromDir()
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{
			"message": "已重新加载",
			"loaded":  loaded,
			"total":   flowTokenPool.Count(),
		})
	})

	admin.POST("/config/browser-refresh", func(c *gin.Context) {
		var req struct {
			Enable   *bool `json:"enable"`
			Headless *bool `json:"headless"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		if req.Enable != nil {
			pool.EnableBrowserRefresh = *req.Enable
		}
		if req.Headless != nil {
			pool.BrowserRefreshHeadless = *req.Headless
		}
		c.JSON(200, gin.H{
			"message":  "浏览器刷新配置已更新",
			"enable":   pool.EnableBrowserRefresh,
			"headless": pool.BrowserRefreshHeadless,
		})
	})
}

func runLocalMode() {
	// 本地模式：正常启动
	if err := pool.Pool.Load(DataDir); err != nil {
		log.Fatalf("❌ 加载账号失败: %v", err)
	}

	// 代理实例池由异步健康检查完成后初始化

	// 检查 CONFIG_ID
	if DefaultConfig != "" {
		logger.Info("✅ 使用默认 configId: %s", DefaultConfig)
	}

	// 检查 API Key 配置
	if len(appConfig.APIKeys) == 0 {
		logger.Warn("⚠️ 未配置 API Key，API 将无鉴权运行")
	}

	// 启动号池管理
	if appConfig.Pool.RefreshOnStartup {
		pool.Pool.StartPoolManager()
	}
	if pool.Pool.TotalCount() == 0 {
		needCount := appConfig.Pool.TargetCount
		logger.Info("📝 无账号，启动注册 %d 个...", needCount)
		register.StartRegister(needCount)
	}
	if appConfig.Pool.CheckIntervalMinutes > 0 {
		go register.PoolMaintainer()
	}

	// 启动 API 服务
	runAPIServer()
}
