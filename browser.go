package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/input"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

var (
	RegisterDebug bool
	RegisterOnce  bool
	firstNames    = []string{"John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Lisa", "James", "Emma"}
	lastNames     = []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Taylor"}
	commonWords   = map[string]bool{
		"VERIFY": true, "GOOGLE": true, "UPDATE": true, "MOBILE": true, "DEVICE": true,
		"SUBMIT": true, "RESEND": true, "CANCEL": true, "DELETE": true, "REMOVE": true,
		"SEARCH": true, "VIDEOS": true, "IMAGES": true, "GMAIL": true, "EMAIL": true,
		"ACCOUNT": true, "CHROME": true,
	}
)

// TempEmailResponse 临时邮箱响应
type TempEmailResponse struct {
	Email string `json:"email"`
	Data  struct {
		Email string `json:"email"`
	} `json:"data"`
}

// EmailListResponse 邮件列表响应
type EmailListResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Emails []EmailContent `json:"emails"`
	} `json:"data"`
}

// EmailContent 邮件内容
type EmailContent struct {
	Subject string `json:"subject"`
	Content string `json:"content"`
}

// BrowserRegisterResult 注册结果
type BrowserRegisterResult struct {
	Success       bool
	Email         string
	FullName      string
	Authorization string
	Cookies       []Cookie
	ConfigID      string
	CSESIDX       string
	Error         error
}

// generateRandomName 生成随机全名
func generateRandomName() string {
	return firstNames[rand.Intn(len(firstNames))] + " " + lastNames[rand.Intn(len(lastNames))]
}

// TempMailProvider 临时邮箱提供商
type TempMailProvider struct {
	Name        string
	GenerateURL string
	CheckURL    string
	Headers     map[string]string
}

// 支持的临时邮箱提供商列表
var tempMailProviders = []TempMailProvider{
	{
		Name:        "chatgpt.org.uk",
		GenerateURL: "https://mail.chatgpt.org.uk/api/generate-email",
		CheckURL:    "https://mail.chatgpt.org.uk/api/emails?email=%s",
		Headers: map[string]string{
			"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
			"Referer":    "https://mail.chatgpt.org.uk",
		},
	},
	// 备用邮箱服务可以在这里添加
}

func getTemporaryEmail() (string, error) {
	var lastErr error

	for _, provider := range tempMailProviders {
		email, err := getEmailFromProvider(provider)
		if err != nil {
			lastErr = err
			log.Printf("⚠️ 临时邮箱 %s 失败: %v，尝试下一个", provider.Name, err)
			continue
		}
		return email, nil
	}

	return "", fmt.Errorf("所有临时邮箱服务均失败: %v", lastErr)
}
func getEmailFromProvider(provider TempMailProvider) (string, error) {
	req, _ := http.NewRequest("GET", provider.GenerateURL, nil)
	for k, v := range provider.Headers {
		req.Header.Set(k, v)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, _ := readResponseBody(resp)
	var result TempEmailResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("解析响应失败: %w", err)
	}

	email := result.Email
	if email == "" {
		email = result.Data.Email
	}
	if email == "" {
		return "", fmt.Errorf("返回的邮箱为空")
	}
	return email, nil
}

// getEmailCount 获取当前邮件数量
func getEmailCount(email string) int {
	req, _ := http.NewRequest("GET", fmt.Sprintf("https://mail.chatgpt.org.uk/api/emails?email=%s", email), nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	req.Header.Set("Referer", "https://mail.chatgpt.org.uk")

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	body, _ := readResponseBody(resp)
	var result EmailListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return 0
	}
	return len(result.Data.Emails)
}

func getVerificationEmailQuick(email string, retries int, intervalSec int) (*EmailContent, error) {
	return getVerificationEmailAfter(email, retries, intervalSec, 0)
}

// getVerificationEmailAfter 获取包含有效验证码的新邮件
func getVerificationEmailAfter(email string, retries int, intervalSec int, initialCount int) (*EmailContent, error) {
	for i := 0; i < retries; i++ {
		req, _ := http.NewRequest("GET", fmt.Sprintf("https://mail.chatgpt.org.uk/api/emails?email=%s", email), nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		req.Header.Set("Referer", "https://mail.chatgpt.org.uk")

		resp, err := httpClient.Do(req)
		if err != nil {
			time.Sleep(time.Duration(intervalSec) * time.Second)
			continue
		}

		body, _ := readResponseBody(resp)
		resp.Body.Close()

		var result EmailListResponse
		if err := json.Unmarshal(body, &result); err != nil {
			time.Sleep(time.Duration(intervalSec) * time.Second)
			continue
		}

		// 检查是否有新邮件（数量增加）且包含有效验证码
		if result.Success && len(result.Data.Emails) > initialCount {
			// 验证最新邮件是否包含有效验证码
			latestEmail := &result.Data.Emails[0]
			if _, err := extractVerificationCode(latestEmail.Content); err == nil {
				return latestEmail, nil
			}
			// 验证码提取失败，继续等待新邮件
		}
		time.Sleep(time.Duration(intervalSec) * time.Second)
	}
	return nil, fmt.Errorf("未收到验证码邮件")
}

func extractVerificationCode(content string) (string, error) {
	re := regexp.MustCompile(`\b[A-Z0-9]{6}\b`)
	matches := re.FindAllString(content, -1)

	for _, code := range matches {
		if commonWords[code] {
			continue
		}
		if regexp.MustCompile(`[0-9]`).MatchString(code) {
			return code, nil
		}
	}

	for _, code := range matches {
		if !commonWords[code] {
			return code, nil
		}
	}

	re2 := regexp.MustCompile(`(?i)code\s*[:is]\s*([A-Z0-9]{6})`)
	if m := re2.FindStringSubmatch(content); len(m) > 1 {
		return m[1], nil
	}

	return "", fmt.Errorf("无法从邮件中提取验证码")
}
func safeType(page *rod.Page, text string, delay int) error {
	for _, char := range text {
		if err := page.Keyboard.Type(input.Key(char)); err != nil {
			return err
		}
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}
	return nil
}

// debugScreenshot 调试截图
func debugScreenshot(page *rod.Page, threadID int, step string) {
	if !RegisterDebug {
		return
	}
	screenshotDir := filepath.Join(DataDir, "screenshots")
	os.MkdirAll(screenshotDir, 0755)

	filename := filepath.Join(screenshotDir, fmt.Sprintf("thread%d_%s_%d.png", threadID, step, time.Now().Unix()))
	data, err := page.Screenshot(true, nil)
	if err != nil {
		log.Printf("[注册 %d] 📸 截图失败: %v", threadID, err)
		return
	}
	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Printf("[注册 %d] 📸 保存截图失败: %v", threadID, err)
		return
	}
	log.Printf("[注册 %d] 📸 截图保存: %s", threadID, filename)
}

// handleAdditionalSteps 处理额外步骤（复选框、密码、公司信息等）
func handleAdditionalSteps(page *rod.Page, threadID int) bool {
	log.Printf("[注册 %d] 检查是否需要处理额外步骤...", threadID)
	
	hasAdditionalSteps := false
	
	// 检查是否需要同意条款
	checkboxResult, _ := page.Eval(`() => {
		const checkboxes = document.querySelectorAll('input[type="checkbox"]');
		for (const checkbox of checkboxes) {
			if (!checkbox.checked) {
				checkbox.click();
				return { clicked: true };
			}
		}
		return { clicked: false };
	}`)
	
	if checkboxResult != nil && checkboxResult.Value.Get("clicked").Bool() {
		hasAdditionalSteps = true
		log.Printf("[注册 %d] 已勾选条款复选框", threadID)
		time.Sleep(1 * time.Second)
	}
	
	// 检查是否需要输入密码
	passwordResult, _ := page.Eval(`() => {
		const passwordFields = document.querySelectorAll('input[type="password"]');
		if (passwordFields.length > 0) {
			for (const field of passwordFields) {
				if (!field.value) {
					field.value = 'TestPassword123!';
					// 触发事件
					field.dispatchEvent(new Event('input', { bubbles: true }));
					field.dispatchEvent(new Event('change', { bubbles: true }));
					return { set: true };
				}
			}
		}
		return { set: false };
	}`)
	
	if passwordResult != nil && passwordResult.Value.Get("set").Bool() {
		hasAdditionalSteps = true
		log.Printf("[注册 %d] 已填写密码", threadID)
		time.Sleep(1 * time.Second)
	}
	
	// 检查是否需要公司信息
	companyResult, _ := page.Eval(`() => {
		const companySelectors = [
			'input[name*="company"]',
			'input[name*="organization"]',
			'input[name*="business"]',
			'input[placeholder*="Company"]',
			'input[placeholder*="Organization"]'
		];
		
		for (const selector of companySelectors) {
			const elements = document.querySelectorAll(selector);
			if (elements.length > 0 && !elements[0].value) {
				elements[0].value = 'Test Company';
				elements[0].dispatchEvent(new Event('input', { bubbles: true }));
				return { set: true };
			}
		}
		
		return { set: false };
	}`)
	
	if companyResult != nil && companyResult.Value.Get("set").Bool() {
		hasAdditionalSteps = true
		log.Printf("[注册 %d] 已填写公司名称", threadID)
		time.Sleep(1 * time.Second)
	}
	
	// 检查是否需要职位信息
	roleResult, _ := page.Eval(`() => {
		const roleFields = [
			'input[name*="title"]',
			'input[name*="role"]',
			'input[name*="position"]',
			'input[placeholder*="Title"]',
			'input[placeholder*="Role"]'
		];
		
		for (const selector of roleFields) {
			const elements = document.querySelectorAll(selector);
			if (elements.length > 0 && !elements[0].value) {
				elements[0].value = 'Developer';
				elements[0].dispatchEvent(new Event('input', { bubbles: true }));
				return { set: true };
			}
		}
		
		return { set: false };
	}`)
	
	if roleResult != nil && roleResult.Value.Get("set").Bool() {
		hasAdditionalSteps = true
		log.Printf("[注册 %d] 已填写职位", threadID)
		time.Sleep(1 * time.Second)
	}
	
	// 如果有额外步骤，尝试提交
	if hasAdditionalSteps {
		log.Printf("[注册 %d] 发现有额外步骤，尝试提交...", threadID)
		
		// 尝试提交额外信息
		for i := 0; i < 3; i++ {
			submitResult, _ := page.Eval(`() => {
				const submitButtons = [
					...document.querySelectorAll('button'),
					...document.querySelectorAll('input[type="submit"]')
				];
				
				for (const button of submitButtons) {
					if (!button.disabled && button.offsetParent !== null) {
						const text = button.textContent || '';
						if (text.includes('同意') || text.includes('Confirm') || 
							text.includes('继续') || text.includes('Next') || 
							text.includes('Submit') || text.includes('完成')) {
							button.click();
							return { clicked: true };
						}
					}
				}
				
				// 点击第一个可用的提交按钮
				for (const button of submitButtons) {
					if (!button.disabled && button.offsetParent !== null) {
						button.click();
						return { clicked: true };
					}
				}
				
				return { clicked: false };
			}`)
			
			if submitResult != nil && submitResult.Value.Get("clicked").Bool() {
				log.Printf("[注册 %d] 已提交额外信息", threadID)
				break
			}
			
			time.Sleep(1 * time.Second)
		}
		
		// 等待可能的跳转
		time.Sleep(3 * time.Second)
		return true
	}
	
	return false
}

// checkAndHandleAdminPage 检查并处理管理创建页面
func checkAndHandleAdminPage(page *rod.Page, threadID int) bool {
	currentURL := ""
	info, _ := page.Info()
	if info != nil {
		currentURL = info.URL
	}
	
	// 检查是否是管理创建页面
	if strings.Contains(currentURL, "/admin/create") {
		log.Printf("[注册 %d] 检测到管理创建页面，尝试完成设置...", threadID)
		
		// 尝试填写必要的表单字段
		formCompleted, _ := page.Eval(`() => {
			let completed = false;
			
			// 查找公司名称字段
			const companyFields = [
				'input[name*="company"]',
				'input[name*="organization"]',
				'input[name*="business"]',
				'input[placeholder*="Company"]',
				'input[placeholder*="Organization"]'
			];
			
			for (const selector of companyFields) {
				const elements = document.querySelectorAll(selector);
				if (elements.length > 0) {
					elements[0].value = 'Test Company';
					elements[0].dispatchEvent(new Event('input', { bubbles: true }));
					completed = true;
					console.log('填写公司名称');
					break;
				}
			}
			
			// 查找职位字段
			const roleFields = [
				'input[name*="title"]',
				'input[name*="role"]',
				'input[name*="position"]',
				'input[placeholder*="Title"]',
				'input[placeholder*="Role"]'
			];
			
			for (const selector of roleFields) {
				const elements = document.querySelectorAll(selector);
				if (elements.length > 0) {
					elements[0].value = 'Developer';
					elements[0].dispatchEvent(new Event('input', { bubbles: true }));
					completed = true;
					console.log('填写职位');
					break;
				}
			}
			
			// 查找并点击继续按钮
			const continueTexts = ['Continue', '继续', 'Next', 'Submit', 'Finish', '完成'];
			const allButtons = document.querySelectorAll('button');
			
			for (const button of allButtons) {
				if (button.offsetParent !== null && !button.disabled) {
					const text = (button.textContent || '').trim();
					if (continueTexts.some(t => text.includes(t))) {
						button.click();
						console.log('点击继续按钮:', text);
						completed = true;
						return completed;
					}
				}
			}
			
			// 如果没有找到特定按钮，尝试点击第一个可见按钮
			for (const button of allButtons) {
				if (button.offsetParent !== null && !button.disabled) {
					const text = button.textContent || '';
					if (text.trim() && !text.includes('Cancel') && !text.includes('取消')) {
						button.click();
						console.log('点击通用按钮:', text);
						completed = true;
						break;
					}
				}
			}
			
			return completed;
		}`)
		
		if formCompleted != nil && formCompleted.Value.Bool() {
			log.Printf("[注册 %d] 已填写管理表单，等待跳转...", threadID)
			time.Sleep(5 * time.Second)
			return true
		}
	}
	
	return false
}

func RunBrowserRegister(headless bool, proxy string, threadID int) (result *BrowserRegisterResult) {
	result = &BrowserRegisterResult{}
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[注册 %d] ☠️ panic 恢复: %v", threadID, r)
			result.Error = fmt.Errorf("panic: %v", r)
		}
	}()

	// 获取临时邮箱
	email, err := getTemporaryEmail()
	if err != nil {
		result.Error = err
		return result
	}
	result.Email = email

	// 启动浏览器 - 优先使用系统浏览器
	l := launcher.New()

	// 检测系统浏览器（支持更多环境）
	systemBrowsers := []string{
		// Linux
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/snap/bin/chromium",
		"/opt/google/chrome/chrome",
		// Docker/Alpine
		"/usr/bin/chromium-browser",
		"/usr/lib/chromium/chromium",
		// Windows
		"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
		"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
		// macOS
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
		"/Applications/Chromium.app/Contents/MacOS/Chromium",
	}

	browserFound := false
	for _, path := range systemBrowsers {
		if _, err := os.Stat(path); err == nil {
			l = l.Bin(path)
			browserFound = true
			log.Printf("[注册 %d] 使用浏览器: %s", threadID, path)
			break
		}
	}

	if !browserFound {
		log.Printf("[注册 %d] ⚠️ 未找到系统浏览器，尝试使用 rod 自动下载", threadID)
	}

	// 设置启动参数（兼容更多环境）
	l = l.Headless(headless).
		Set("no-sandbox").
		Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-gpu").
		Set("disable-software-rasterizer").
		Set("disable-blink-features", "AutomationControlled").
		Set("window-size", "1280,800").
		Set("lang", "zh-CN").
		Set("disable-extensions")

	if proxy != "" {
		l = l.Proxy(proxy)
	}

	url, err := l.Launch()
	if err != nil {
		result.Error = fmt.Errorf("启动浏览器失败: %w", err)
		return result
	}

	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		result.Error = fmt.Errorf("连接浏览器失败: %w", err)
		return result
	}
	defer browser.Close()

	browser = browser.Timeout(120 * time.Second)

	// 获取默认页面
	pages, _ := browser.Pages()
	var page *rod.Page
	if len(pages) > 0 {
		page = pages[0]
	} else {
		page, _ = browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	}

	// 设置视口和 User-Agent
	page.MustSetViewport(1280, 800, 1, false)
	page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	})

	// 监听请求以捕获 authorization
	var authorization string
	var configID, csesidx string

	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if auth, ok := e.Request.Headers["authorization"]; ok {
			if authStr := auth.String(); authStr != "" {
				authorization = authStr
			}
		}
		url := e.Request.URL
		if m := regexp.MustCompile(`/cid/([a-f0-9-]+)`).FindStringSubmatch(url); len(m) > 1 && configID == "" {
			configID = m[1]
		}
		if m := regexp.MustCompile(`[?&]csesidx=(\d+)`).FindStringSubmatch(url); len(m) > 1 && csesidx == "" {
			csesidx = m[1]
		}
	})()
	if err := page.Navigate("https://business.gemini.google"); err != nil {
		result.Error = fmt.Errorf("打开页面失败: %w", err)
		return result
	}
	page.WaitLoad()
	time.Sleep(500 * time.Millisecond)
	debugScreenshot(page, threadID, "01_page_loaded")
	if _, err := page.Timeout(20 * time.Second).Element("input"); err != nil {
		result.Error = fmt.Errorf("等待输入框超时: %w", err)
		return result
	}
	time.Sleep(300 * time.Millisecond)

	// 点击输入框聚焦
	page.Eval(`() => {
		const inputs = document.querySelectorAll('input');
		if (inputs.length > 0) {
			inputs[0].click();
			inputs[0].focus();
		}
	}`)
	time.Sleep(200 * time.Millisecond)
	safeType(page, email, 15)
	time.Sleep(500 * time.Millisecond)
	debugScreenshot(page, threadID, "02_email_input")

	// 触发 blur
	page.Eval(`() => {
		const inputs = document.querySelectorAll('input');
		if (inputs.length > 0) {
			inputs[0].blur();
		}
	}`)
	time.Sleep(500 * time.Millisecond)
	debugScreenshot(page, threadID, "03_before_submit")
	emailSubmitted := false
	for i := 0; i < 8; i++ {
		clickResult, _ := page.Eval(`() => {
			if (!document.body) return { clicked: false, reason: 'body_null' };
			
			const targets = ['继续', 'Next', '邮箱', 'Continue'];
			const elements = [
				...document.querySelectorAll('button'),
				...document.querySelectorAll('input[type="submit"]'),
				...document.querySelectorAll('div[role="button"]'),
				...document.querySelectorAll('span[role="button"]')
			];

			for (const element of elements) {
				if (!element) continue;
				const style = window.getComputedStyle(element);
				if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') continue;
				if (element.disabled) continue;

				const text = element.textContent ? element.textContent.trim() : '';
				if (targets.some(t => text.includes(t))) {
					element.click();
					return { clicked: true, text: text };
				}
			}
			return { clicked: false, reason: 'no_button' };
		}`)

		if clickResult != nil && clickResult.Value.Get("clicked").Bool() {
			emailSubmitted = true
			break
		}
		log.Printf("[注册 %d] 尝试 %d/8: 未找到按钮", threadID, i+1)
		time.Sleep(1 * time.Second)
	}
	if !emailSubmitted {
		result.Error = fmt.Errorf("找不到提交按钮")
		return result
	}
	time.Sleep(2 * time.Second)
	debugScreenshot(page, threadID, "04_after_submit")
	var needsVerification bool
	checkResult, _ := page.Eval(`() => {
		const pageText = document.body ? document.body.textContent : '';
		
		// 检查常见错误
		if (pageText.includes('出了点问题') || pageText.includes('Something went wrong') ||
			pageText.includes('无法创建') || pageText.includes('cannot create') ||
			pageText.includes('不安全') || pageText.includes('secure') ||
			pageText.includes('电话') || pageText.includes('Phone') || pageText.includes('number')) {
			return { error: true, text: document.body.innerText.substring(0, 100) };
		}

		// 检查是否需要验证码
		if (pageText.includes('验证') || pageText.includes('Verify') || 
			pageText.includes('code') || pageText.includes('sent')) {
			return { needsVerification: true, isNamePage: false };
		}
		
		// 检查是否已经到了姓名页面
		if (pageText.includes('姓氏') || pageText.includes('名字') || 
			pageText.includes('Full name') || pageText.includes('全名')) {
			return { needsVerification: false, isNamePage: true };
		}
		
		return { needsVerification: true, isNamePage: false };
	}`)

	if checkResult != nil {
		if checkResult.Value.Get("error").Bool() {
			errText := checkResult.Value.Get("text").String()
			result.Error = fmt.Errorf("页面显示错误: %s...", errText)
			log.Printf("[注册 %d] ❌ %v", threadID, result.Error)
			return result
		}
		needsVerification = checkResult.Value.Get("needsVerification").Bool()
		isNamePage := checkResult.Value.Get("isNamePage").Bool()
		log.Printf("[注册 %d] 页面状态: needsVerification=%v, isNamePage=%v", threadID, needsVerification, isNamePage)
	} else {
		needsVerification = true
	}

	// 处理验证码
	if needsVerification {

		var emailContent *EmailContent
		maxWaitTime := 3 * time.Minute
		startTime := time.Now()
		clickCount := 0

		for time.Since(startTime) < maxWaitTime {
			// 尝试点击重发按钮
			clickResult, _ := page.Eval(`() => {
				// 精确匹配: <span jsname="V67aGc" class="YuMlnb-vQzf8d">重新发送验证码</span>
				const btn = document.querySelector('span[jsname="V67aGc"].YuMlnb-vQzf8d') ||
				            document.querySelector('span.YuMlnb-vQzf8d');
				
				if (btn && btn.textContent.includes('重新发送')) {
					btn.click();
					if (btn.parentElement) btn.parentElement.click();
					return {clicked: true};
				}
				return {clicked: false};
			}`)

			if clickResult != nil && clickResult.Value.Get("clicked").Bool() {
				clickCount++
				time.Sleep(1 * time.Second)
			}

			// 快速检查邮件
			emailContent, _ = getVerificationEmailQuick(email, 1, 1)
			if emailContent != nil {
				break
			}
		}

		if emailContent == nil {
			result.Error = fmt.Errorf("无法获取验证码邮件")
			return result
		}

		// 提取验证码
		code, err := extractVerificationCode(emailContent.Content)
		if err != nil {
			result.Error = err
			return result
		}

		// 等待验证码输入框
		time.Sleep(500 * time.Millisecond)

		// 清空并聚焦输入框
		page.Eval(`() => {
			const inputs = document.querySelectorAll('input');
			if (inputs.length > 0) {
				inputs[0].value = '';
				inputs[0].click();
				inputs[0].focus();
			}
		}`)
		time.Sleep(200 * time.Millisecond)
		safeType(page, code, 15)
		time.Sleep(500 * time.Millisecond)

		// 触发 blur
		page.Eval(`() => {
			const inputs = document.querySelectorAll('input');
			if (inputs.length > 0) {
				inputs[0].blur();
			}
		}`)
		time.Sleep(500 * time.Millisecond)

		for i := 0; i < 5; i++ {
			clickResult, _ := page.Eval(`() => {
				const targets = ['验证', 'Verify', '继续', 'Next', 'Continue'];
				const elements = [
					...document.querySelectorAll('button'),
					...document.querySelectorAll('input[type="submit"]'),
					...document.querySelectorAll('div[role="button"]')
				];

				for (const element of elements) {
					if (!element) continue;
					const style = window.getComputedStyle(element);
					if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') continue;
					if (element.disabled) continue;

					const text = element.textContent ? element.textContent.trim() : '';
					if (targets.some(t => text.includes(t))) {
						element.click();
						return { clicked: true, text: text };
					}
				}
				return { clicked: false };
			}`)

			if clickResult != nil && clickResult.Value.Get("clicked").Bool() {
				break
			}
			time.Sleep(1 * time.Second)
		}

		time.Sleep(2 * time.Second)
	}

	// 填写姓名
	fullName := generateRandomName()
	result.FullName = fullName

	time.Sleep(500 * time.Millisecond)

	// 清空并聚焦输入框
	page.Eval(`() => {
		const inputs = document.querySelectorAll('input');
		if (inputs.length > 0) {
			inputs[0].value = '';
			inputs[0].click();
			inputs[0].focus();
		}
	}`)
	time.Sleep(200 * time.Millisecond)

	// 输入姓名
	safeType(page, fullName, 15)
	time.Sleep(500 * time.Millisecond)

	// 触发 blur
	page.Eval(`() => {
		const inputs = document.querySelectorAll('input');
		if (inputs.length > 0) {
			inputs[0].blur();
		}
	}`)
	time.Sleep(200 * time.Millisecond)
	
	// 确认提交姓名
	confirmSubmitted := false
	for i := 0; i < 5; i++ {
		clickResult, _ := page.Eval(`() => {
			const targets = ['同意', 'Confirm', '继续', 'Next', 'Continue', 'I agree'];
			const elements = [
				...document.querySelectorAll('button'),
				...document.querySelectorAll('input[type="submit"]'),
				...document.querySelectorAll('div[role="button"]')
			];

			for (const element of elements) {
				if (!element) continue;
				const style = window.getComputedStyle(element);
				if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') continue;
				if (element.disabled) continue;

				const text = element.textContent ? element.textContent.trim() : '';
				if (targets.some(t => text.includes(t))) {
					element.click();
					return { clicked: true, text: text };
				}
			}

			// 备用：点击第一个可见按钮
			for (const element of elements) {
				if (element && element.offsetParent !== null && !element.disabled) {
					element.click();
					return { clicked: true, text: 'fallback' };
				}
			}
			return { clicked: false };
		}`)

		if clickResult != nil && clickResult.Value.Get("clicked").Bool() {
			confirmSubmitted = true
			break
		}
		time.Sleep(1000 * time.Millisecond)
	}
	
	if !confirmSubmitted {
		log.Printf("[注册 %d] ⚠️ 未能点击确认按钮，尝试继续", threadID)
	}
	
	time.Sleep(3 * time.Second)
	
	// 等待页面稳定
	page.WaitLoad()
	time.Sleep(2 * time.Second)
	
	// 处理额外步骤（复选框、密码、公司信息等）
	handleAdditionalSteps(page, threadID)
	
	// 检查并处理管理创建页面
	checkAndHandleAdminPage(page, threadID)
	
	// 等待更多可能的跳转
	time.Sleep(3 * time.Second)
	
	// 尝试多次点击可能出现的额外按钮
	for i := 0; i < 15; i++ {
		time.Sleep(2 * time.Second)

		// 尝试点击可能出现的额外按钮
		page.Eval(`() => {
			const buttons = document.querySelectorAll('button');
			for (const button of buttons) {
				if (!button) continue;
				const text = button.textContent || '';
				if (text.includes('同意') || text.includes('Confirm') || text.includes('继续') || 
					text.includes('Next') || text.includes('I agree')) {
					if (button.offsetParent !== null && !button.disabled) {
						button.click();
						return true;
					}
				}
			}
			return false;
		}`)

		// 从 URL 提取信息
		info, _ := page.Info()
		if info != nil {
			currentURL := info.URL
			if m := regexp.MustCompile(`/cid/([a-f0-9-]+)`).FindStringSubmatch(currentURL); len(m) > 1 && configID == "" {
				configID = m[1]
				log.Printf("[注册 %d] 从URL提取 configId: %s", threadID, configID)
			}
			if m := regexp.MustCompile(`[?&]csesidx=(\d+)`).FindStringSubmatch(currentURL); len(m) > 1 && csesidx == "" {
				csesidx = m[1]
				log.Printf("[注册 %d] 从URL提取 csesidx: %s", threadID, csesidx)
			}
		}

		if authorization != "" {
			break
		}
	}
	
	// 增强的 Authorization 获取逻辑
	if authorization == "" {
		log.Printf("[注册 %d] 仍未获取到 Authorization，尝试更多方法...", threadID)
		
		// 尝试刷新页面
		page.Reload()
		page.WaitLoad()
		time.Sleep(3 * time.Second)
		
		// 尝试从 localStorage 获取
		localStorageAuth, _ := page.Eval(`() => {
			return localStorage.getItem('Authorization') || 
				   localStorage.getItem('authorization') ||
				   localStorage.getItem('auth_token') ||
				   localStorage.getItem('token');
		}`)
		
		if localStorageAuth != nil && localStorageAuth.Value.String() != "" {
			authorization = localStorageAuth.Value.String()
			log.Printf("[注册 %d] 从 localStorage 获取 Authorization", threadID)
		}
		
		// 从页面源代码中提取
		pageContent, _ := page.Eval(`() => document.body ? document.body.innerHTML : ''`)
		if pageContent != nil && pageContent.Value.String() != "" {
			content := pageContent.Value.String()
			re := regexp.MustCompile(`"authorization"\s*:\s*"([^"]+)"`)
			if matches := re.FindStringSubmatch(content); len(matches) > 1 {
				authorization = matches[1]
				log.Printf("[注册 %d] 从页面内容提取 Authorization", threadID)
			}
		}
		
		// 从当前 URL 中提取
		info, _ := page.Info()
		if info != nil {
			currentURL := info.URL
			re := regexp.MustCompile(`[?&](?:token|auth)=([^&]+)`)
			if matches := re.FindStringSubmatch(currentURL); len(matches) > 1 {
				authorization = matches[1]
				log.Printf("[注册 %d] 从 URL 提取 Authorization", threadID)
			}
		}
	}

	if authorization == "" {
		result.Error = fmt.Errorf("未能获取 Authorization")
		return result
	}
	var resultCookies []Cookie
	cookieMap := make(map[string]bool)

	// 获取当前页面所有 cookie
	cookies, _ := page.Cookies(nil)
	for _, c := range cookies {
		key := c.Name + "|" + c.Domain
		if !cookieMap[key] {
			cookieMap[key] = true
			resultCookies = append(resultCookies, Cookie{
				Name:   c.Name,
				Value:  c.Value,
				Domain: c.Domain,
			})
		}
	}

	// 尝试从特定域名获取更多 cookie
	domains := []string{
		"https://business.gemini.google",
		"https://gemini.google",
		"https://accounts.google.com",
	}
	for _, domain := range domains {
		domainCookies, err := page.Cookies([]string{domain})
		if err == nil {
			for _, c := range domainCookies {
				key := c.Name + "|" + c.Domain
				if !cookieMap[key] {
					cookieMap[key] = true
					resultCookies = append(resultCookies, Cookie{
						Name:   c.Name,
						Value:  c.Value,
						Domain: c.Domain,
					})
				}
			}
		}
	}

	log.Printf("[注册 %d] 获取到 %d 个 Cookie", threadID, len(resultCookies))

	result.Success = true
	result.Authorization = authorization
	result.Cookies = resultCookies
	result.ConfigID = configID
	result.CSESIDX = csesidx

	log.Printf("[注册 %d] ✅ 注册成功: %s", threadID, email)
	return result
}

// SaveBrowserRegisterResult 保存注册结果
func SaveBrowserRegisterResult(result *BrowserRegisterResult, dataDir string) error {
	if !result.Success {
		return result.Error
	}

	data := AccountData{
		Email:         result.Email,
		FullName:      result.FullName,
		Authorization: result.Authorization,
		Cookies:       result.Cookies,
		ConfigID:      result.ConfigID,
		CSESIDX:       result.CSESIDX,
		Timestamp:     time.Now().Format(time.RFC3339),
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化失败: %w", err)
	}

	filename := filepath.Join(dataDir, fmt.Sprintf("%s.json", result.Email))
	if err := os.WriteFile(filename, jsonData, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %w", err)
	}

	return nil
}

// BrowserRefreshResult Cookie刷新结果
type BrowserRefreshResult struct {
	Success         bool
	SecureCookies   []Cookie
	ConfigID        string
	CSESIDX         string
	Authorization   string
	ResponseHeaders map[string]string // 捕获的响应头
	NewCookies      []Cookie          // 从响应头提取的新Cookie
	Error           error
}

func RefreshCookieWithBrowser(acc *Account, headless bool, proxy string) *BrowserRefreshResult {
	result := &BrowserRefreshResult{}
	email := acc.Data.Email

	defer func() {
		if r := recover(); r != nil {
			result.Error = fmt.Errorf("panic: %v", r)
		}
	}()

	// 启动浏览器
	l := launcher.New()
	systemBrowsers := []string{
		"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
		"/usr/bin/chromium", "/usr/bin/chromium-browser",
		"/snap/bin/chromium", "/opt/google/chrome/chrome",
		"/usr/lib/chromium/chromium",
		"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	}
	for _, path := range systemBrowsers {
		if _, err := os.Stat(path); err == nil {
			l = l.Bin(path)
			break
		}
	}

	l = l.Headless(headless).
		Set("no-sandbox").
		Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-gpu").
		Set("disable-blink-features", "AutomationControlled").
		Set("window-size", "1280,800")

	if proxy != "" {
		l = l.Proxy(proxy)
	}

	url, err := l.Launch()
	if err != nil {
		result.Error = fmt.Errorf("启动浏览器失败: %w", err)
		return result
	}

	browser := rod.New().ControlURL(url)
	if err := browser.Connect(); err != nil {
		result.Error = fmt.Errorf("连接浏览器失败: %w", err)
		return result
	}
	defer browser.Close()

	browser = browser.Timeout(120 * time.Second)

	pages, _ := browser.Pages()
	var page *rod.Page
	if len(pages) > 0 {
		page = pages[0]
	} else {
		page, _ = browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	}

	page.MustSetViewport(1280, 800, 1, false)
	page.SetUserAgent(&proto.NetworkSetUserAgentOverride{
		UserAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	})

	// 监听请求和响应以捕获 authorization 和响应头
	var authorization string
	var configID, csesidx string
	var responseHeadersMu sync.Mutex
	responseHeaders := make(map[string]string)
	var newCookiesFromResponse []Cookie

	// 监听响应以捕获 Set-Cookie 等头信息
	go page.EachEvent(func(e *proto.NetworkResponseReceived) {
		responseHeadersMu.Lock()
		defer responseHeadersMu.Unlock()

		// 获取响应头中的重要信息 - Headers 是 map[string]gson.JSON 类型
		headers := e.Response.Headers
		importantKeys := []string{"set-cookie", "Set-Cookie", "authorization", "Authorization",
			"x-goog-authenticated-user", "X-Goog-Authenticated-User"}

		for _, key := range importantKeys {
			if val, ok := headers[key]; ok {
				str := val.Str()
				if str == "" {
					continue
				}
				responseHeaders[key] = str
				// 解析 Set-Cookie
				if strings.ToLower(key) == "set-cookie" {
					parts := strings.Split(str, ";")
					if len(parts) > 0 {
						nv := strings.SplitN(parts[0], "=", 2)
						if len(nv) == 2 {
							newCookiesFromResponse = append(newCookiesFromResponse, Cookie{
								Name:   strings.TrimSpace(nv[0]),
								Value:  strings.TrimSpace(nv[1]),
								Domain: ".gemini.google",
							})
						}
					}
				}
			}
		}
	})()

	go page.EachEvent(func(e *proto.NetworkRequestWillBeSent) {
		if auth, ok := e.Request.Headers["authorization"]; ok {
			if authStr := auth.String(); authStr != "" {
				authorization = authStr
			}
		}
		reqURL := e.Request.URL
		if m := regexp.MustCompile(`/cid/([a-f0-9-]+)`).FindStringSubmatch(reqURL); len(m) > 1 && configID == "" {
			configID = m[1]
		}
		if m := regexp.MustCompile(`[?&]csesidx=(\d+)`).FindStringSubmatch(reqURL); len(m) > 1 && csesidx == "" {
			csesidx = m[1]
		}
	})()

	// 导航到目标页面
	targetURL := "https://business.gemini.google/"
	page.Navigate(targetURL)
	page.WaitLoad()
	time.Sleep(2 * time.Second)

	// 检查页面状态
	info, _ := page.Info()
	currentURL := ""
	if info != nil {
		currentURL = info.URL
	}
	initialEmailCount := 0
	maxCodeRetries := 3 // 验证码重试次数（必须在goto之前声明）

	// 检查是否已经登录成功（有authorization）
	if authorization != "" {
		log.Printf("[Cookie刷新] [%s] Cookie有效，已自动登录", email)
		goto extractResult
	}

	// 获取实际邮件数量
	initialEmailCount = getEmailCount(email)

	// 检查是否在登录页面需要输入邮箱
	if _, err := page.Timeout(5 * time.Second).Element("input"); err == nil {

		// 输入邮箱 - 先清空再输入
		time.Sleep(500 * time.Millisecond)
		page.Eval(`() => {
			const inputs = document.querySelectorAll('input');
			if (inputs.length > 0) {
				inputs[0].value = '';
				inputs[0].click();
				inputs[0].focus();
			}
		}`)
		time.Sleep(300 * time.Millisecond)
		safeType(page, email, 30)
		time.Sleep(500 * time.Millisecond)
		page.Eval(`() => {
			const inputs = document.querySelectorAll('input');
			if (inputs.length > 0) { inputs[0].blur(); }
		}`)
		time.Sleep(500 * time.Millisecond)

		// 点击继续按钮
		for i := 0; i < 5; i++ {
			clickResult, _ := page.Eval(`() => {
				const targets = ['继续', 'Next', 'Continue', '邮箱'];
				const elements = [...document.querySelectorAll('button'), ...document.querySelectorAll('div[role="button"]')];
				for (const el of elements) {
					if (!el || el.disabled) continue;
					const style = window.getComputedStyle(el);
					if (style.display === 'none' || style.visibility === 'hidden') continue;
					const text = el.textContent ? el.textContent.trim() : '';
					if (targets.some(t => text.includes(t))) { el.click(); return {clicked:true}; }
				}
				return {clicked:false};
			}`)
			if clickResult != nil && clickResult.Value.Get("clicked").Bool() {
				break
			}
			time.Sleep(1 * time.Second)
		}
		time.Sleep(2 * time.Second)
	}
	time.Sleep(3 * time.Second)

	// 验证码重试循环
	for codeRetry := 0; codeRetry < maxCodeRetries; codeRetry++ {
		if codeRetry > 0 {
			log.Printf("[Cookie刷新] [%s] 验证码验证失败，重试 %d/%d", email, codeRetry+1, maxCodeRetries)
			// 点击"重新发送验证码"按钮
			page.Eval(`() => {
				const links = document.querySelectorAll('a, span, button');
				for (const el of links) {
					const text = el.textContent || '';
					if (text.includes('重新发送') || text.includes('Resend')) {
						el.click();
						return true;
					}
				}
				return false;
			}`)
			time.Sleep(2 * time.Second)
			// 更新邮件计数基准
			initialEmailCount = getEmailCount(email)
		}

		var emailContent *EmailContent
		maxWaitTime := 3 * time.Minute
		startTime := time.Now()

		for time.Since(startTime) < maxWaitTime {
			// 快速检查新邮件（只接受数量增加的情况）
			emailContent, _ = getVerificationEmailAfter(email, 1, 1, initialEmailCount)
			if emailContent != nil {
				break
			}
			time.Sleep(2 * time.Second)
		}

		if emailContent == nil {
			result.Error = fmt.Errorf("无法获取验证码邮件")
			return result
		}

		// 提取验证码
		code, err := extractVerificationCode(emailContent.Content)
		if err != nil {
			continue // 重试
		}

		// 输入验证码
		time.Sleep(500 * time.Millisecond)
		page.Eval(`() => {
			const inputs = document.querySelectorAll('input');
			for (const inp of inputs) { inp.value = ''; }
			if (inputs.length > 0) { inputs[0].click(); inputs[0].focus(); }
		}`)
		time.Sleep(300 * time.Millisecond)
		safeType(page, code, 30)
		time.Sleep(500 * time.Millisecond)

		// 点击验证按钮
		for i := 0; i < 5; i++ {
			clickResult, _ := page.Eval(`() => {
				const targets = ['验证', 'Verify', '继续', 'Next', 'Continue'];
				const els = [...document.querySelectorAll('button'), ...document.querySelectorAll('div[role="button"]')];
				for (const el of els) {
					if (!el || el.disabled) continue;
					const style = window.getComputedStyle(el);
					if (style.display === 'none' || style.visibility === 'hidden') continue;
					const text = el.textContent ? el.textContent.trim() : '';
					if (targets.some(t => text.includes(t))) { el.click(); return {clicked:true}; }
				}
				return {clicked:false};
			}`)
			if clickResult != nil && clickResult.Value.Get("clicked").Bool() {
				break
			}
			time.Sleep(1 * time.Second)
		}
		time.Sleep(2 * time.Second)

		// 检测验证码错误
		hasError, _ := page.Eval(`() => {
			const text = document.body.innerText || '';
			return text.includes('验证码有误') || text.includes('incorrect') || text.includes('wrong code') || text.includes('请重试');
		}`)
		if hasError != nil && hasError.Value.Bool() {
			continue // 重试
		}

		// 验证成功，跳出重试循环
		break
	}
	for i := 0; i < 15; i++ {
		time.Sleep(2 * time.Second)

		// 点击可能出现的确认按钮
		page.Eval(`() => {
			const btns = document.querySelectorAll('button');
			for (const btn of btns) {
				const text = btn.textContent || '';
				if ((text.includes('同意') || text.includes('Confirm') || text.includes('继续') || text.includes('I agree')) && btn.offsetParent !== null && !btn.disabled) {
					btn.click(); return true;
				}
			}
			return false;
		}`)

		// 从URL提取信息
		info, _ := page.Info()
		if info != nil {
			if m := regexp.MustCompile(`/cid/([a-f0-9-]+)`).FindStringSubmatch(info.URL); len(m) > 1 && configID == "" {
				configID = m[1]
			}
			if m := regexp.MustCompile(`[?&]csesidx=(\d+)`).FindStringSubmatch(info.URL); len(m) > 1 && csesidx == "" {
				csesidx = m[1]
			}
		}

		if authorization != "" {
			break
		}
	}

extractResult:
	if authorization == "" {
		result.Error = fmt.Errorf("未能获取 Authorization")
		return result
	}

	// 获取cookies - 合并浏览器cookie和响应头中的cookie
	cookies, _ := page.Cookies(nil)
	cookieMap := make(map[string]Cookie) // 用于去重，后添加的会覆盖先添加的

	// 先添加原有的 cookie（作为基础）
	for _, c := range acc.Data.GetAllCookies() {
		cookieMap[c.Name] = c
	}

	// 再添加浏览器获取的 cookie（会覆盖旧的）
	for _, c := range cookies {
		cookieMap[c.Name] = Cookie{
			Name:   c.Name,
			Value:  c.Value,
			Domain: c.Domain,
		}
	}

	// 最后添加从响应头获取的新 cookie（最高优先级）
	responseHeadersMu.Lock()
	for _, c := range newCookiesFromResponse {
		cookieMap[c.Name] = c
	}
	// 复制响应头
	result.ResponseHeaders = make(map[string]string)
	for k, v := range responseHeaders {
		result.ResponseHeaders[k] = v
	}
	result.NewCookies = newCookiesFromResponse
	responseHeadersMu.Unlock()

	// 转换为数组
	var resultCookies []Cookie
	for _, c := range cookieMap {
		resultCookies = append(resultCookies, c)
	}

	// 从URL提取最终信息
	info, _ = page.Info()
	if info != nil {
		currentURL = info.URL
		if m := regexp.MustCompile(`/cid/([a-f0-9-]+)`).FindStringSubmatch(currentURL); len(m) > 1 && configID == "" {
			configID = m[1]
		}
		if m := regexp.MustCompile(`[?&]csesidx=(\d+)`).FindStringSubmatch(currentURL); len(m) > 1 && csesidx == "" {
			csesidx = m[1]
		}
	}

	result.Success = true
	result.Authorization = authorization
	result.SecureCookies = resultCookies
	result.ConfigID = configID
	result.CSESIDX = csesidx

	log.Printf("[Cookie刷新] ✅ [%s] 刷新成功", email)
	return result
}

// NativeRegisterWorker 原生 Go 注册 worker
func NativeRegisterWorker(id int, dataDirAbs string) {
	time.Sleep(time.Duration(id) * 3 * time.Second)

	for atomic.LoadInt32(&isRegistering) == 1 {
		if pool.TotalCount() >= appConfig.Pool.TargetCount {
			return
		}

		log.Printf("[注册线程 %d] 启动注册任务", id)

		result := RunBrowserRegister(appConfig.Pool.RegisterHeadless, Proxy, id)

		if result.Success {
			if err := SaveBrowserRegisterResult(result, dataDirAbs); err != nil {
				log.Printf("[注册线程 %d] ⚠️ 保存失败: %v", id, err)
				registerStats.AddFailed(err.Error())
			} else {
				registerStats.AddSuccess()
				pool.Load(DataDir)
			}
		} else {
			errMsg := "未知错误"
			if result.Error != nil {
				errMsg = result.Error.Error()
			}
			log.Printf("[注册线程 %d] ❌ 注册失败: %s", id, errMsg)
			registerStats.AddFailed(errMsg)

			if strings.Contains(errMsg, "频繁") || strings.Contains(errMsg, "rate") ||
				strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "连接") {
				waitTime := 10 + id*2
				log.Printf("[注册线程 %d] ⏳ 等待 %d 秒后重试...", id, waitTime)
				time.Sleep(time.Duration(waitTime) * time.Second)
			} else {
				time.Sleep(3 * time.Second)
			}
		}
	}
	log.Printf("[注册线程 %d] 停止", id)
}
