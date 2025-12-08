# Business2API

> 🚀 OpenAI/Gemini 兼容的 Gemini Business API 代理服务，支持账号池管理、自动注册和 Flow 图片/视频生成。

[![Build](https://github.com/XxxXTeam/business2api/actions/workflows/build.yml/badge.svg)](https://github.com/XxxXTeam/business2api/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## ✨ 功能特性

- 🔌 **多 API 兼容** - 支持 OpenAI (`/v1/chat/completions`)、Gemini (`/v1beta/models`)、Claude (`/v1/messages`) 格式
- 🏊 **账号池管理** - 自动轮询、刷新、维护多个 Gemini Business 账号
- 🌊 **流式响应** - 支持 SSE 流式输出
- 🎨 **多模态支持** - 支持图片、视频输入和生成
- 🤖 **自动注册** - 浏览器自动化注册新账号
- 🌐 **代理支持** - 支持 HTTP/SOCKS5 代理

## 📦 支持的模型

### Gemini 文本/多模态
| 模型 | 文本 | 图片生成 | 视频生成 | 搜索 |
|------|------|----------|----------|------|
| gemini-2.5-flash | ✅ | ✅ | ✅ | ✅ |
| gemini-2.5-pro | ✅ | ✅ | ✅ | ✅ |
| gemini-3-pro-preview | ✅ | ✅ | ✅ | ✅ |
| gemini-3-pro | ✅ | ✅ | ✅ | ✅ |
---

## 快速开始

### 方式一：Docker 部署（推荐）

#### 1. 使用 Docker Compose

```bash
# 创建目录
mkdir business2api && cd business2api

# 下载必要文件
wget https://raw.githubusercontent.com/XxxXTeam/business2api/master/docker/docker-compose.yml
wget https://raw.githubusercontent.com/XxxXTeam/business2api/master/config/config.json.example -O config.json

# 编辑配置
vim config.json

# 创建数据目录
mkdir data

# 启动服务
docker compose up -d
```

#### 2. 使用 Docker Run

```bash
# 拉取镜像
docker pull ghcr.io/xxxteam/business2api:latest

# 创建配置文件
wget https://raw.githubusercontent.com/XxxXTeam/business2api/master/config/config.json.example -O config.json

# 运行容器
docker run -d \
  --name business2api \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.json:/app/config.json:ro \
  ghcr.io/xxxteam/business2api:latest
```

### 方式二：二进制部署

#### 1. 下载预编译版本

从 [Releases](https://github.com/XxxXTeam/business2api/releases) 下载对应平台的二进制文件。

```bash
# Linux amd64
wget https://github.com/XxxXTeam/business2api/releases/latest/download/business2api-linux-amd64.tar.gz
tar -xzf business2api-linux-amd64.tar.gz
chmod +x business2api-linux-amd64
```

#### 2. 从源码编译

```bash
# 需要 Go 1.24+
git clone https://github.com/XxxXTeam/business2api.git
cd business2api

# 编译
go build -o business2api .

# 运行
./business2api
```

### 方式三：使用 Systemd 服务

```bash
# 创建服务文件
sudo tee /etc/systemd/system/business2api.service << EOF
[Unit]
Description=Gemini Gateway Service
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=/opt/business2api
ExecStart=/opt/business2api/business2api
Restart=always
RestartSec=5
Environment=LISTEN_ADDR=:8000
Environment=DATA_DIR=/opt/business2api/data

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable business2api
sudo systemctl start business2api
```

---

## 配置说明

### config.json

```json
{
  "api_keys": ["sk-your-api-key"],    // API 密钥列表，用于鉴权
  "listen_addr": ":8000",              // 监听地址
  "data_dir": "./data",                // 账号数据目录
  "default_config": "",                // 默认 configId（可选）
  "debug": false,                      // 调试模式（输出详细日志）
  "proxy": "",                         // 代理地址（可选）
  
  "pool": {
    "target_count": 50,                // 目标账号数量
    "min_count": 10,                   // 最小账号数，低于此值触发注册
    "check_interval_minutes": 30,      // 检查间隔（分钟）
    "register_threads": 1,             // 注册线程数
    "register_headless": true,         // 无头模式注册
    "refresh_on_startup": true,        // 启动时刷新账号
    "refresh_cooldown_sec": 240,       // 刷新冷却时间（秒）
    "use_cooldown_sec": 15,            // 使用冷却时间（秒）
    "max_fail_count": 3,               // 最大连续失败次数
    "enable_browser_refresh": true,    // 启用浏览器刷新401账号
    "browser_refresh_headless": true,  // 浏览器刷新无头模式
    "browser_refresh_max_retry": 1     // 浏览器刷新最大重试次数
  },

  "pool_server": {                     
    "enable": false,                   // 是否启用分离模式
    "mode": "local",                   // 运行模式：local/server/client
    "server_addr": "http://ip:8001",   // 服务器地址（client模式）
    "listen_addr": ":8001",            // 监听地址（server模式）
    "secret": "your-secret-key",       // 通信密钥
    "target_count": 50,                // 目标账号数（server模式）
    "data_dir": "./data"               // 数据目录（server模式）
  }
}
```

---

## C/S 分离架构

支持将号池管理与API服务分离部署，适用于多节点场景。

### 架构说明

```
┌─────────────────┐         ┌─────────────────┐
│   API Server    │◄───────►│   Pool Server   │
│   (客户端模式)   │   HTTP   │   (服务器模式)   │
└─────────────────┘         └────────┬────────┘
                                     │
                            WebSocket│
                                     │
                            ┌────────▼────────┐
                            │  Worker Client  │
                            │  (注册/续期)     │
                            └─────────────────┘
```

### 运行模式

| 模式 | 说明 |
|------|------|
| `local` | 本地模式（默认），API服务和号池管理在同一进程 |
| `server` | 服务器模式，提供号池服务和任务分发 |
| `client` | 客户端模式，只接收任务（注册/续期），不提供API服务 |

### Server 模式配置

```json
{
  "pool_server": {
    "enable": true,
    "mode": "server",
    "listen_addr": ":8001",
    "secret": "shared-secret-key",
    "target_count": 100,
    "data_dir": "./data"
  }
}
```

### Client 模式配置（仅注册/续期工作节点）

```json
{
  "pool_server": {
    "enable": true,
    "mode": "client",
    "server_addr": "http://server-ip:8001",
    "secret": "shared-secret-key"
  }
}
```

**架构说明（v2.x）：**
```
┌─────────────────────────────────────────────────────┐
│                   Server (:8000)                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │   API 服务   │  │   WS 服务   │  │  号池管理    │  │
│  │ /v1/chat/*  │  │    /ws      │  │  Pool Mgr   │  │
│  └─────────────┘  └──────┬──────┘  └─────────────┘  │
└──────────────────────────┼──────────────────────────┘
                           │ WebSocket
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐ ┌────▼────┐ ┌─────▼─────┐
        │  Client1  │ │ Client2 │ │  Client3  │
        │  (注册)    │ │ (注册)   │ │  (注册)   │
        └───────────┘ └─────────┘ └───────────┘
```

**Client 模式说明：**
- 通过 WebSocket 连接 Server (`/ws`) 接收任务
- 执行注册新账号任务
- 执行401账号Cookie续期任务
- 完成后自动回传账号数据到Server
- **不提供API服务**，只作为工作节点

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `LISTEN_ADDR` | 监听地址 | `:8000` |
| `DATA_DIR` | 数据目录 | `./data` |
| `PROXY` | 代理地址 | - |
| `API_KEY` | API 密钥 | - |
| `CONFIG_ID` | 默认 configId | - |

---

## API 使用

### 获取模型列表

```bash
curl http://localhost:8000/v1/models \
  -H "Authorization: Bearer sk-your-api-key"
```

### 聊天补全

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-api-key" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [
      {"role": "user", "content": "Hello!"}
    ],
    "stream": true
  }'
```

### 多模态（图片输入）

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-your-api-key" \
  -d '{
    "model": "gemini-2.5-flash",
    "messages": [
      {
        "role": "user",
        "content": [
          {"type": "text", "text": "描述这张图片"},
          {"type": "image_url", "image_url": {"url": "data:image/jpeg;base64,..."}}
        ]
      }
    ]
  }'
```

---


---

## Flow 图片/视频生成

Flow 集成了 Google VideoFX (Veo) API，支持图片和视频生成。

### 配置

```json
{
  "flow": {
    "enable": true,
    "tokens": ["your-flow-st-token"],  // labs.google/fx 登录后的 ST Cookie
    "proxy": "",
    "timeout": 120,
    "poll_interval": 3,
    "max_poll_attempts": 500
  }
}
```

### 获取 Flow Token

1. 访问 [labs.google/fx](https://labs.google/fx) 并登录
2. 打开开发者工具 → Application → Cookies
3. 复制 `__Secure-next-auth.session-token` 的值
4. 添加到配置文件的 `flow.tokens` 数组

### 使用示例

```bash
# 图片生成
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-xxx" \
  -d '{"model": "gemini-2.5-flash-image-landscape", "messages": [{"role": "user", "content": "一只可爱的猫咪"}], "stream": true}'

# 视频生成
curl http://localhost:8000/v1/chat/completions \
  -d '{"model": "veo_3_1_t2v_fast_landscape", "messages": [{"role": "user", "content": "猫咪在草地上追蝴蝶"}], "stream": true}'
```

---

## 🔧 常见问题与解决方案

### 注册相关

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `无法获取验证码邮件` | 临时邮箱服务不稳定或邮件延迟 | 多次重试，检查代理是否正常 |
| `panic: nil pointer` | 浏览器启动失败或页面未加载 | 检查 Chrome 是否安装，确保有足够内存 |
| `页面显示错误: 电话` | Google 要求手机验证 | 更换代理 IP 或等待一段时间 |
| `找不到提交按钮` | 页面结构变化或加载超时 | 升级到最新版本，检查网络 |

### API 相关

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `401 Unauthorized` | API Key 无效或未配置 | 检查 `api_keys` 配置 |
| `429 Too Many Requests` | 账号触发速率限制 | 增加账号池数量，调整 `use_cooldown_sec` |
| `503 Service Unavailable` | 无可用账号 | 等待账号刷新或增加注册 |
| `空响应` | Google 返回空内容 | 重试请求，检查 prompt 是否触发过滤 |

### WebSocket 相关

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `客户端频繁断开` | 心跳超时或网络不稳定 | 检查网络，确保 Server 和 Client 时间同步 |
| `上传注册结果失败` | Server 端口或路径错误 | 确保 `server_addr` 指向正确地址 |

### Flow 相关

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `Flow 服务未启用` | 未配置或 Token 为空 | 检查 `flow.enable` 和 `flow.tokens` |
| `Token 认证失败` | ST Token 过期 | 重新获取 Token |
| `视频生成超时` | 生成时间过长 | 增加 `max_poll_attempts` |

### Docker 相关

| 错误 | 原因 | 解决方案 |
|------|------|----------|
| `无法启动浏览器` | Docker 容器缺少 Chrome | 使用包含 Chrome 的镜像或挂载主机浏览器 |
| `权限被拒绝` | 数据目录权限问题 | `chown -R 1000:1000 ./data` |

---

## 📡 API 端点一览

| 端点 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 服务状态和信息 |
| `/health` | GET | 健康检查 |
| `/ws` | WS | WebSocket 端点 (Server 模式) |
| `/v1/models` | GET | OpenAI 格式模型列表 |
| `/v1/chat/completions` | POST | OpenAI 格式聊天补全 |
| `/v1/messages` | POST | Claude 格式消息 |
| `/v1beta/models` | GET | Gemini 格式模型列表 |
| `/v1beta/models/:model` | GET | Gemini 格式模型详情 |
| `/v1beta/models/:model:generateContent` | POST | Gemini 格式生成内容 |
| `/admin/status` | GET | 管理状态 |
| `/admin/register` | POST | 触发注册 |
| `/admin/refresh` | POST | 刷新账号池 |

---

## 🛠️ 开发

### 本地运行

```bash
# 安装依赖
go mod download

# 运行
go run .

# 调试模式
go run . -d
```

### 构建

```bash
# 构建二进制
CGO_ENABLED=0 go build -ldflags="-s -w" -o business2api .

# 构建 Docker 镜像
docker build -t business2api .

# 多平台构建
GOOS=linux GOARCH=amd64 go build -o business2api-linux-amd64 .
GOOS=darwin GOARCH=arm64 go build -o business2api-darwin-arm64 .
```

### 项目结构

```
.
├── main.go              # 主程序入口
├── utils.go             # 工具函数
├── config/              # 配置文件
├── src/
│   ├── api/             # API 处理
│   ├── flow/            # Flow 图片/视频生成
│   ├── logger/          # 日志
│   ├── pool/            # 账号池管理
│   └── register/        # 浏览器注册
├── docker/              # Docker 相关
└── .github/             # GitHub Actions
```

---

## 📄 License

MIT License
