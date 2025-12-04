# Business2API

OpenAI 兼容的 Gemini Business API 代理服务，支持账号池管理和自动注册。

## 功能特性

- ✅ **OpenAI 兼容 API** - 支持 `/v1/chat/completions`、`/v1/models` 等标准接口
- ✅ **账号池管理** - 自动轮询、刷新、维护多个 Gemini 账号
- ✅ **流式响应** - 支持 SSE 流式输出
- ✅ **多模态支持** - 支持图片、视频输入和生成
- ✅ **自动注册** - 通过 Puppeteer 脚本自动注册新账号
- ✅ **代理支持** - 支持 HTTP/SOCKS 代理

## 支持的模型

- `gemini-2.5-flash` / `gemini-2.5-flash-image` / `gemini-2.5-flash-video`  /  `gemini-2.5-flash-search` 
- `gemini-2.5-pro` / `gemini-2.5-pro-image` / `gemini-2.5-pro-video`  /  `gemini-2.5-pro-search` 
- `gemini-3-pro-preview` / `gemini-3-pro-preview-image` / `gemini-3-pro-preview-video`  /  `gemini-3-pro-preview-search` 
- `gemini-3-pro` / `gemini-3-pro-image` / `gemini-3-pro-video` /  `gemini-3-pro-search` 

---

## 快速开始

### 方式一：Docker 部署（推荐）

#### 1. 使用 Docker Compose

```bash
# 克隆项目
git clone https://github.com/XxxXTeam/business2api.git
cd business2api

# 复制配置文件
cp config.json.example config.json

# 编辑配置
vim config.json

# 启动服务
docker-compose up -d
```

#### 2. 使用预构建镜像

```bash
# 拉取镜像
docker pull ghcr.io/xxxteam/business2api:latest

# 运行容器
docker run -d \
  --name business2api \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.json:/app/config.json:ro \
  -e LISTEN_ADDR=:8000 \
  ghcr.io/xxxteam/business2api:latest
```

#### 3. 手动构建镜像

```bash
# 构建镜像
docker build -t business2api .

# 运行
docker run -d \
  --name business2api \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config.json:/app/config.json:ro \
  business2api
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
  "pool": {
    "target_count": 50,                // 目标账号数量
    "min_count": 10,                   // 最小账号数，低于此值触发注册
    "check_interval_minutes": 30,      // 检查间隔（分钟）
    "register_threads": 1,             // 注册线程数
    "register_headless": true,         // 无头模式注册
    "register_script": "./main.js",    // 注册脚本路径
    "refresh_on_startup": true         // 启动时刷新账号
  },
  "proxy": ""                          // 代理地址（可选）
}
```

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

## 账号注册脚本

注册脚本使用 Puppeteer 自动化注册 Gemini Business 账号。

### 安装依赖

```bash
npm install
```

### 运行注册

```bash
# 单次注册
node main.js --headless

# 持续注册模式
node main.js --headless --continuous

# 多线程注册
node main.js --headless --threads 3

# 指定数据目录
node main.js --headless --data-dir /path/to/data
```

### 命令行参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--headless` | `-h` | 无头模式运行 |
| `--threads <n>` | `-t` | 线程数 |
| `--continuous` | `-c` | 持续运行模式 |
| `--data-dir <dir>` | `-d` | 数据保存目录 |

---

## 开发

### 本地运行

```bash
# Go 服务
go run .

# 注册脚本
npm install
node main.js
```

### 构建

```bash
# 构建 Go 二进制
CGO_ENABLED=0 go build -ldflags="-s -w" -o business2api .

# 构建 Docker 镜像
docker build -t business2api .
```

---

## License

MIT License
