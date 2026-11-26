<div align="center">

# Octopus Relay

**面向个人的轻量级自建中转服务（Self-Hosted Relay for [Octopus](https://github.com/AIDotNet/Octopus)）**

单文件 NativeAOT · 零外部数据库（纯 JSON 原子持久化）· 内置极简控制台 · 端到端加密零知识转发

[![CI](https://img.shields.io/github/actions/workflow/status/AIDotNet/Octopus-Relay/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/AIDotNet/Octopus-Relay/actions/workflows/ci.yml)
[![.NET 10](https://img.shields.io/badge/.NET-10-512BD4?style=flat-square)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 核心特性

- **极简轻量**：基于 .NET 10 NativeAOT 编译，**零第三方运行时依赖、无需 PostgreSQL、无需注册 GitHub/Google OAuth、无需配置发信域名**，Docker 镜像约 26 MB，常驻内存低于 30 MB。
- **纯 JSON 原子持久化**：所有状态仅存于单一目录（`/data/state.json` + 自动生成的 `/data/secret.key`），采用临时文件 + `fsync` + 原子替换写入；容器重启或升级后，所有电脑和手机**无感自动重连，无需重新登录**。
- **端到端零知识中转**：完整兼容 Octopus SIGMA 安全通道与设备配对机制，中转服务只搬运密文帧，无法解密终端输出、对话内容或文件。
- **双模式接入**：
  1. **管理员密码 + 浏览器设备码**：内置零外部 CDN 依赖的中英文响应式管理控制台（`/login`、`/device`、`/account`），**零改动兼容所有已发布的 Octopus 桌面端与手机端**。
  2. **Access Key 免浏览器一键接入**：支持通过访问密钥或一键配置链接（`octopus://relay?v=1&url=...&key=...`）直接在桌面端与手机端完成设备绑定，同时保留单设备独立令牌与随时踢出能力。
- **完整协议支持**：支持主机实时特性上报（含 `password-access` 访问密码状态同步）、设备在线列表、单设备吊销立即踢线、隧道配额与空闲超时控制。

---

## 快速部署

> **HTTPS 提示**：Octopus 手机端（iOS / Android）以及浏览器安全 Cookie 要求外网使用 **HTTPS / WSS**。推荐直接用下方的 Caddy 一键编排，或挂在已有 Nginx / 1Panel / Cloudflare Tunnel / Tailscale Serve 后面。

### 方式一：Docker Compose + Caddy 全自动 HTTPS（推荐，新 VPS 1 分钟上线）

```bash
git clone https://github.com/AIDotNet/Octopus-Relay.git
cd Octopus-Relay
cp .env.example .env
```

编辑 `.env`，至少填入域名与密码：

```env
RELAY_DOMAIN=relay.example.com
RELAY_PASSWORD=your-strong-password-here
```

启动服务（Caddy 自动申请并续期 Let's Encrypt 证书）：

```bash
docker compose -f compose.caddy.yaml up -d
```

打开 `https://relay.example.com/account` 登录控制台，可随时查看在线设备、踢出设备或生成免浏览器接入的 **Access Key / 一键配置链接**。

### 方式二：单容器部署（配合已有 Nginx / 1Panel / Cloudflare Tunnel / Tailscale）

```bash
docker run -d --name octopus-relay --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v octopus-relay-data:/data \
  -e RELAY_PASSWORD="your-strong-password-here" \
  -e RELAY_TRUST_PROXY="true" \
  ghcr.io/aidotnet/octopus-relay:latest
```

> 若暂不设置 `RELAY_PASSWORD` 和 `RELAY_ACCESS_KEY`，首次启动会在日志中打印一次性初始化链接（`docker logs octopus-relay`），可在浏览器 `/setup` 页面完成初始化。

### 方式三：单文件二进制运行（VPS / NAS / 树莓派 / systemd）

从 [Releases](https://github.com/AIDotNet/Octopus-Relay/releases) 下载对应平台二进制（或本地构建）：

```bash
./octopus-relay \
  --data ./data \
  --listen http://127.0.0.1:8080 \
  --public-url https://relay.example.com \
  --password "your-strong-password-here" \
  --trust-proxy
```

无域名场景也可直接用 **Tailscale Serve** 一行获得受信任 HTTPS 证书：

```bash
tailscale serve --bg http://127.0.0.1:8080
```

---

## 反向代理配置示例（Nginx）

配置反代时务必放行 **WebSocket 升级头**、调大读超时并关闭缓冲（避免终端按键延迟）：

```nginx
server {
    listen 443 ssl http2;
    server_name relay.example.com;

    ssl_certificate     /path/to/fullchain.pem;
    ssl_certificate_key /path/to/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

---

## 在 Octopus 客户端中连接

### 1. 使用浏览器密码登录（支持所有版本 Octopus）
- **桌面端**：点击顶部账号按钮（或进入 `设置 → 远程访问`）→ 展开 **自定义服务** → 填入 `https://relay.example.com` → 点击登录，在浏览器中输入管理员密码并确认 8 位设备码。
- **手机端**：欢迎页选择 **自定义服务** → 填入 `https://relay.example.com` → 点击登录并在浏览器确认设备码。

### 2. 使用 Access Key 免浏览器一键接入
1. 登录 `https://relay.example.com/account`（或通过环境变量 `RELAY_ACCESS_KEY` 预设），生成访问密钥并复制 **一键配置链接**（`octopus://relay?v=1&url=...&key=...`）。
2. 在 Octopus 桌面端或手机端的自定义服务输入框中直接**粘贴一键配置链接**（或分别填入服务地址与访问密钥），点击登录即可直接完成绑定，无需打开浏览器。

---

## 环境变量与命令行参数

所有参数同时支持环境变量与 CLI 参数（CLI 参数优先级更高）：

| 环境变量 | CLI 参数 | 默认值 | 说明 |
|---|---|---|---|
| `RELAY_DATA_DIR` | `--data` | `./data`（容器 `/data`） | 存放 `state.json` 与 `secret.key` 的目录 |
| `RELAY_LISTEN` | `--listen` | `http://0.0.0.0:8080` | Kestrel 监听地址 |
| `RELAY_PUBLIC_URL` | `--public-url` | 自动从请求推导 | 对外访问根地址（如 `https://relay.example.com`） |
| `RELAY_PASSWORD` | `--password` | 空 | 管理员密码（≥ 8 位），用于 Web 控制台与设备码登录 |
| `RELAY_ACCESS_KEY` | `--access-key` | 空 | 访问密钥（≥ 16 位），用于客户端免浏览器直连 |
| `RELAY_SECRET` | `--secret` | 自动生成并持久化 | 签名主密钥（base64，≥ 32 字节） |
| `RELAY_NAME` | `--name` | `Octopus Relay` | 服务显示名称 |
| `RELAY_OWNER_NAME` | `--owner` | `Owner` | 机主显示名称 |
| `RELAY_TRUST_PROXY` | `--trust-proxy` | `false` | 信任反代头（`CF-Connecting-IP` / `X-Forwarded-*`） |
| `RELAY_MAX_DEVICES` | — | `32` | 最大已授权设备数 |
| `RELAY_MAX_HOSTS` | — | `32` | 同时在线主机上限 |
| `RELAY_MAX_TUNNELS` | — | `128` | 同时活跃隧道总数上限 |
| `RELAY_MAX_TUNNELS_PER_HOST` | — | `32` | 单台主机最大并发隧道数 |
| `RELAY_MONTHLY_BYTES` | — | `0`（不限） | 每月流量上限（字节） |
| `RELAY_IDLE_SECONDS` | — | `0`（不关闭） | 空闲隧道自动关闭秒数 |
| `RELAY_TLS_CERT` / `RELAY_TLS_KEY` | `--tls-cert` / `--tls-key` | 空 | 直出 HTTPS / QUIC 时的 PEM 证书与私钥文件路径 |
| `RELAY_STUN_PORT` | `--stun-port` | 空（关闭） | 启用内置 RFC 5389 UDP STUN 服务端口（推荐 `3478`），用于公网 WebRTC P2P 打洞 |
| `RELAY_STUN_HOST` | `--stun-host` | 自动取公共域名 | `/v1/info` 对外通告的 STUN 主机名或 IP |
| `RELAY_STUN_SERVERS` | `--stun-servers` | 空 | 额外逗号分隔的外部 STUN 地址（如 `stun:stun.example.com:3478`） |
| `RELAY_QUIC_PORT` | `--quic-port` | 空（关闭） | 启用 QUIC UDP 隧道端口（推荐 `8443`，需系统具备 `libmsquic`），支持 QUIC↔WS 混合桥接 |
| `RELAY_QUIC_HOST` | `--quic-host` | 自动取公共域名 | `/v1/info` 对外通告的 QUIC 主机名或 IP |

---

## 开发与构建

```bash
# 运行全部单元测试与集成测试
dotnet test OctopusRelay.slnx

# 本地运行（内存模式，快速试跑）
dotnet run --project src/Octopus.Relay -- --memory --password my-dev-password

# 编译单文件 NativeAOT 二进制
dotnet publish src/Octopus.Relay -c Release -p:PublishAot=true -o dist
```

详细架构与协议规范见 [`design/01-架构与协议.md`](design/01-架构与协议.md)。
