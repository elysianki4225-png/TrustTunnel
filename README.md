# TrustTunnel 傻瓜式一键部署脚本 & 响应式 Web 智控伪装面板

基于官方开源协议 [**TrustTunnel/TrustTunnel**](https://github.com/TrustTunnel/TrustTunnel) 打造的高自由度、小白零门槛一键部署代码库。

> **核心设计理念**：
> 1. **脚本极简，部署后全程网页图形化操作**：无需在终端背诵复杂的命令或手写 TOML，一键启动响应式 Web 配置面板（完美适配电脑 PC 与手机触屏），甚至**不需要再次登录 SSH 服务器**即可完成证书签发、伪装站切换、抗 DPI 混淆调优与扫码连接。
> 2. **开箱即带最强抗 DPI 混淆默认配置**：默认启用 HTTP/3 (QUIC 0-RTT) + Chrome/Firefox HTTP/2 流控窗口指纹模拟 + 非隧道主动探测返回 `404 Not Found` + TLS 握手随机数密钥校验 (`client_random_auth_key` / `client_random_prefix`)。
> 3. **原生集成 `issue_cert.sh` (`IP.nip.io`) 与自有证书**：哪怕没有买域名，也能直接用 VPS 公网 IP (`${VPS_IP}.nip.io`) 申请 Let's Encrypt ECC 证书，或一键生成内嵌式 ECC 自签证书、上传自有证书。
> 4. **一键切换 Nginx / Caddy / 原生反代 + 4 套单页开源 HTML 伪装项目**：内置 **纯前端俄罗斯方块**、**全功能科学计算器**、**个人待办事项番茄钟**、**极简开发者个人简历** 4 套完整可交互的单页应用，普通浏览器或探测爬虫访问时展示真实 Web 应用，VPN 客户端流量则通过加密多路复用隧道高速转发。

---

## 🚀 一、极速傻瓜式一键部署命令（直接复制粘贴即可）

> **本代码库地址**：[https://github.com/elysianki4225-png/TrustTunnel](https://github.com/elysianki4225-png/TrustTunnel)

### 方式 1：单行命令全自动部署（推荐小白 · 自动拉取仓库并启动 Web 配置面板）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/elysianki4225-png/TrustTunnel/main/install.sh)
```

或者无交互直接一键部署并启动 Web 图形化配置界面：

```bash
curl -fsSL https://raw.githubusercontent.com/elysianki4225-png/TrustTunnel/main/install.sh | bash -s -- --web
```

### 方式 2：Git Clone 克隆本仓库一键部署

```bash
git clone https://github.com/elysianki4225-png/TrustTunnel.git && cd TrustTunnel && chmod +x install.sh issue_cert.sh tt-panel && bash install.sh --web
```

### 方式 3：单独一键运行 `issue_cert.sh` 申请 `IP.nip.io` 证书

```bash
curl -fsSL https://raw.githubusercontent.com/elysianki4225-png/TrustTunnel/main/issue_cert.sh | bash -s -- --auto-ip --mode letsencrypt
```

---

### 📋 交互式安装菜单说明

直接运行 `bash install.sh` 时将显示如下傻瓜式菜单：

```text
======================================================================
   TrustTunnel 傻瓜式一键部署脚本 (带响应式 Web 面板 & 4套单页伪装站)
======================================================================
  1) 🚀 一键全自动部署 (安装核心 + 启动 Web 配置面板 + 默认开启最佳混淆与伪装站) [强烈推荐]
  2) 🖥️ 仅部署并启动 Web 配置图形化界面 (证书与节点全部在网页端傻瓜式操作)
  3) 🔒 单独运行 issue_cert.sh 申请 Let's Encrypt (IP.nip.io) 证书
  4) 🎭 安装轻量 Nginx / Caddy 反代并启动 Web 配置面板
  0) 退出脚本
```

部署完成后终端会直接输出：
- **Web 可视化配置面板**：`http://<您的VPS_IP>:8880`
- **当前伪装网站在线预览**：`http://<您的VPS_IP>:8880/camouflage/active`
- **终端快捷管理命令**：输入 `tt-panel` 即可随时查看状态或重启面板

---

## 🔒 二、证书申请脚本 (`issue_cert.sh`) 说明

本仓库完整内置并增强了 `issue_cert.sh`（支持 `nip.io` 免域名申请 Let's Encrypt ECC 证书、自有域名证书、以及免 80 端口的 ECC 自签名证书）。

### 1. 直接在 Web 面板一键点选申请（无需敲命令）
打开 Web 面板 -> **【🚀 三步傻瓜式向导】** 或 **【🔒 证书中心 (nip.io)】**，填入您的 VPS IP，点击 **【⚡ 一键申请 / 生成并安装证书】** 即可自动完成安装与 `hosts.toml` 绑定。

### 2. 或在终端单独执行 `issue_cert.sh`
```bash
# 使用脚本内配置的 VPS_IP (自动拼接 ${VPS_IP}.nip.io 申请 Let's Encrypt ECC 证书)
bash issue_cert.sh

# 自动检测当前服务器公网 IP 并申请 Let's Encrypt 证书
bash issue_cert.sh --auto-ip --mode letsencrypt

# 指定 IP 申请证书
bash issue_cert.sh --ip 156.246.95.165 --mode letsencrypt

# 免 80 端口秒级生成 Prime256v1 ECC 自签名证书（证书自动内嵌至 tt:// 客户端配置中）
bash issue_cert.sh --auto-ip --mode selfsigned
```

证书默认标准输出位置：
- 私钥路径：`/etc/ssl/ip-certs/ip.key`
- 证书路径：`/etc/ssl/ip-certs/ip.crt`

---

## 🎭 三、反向代理 (Nginx / Caddy / 原生反代) 与 4 套单页伪装站

根据 [TrustTunnel 官方协议规范 (`PROTOCOL.md` & `CONFIGURATION.md`)](https://github.com/TrustTunnel/TrustTunnel)，面板提供了 **3 种反代伪装架构** 与 **4 套真实可玩的单页 HTML 开源项目**，均可在网页上 **1 秒傻瓜式切换**：

### 1. 三种反向代理与伪装共存方案

| 方案 | 架构原理 | 优势与适用场景 |
| :--- | :--- | :--- |
| **方案 A：TrustTunnel 原生反代 + 轻量源站（默认推荐）** | TrustTunnel 监听 `:443` (同时处理 TCP 与 UDP QUIC)，在 `vpn.toml` 中开启 `[reverse_proxy]` (`server_address = "127.0.0.1:8080"`, `path_mask = "/"`)。VPN 客户端 `CONNECT` 请求直接进入隧道；任何普通浏览器访问 `GET /...` 自动反代至本地 `127.0.0.1:8080` 的静态伪装服务（内置/Nginx/Caddy）。 | **零性能损耗**，100% 完整保留 HTTP/3 (QUIC) 与 TLS 握手 `ClientRandom` 密钥鉴权。 |
| **方案 B：前置 Nginx Stream (`ssl_preread`) 四层分流** | 前置轻量级 Nginx 监听 `:443`，利用 `ngx_stream_ssl_preread_module` 识别 SNI 将 VPN 流量无损四层转发给 TrustTunnel，其余域名/默认访问返回静态 HTML 伪装网。 | 适合服务器上已有 Nginx 多站点共存的场景（自动生成 `nginx-camouflage.conf`）。 |
| **方案 C：轻量 Caddy 静态伪装源站** | 使用极简 Caddy 托管静态 HTML 单页应用，自动剔除 Server 特征头并配合 TrustTunnel 反代。 | 配置极简，自动生成 `Caddyfile`。 |

### 2. 内置 4 套单页开源 HTML 伪装应用（支持在线预览与自定义 HTML）
- 🎮 **纯前端俄罗斯方块 (`camouflage/tetris/index.html`)**：完整 HTML5 Canvas 霓虹俄罗斯方块，支持电脑方向键与手机触屏按钮、等级加速、最高分记录。
- 🧮 **全功能科学计算器 (`camouflage/calculator/index.html`)**：支持三角函数、对数、幂运算、角度/弧度切换与历史记录纸带。
- ✅ **个人待办事项列表与番茄钟 (`camouflage/todo/index.html`)**：GTD 任务分类管理 + 25 分钟番茄工作法专注计时器。
- 👨‍💻 **开发者个人简历 (`camouflage/resume/index.html`)**：极简暗黑风格全栈工程师个人作品集与项目经历主页。
- ✏️ **自定义单页 HTML**：支持在 Web 面板直接粘贴任意自定义 HTML 代码实时生效。

---

## 🛡️ 四、Web 面板涵盖的 TrustTunnel 全协议特性一览

Web 界面既提供 **【🚀 三步傻瓜式向导】**，也在 **【🛡️ 协议全特性与抗 DPI】** 中开放了 `TrustTunnel` 100% 的底层参数：

1. **抗封锁混淆预设一键切换**：
   - 🛡️ **旗舰抗 DPI 深度混淆模式（默认）**：启用客户端 `anti_dpi = true`、`upstream_protocol = "http3"`、`non_connect_auth_failure_status_code = 404`（防止主动探测暴露 `407 Proxy Authentication Required`）、Chrome HTTP/2 窗口指纹 (`initial_stream_window_size = 131072`, `max_concurrent_streams = 1000`)、QUIC 0-RTT Early Data。
   - ⚡ **极速 QUIC / HTTP3 流媒体模式**：32MB 大连接窗口调优，适合高码率流媒体与游戏。
   - 🌐 **高兼容标准 HTTP/2 模式**：适合对 UDP 限速的网络环境。
2. **TLS 握手随机数过滤规则 (`rules.toml`)**：
   - 支持 **SNI 派生握手机密密钥 (`client_random_auth_key`)**：利用 `AES-128-ECB(SHA256(SNI), HKDF-SHA256(key, salt))` 在 TLS 握手阶段完成零特征身份校验。
   - 支持 **位掩码前缀 (`client_random_prefix`)**：如 `a0b0c0d0/f0f0f0f0`。
   - 支持 **CIDR IP 段黑白名单 (`cidr`, `action = "allow" | "deny"`)**。
3. **多用户管理与连接数限制 (`credentials.toml`)**：
   - 支持无限添加客户端账号，独立设置 `max_http2_conns` 与 `max_http3_conns` 限制同时在线设备数。
4. **一键客户端配置导出 (`tt://?` DeepLink v2 + 二维码 + TOML + HTTPS 订阅)**：
   - 严格遵循官方 `DEEP_LINK.md` v2 二进制 TLV 规范生成 `tt://?...` 链接与高清矢量二维码。
   - 内置 `tt://?` 链接在线解码器，随时校验内部 TLV 参数。
   - 一键下载 `trusttunnel_client.toml` 供电脑端 CLI / GUI 客户端使用。
5. **链式代理出站 (`[forward_protocol]`)、ICMP 隧道 (`[icmp]`)、SIGHUP 热重载与 Prometheus 监控 (`[metrics]`)**：
   - 支持 Direct 直连或转发至上游 SOCKS5（如 Cloudflare WARP）。
   - 支持一键发送 `SIGHUP` 热重载 `hosts.toml` 与 `[subscription]`，无需断开现有 VPN 连接。

---

## 📂 五、代码库目录结构

```text
TrustTunnel/
├── install.sh                   # 傻瓜式一键部署主脚本 (支持交互菜单 & 命令行参数)
├── issue_cert.sh                # Let's Encrypt nip.io / 自有域名 / 自签 ECC 证书一键申请脚本
├── tt-panel                     # 终端快捷管理命令
├── panel/
│   ├── server.py                # 零外部依赖 Web 管理面板后端 + 伪装站点服务器 + DeepLink TLV 编码器
│   └── static/                  # 电脑/手机自适应响应式前端界面 (含本地离线二维码引擎 qrcode.js)
├── camouflage/                  # 4 套完整单页面开源 HTML 伪装项目
│   ├── tetris/index.html        # 纯前端俄罗斯方块游戏
│   ├── calculator/index.html    # 全功能科学计算器
│   ├── todo/index.html          # 个人待办事项列表与番茄钟
│   └── resume/index.html        # 极简开发者个人简历
└── templates/                   # Nginx / Caddy 反代与 Systemd 服务模板
```
