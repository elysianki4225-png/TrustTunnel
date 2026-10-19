#!/bin/bash
set -e

# ==============================================================================
# TrustTunnel 傻瓜式全功能一键部署脚本 (含响应式 Web 智控面板 + 抗DPI混淆 + 静态伪装站)
# 官方核心协议仓库: https://github.com/TrustTunnel/TrustTunnel
# 支持系统: Ubuntu / Debian / CentOS / Rocky / AlmaLinux / Alpine / macOS
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO_URL="https://github.com/elysianki4225-png/TrustTunnel.git"
PANEL_PORT="${PANEL_PORT:-8880}"
CAMOUFLAGE_PORT="${CAMOUFLAGE_PORT:-8080}"
INSTALL_DIR="${INSTALL_DIR:-/opt/trusttunnel-panel}"
TT_BIN_DIR="${TT_BIN_DIR:-/opt/trusttunnel}"
CERT_DIR="${CERT_DIR:-/etc/ssl/ip-certs}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || pwd)"

MODE=""
AUTO_CERT="selfsigned"
PROXY_ENGINE="builtin"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --web|--quick)
      MODE="1"
      shift
      ;;
    --panel-only)
      MODE="2"
      shift
      ;;
    --port)
      PANEL_PORT="$2"
      shift 2
      ;;
    --cam-port)
      CAMOUFLAGE_PORT="$2"
      shift 2
      ;;
    --cert)
      AUTO_CERT="$2"
      shift 2
      ;;
    --proxy)
      PROXY_ENGINE="$2"
      shift 2
      ;;
    -h|--help)
      echo "用法: bash install.sh [选项]"
      echo "  --web                一键部署 TrustTunnel + Web 可视化配置界面 (推荐)"
      echo "  --panel-only         仅启动 Web 可视化配置界面，所有节点与证书在网页内操作"
      echo "  --port <端口>        Web 面板监听端口 (默认: 8880)"
      echo "  --cam-port <端口>    本地静态伪装网站端口 (默认: 8080)"
      echo "  --cert <模式>        letsencrypt (nip.io) | selfsigned | skip"
      echo "  --proxy <引擎>       builtin (默认) | nginx | caddy"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

detect_public_ip() {
  local ip=""
  ip=$(curl -fsSL4 --max-time 5 https://api.ipify.org 2>/dev/null || curl -fsSL4 --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
  echo "$ip"
}

install_base_deps() {
  echo -e "${CYAN}=== [1/5] 正在检查并安装基础依赖 (curl, git, socat, openssl, python3) ===${NC}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl git socat openssl python3 tar >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl git socat openssl python3 tar >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl git socat openssl python3 tar >/dev/null 2>&1 || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache curl git socat openssl python3 tar bash >/dev/null 2>&1 || true
  fi
}

install_trusttunnel_core() {
  echo -e "${CYAN}=== [2/5] 正在安装 TrustTunnel 官方服务端核心 (${TT_BIN_DIR}) ===${NC}"
  if curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s - -o "$TT_BIN_DIR" -a y; then
    echo -e "${GREEN}✔ TrustTunnel 官方核心安装成功！${NC}"
  else
    echo -e "${YELLOW}⚠ 提示：当前网络环境未能直接拉取 GitHub Release 二进制，您稍后可在 Web 面板内一键重试下载。${NC}"
  fi
}

install_optional_proxy() {
  local engine="$1"
  if [[ "$engine" == "nginx" ]]; then
    echo -e "${CYAN}=== 正在安装轻量级 Nginx 反向代理 ===${NC}"
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y nginx >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y nginx >/dev/null 2>&1 || true
    fi
  elif [[ "$engine" == "caddy" ]]; then
    echo -e "${CYAN}=== 正在安装轻量级 Caddy 反向代理 ===${NC}"
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y caddy >/dev/null 2>&1 || true
    fi
  fi
}

setup_panel_files() {
  echo -e "${CYAN}=== [3/5] 正在部署 Web 可视化配置面板与 4 套单页伪装站 ===${NC}"
  if [[ ! -f "$SCRIPT_DIR/panel/server.py" ]]; then
    echo -e "${CYAN}正在从代码库 ${REPO_URL} 拉取面板与伪装站文件...${NC}"
    rm -rf "$INSTALL_DIR"
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    SCRIPT_DIR="$INSTALL_DIR"
  fi
  if [[ "$(id -u)" -eq 0 ]]; then
    mkdir -p "$INSTALL_DIR"
    if [[ "$SCRIPT_DIR" != "$INSTALL_DIR" ]]; then
      cp -rf "$SCRIPT_DIR"/* "$INSTALL_DIR"/
    fi
    chmod +x "$INSTALL_DIR/issue_cert.sh" "$INSTALL_DIR/install.sh" "$INSTALL_DIR/tt-panel" 2>/dev/null || true
    ln -sf "$INSTALL_DIR/tt-panel" /usr/local/bin/tt-panel 2>/dev/null || true
  else
    INSTALL_DIR="$SCRIPT_DIR"
    chmod +x "$INSTALL_DIR/issue_cert.sh" "$INSTALL_DIR/install.sh" "$INSTALL_DIR/tt-panel" 2>/dev/null || true
  fi
}

setup_certificates() {
  local mode="$1"
  local vps_ip
  vps_ip=$(detect_public_ip)
  echo -e "${CYAN}=== [4/5] 正在准备 SSL/TLS 证书 (模式: ${mode}) ===${NC}"
  if [[ "$mode" == "letsencrypt" ]]; then
    bash "$INSTALL_DIR/issue_cert.sh" --ip "$vps_ip" --mode letsencrypt || \
      bash "$INSTALL_DIR/issue_cert.sh" --ip "$vps_ip" --mode selfsigned
  elif [[ "$mode" == "selfsigned" ]]; then
    bash "$INSTALL_DIR/issue_cert.sh" --ip "$vps_ip" --mode selfsigned
  else
    echo -e "${YELLOW}已跳过脚本端证书申请，请直接在 Web 界面【证书中心】图形化配置 nip.io 证书或上传自有证书。${NC}"
  fi
}

start_web_panel() {
  echo -e "${CYAN}=== [5/5] 正在启动 TrustTunnel Web 可视化智控面板 ===${NC}"
  if [[ "$(id -u)" -eq 0 ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    cat > /etc/systemd/system/trusttunnel-panel.service <<EOF
[Unit]
Description=TrustTunnel Web Configuration & Camouflage Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/env python3 ${INSTALL_DIR}/panel/server.py --host 0.0.0.0 --port ${PANEL_PORT} --camouflage-port ${CAMOUFLAGE_PORT}
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now trusttunnel-panel

    if [[ -f "${TT_BIN_DIR}/trusttunnel_endpoint" ]]; then
      cat > /etc/systemd/system/trusttunnel.service <<EOF
[Unit]
Description=TrustTunnel VPN Endpoint
After=network-online.target trusttunnel-panel.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${TT_BIN_DIR}
ExecStart=${TT_BIN_DIR}/trusttunnel_endpoint ${TT_BIN_DIR}/vpn.toml ${TT_BIN_DIR}/hosts.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
      systemctl daemon-reload
      systemctl enable --now trusttunnel 2>/dev/null || true
    fi
  else
    pkill -f "panel/server.py" 2>/dev/null || true
    nohup python3 "$INSTALL_DIR/panel/server.py" --host 0.0.0.0 --port "$PANEL_PORT" --camouflage-port "$CAMOUFLAGE_PORT" > "$INSTALL_DIR/panel.log" 2>&1 &
    sleep 1
  fi

  local pub_ip
  pub_ip=$(detect_public_ip)
  echo ""
  echo -e "${GREEN}======================================================================${NC}"
  echo -e "${GREEN} 🎉 TrustTunnel 一键部署完成！无需再操作命令行，请直接打开网页配置：${NC}"
  echo -e "${GREEN}======================================================================${NC}"
  echo -e " 🌐 Web 可视化配置面板 : ${CYAN}http://${pub_ip}:${PANEL_PORT}${NC}"
  echo -e " 🎭 当前伪装网站预览   : ${CYAN}http://${pub_ip}:${PANEL_PORT}/camouflage/active${NC}"
  echo -e " 🔒 默认证书域名       : ${YELLOW}${pub_ip}.nip.io${NC}"
  echo -e " 🛡️ 默认混淆策略       : ${GREEN}旗舰抗 DPI 混淆 (HTTP/3 QUIC + Chrome H2 + 404 防探测 + 单页伪装)${NC}"
  echo -e " 🛠️ 终端快捷管理命令   : ${CYAN}tt-panel${NC}"
  echo -e "${GREEN}======================================================================${NC}"
}

if [[ -z "$MODE" ]]; then
  echo -e "${CYAN}======================================================================${NC}"
  echo -e "${CYAN}   TrustTunnel 傻瓜式一键部署脚本 (带响应式 Web 面板 & 4套单页伪装站)${NC}"
  echo -e "${CYAN}======================================================================${NC}"
  echo "  1) 🚀 一键全自动部署 (安装核心 + 启动 Web 配置面板 + 默认开启最佳混淆与伪装站) [强烈推荐]"
  echo "  2) 🖥️ 仅部署并启动 Web 配置图形化界面 (证书与节点全部在网页端傻瓜式操作)"
  echo "  3) 🔒 单独运行 issue_cert.sh 申请 Let's Encrypt (IP.nip.io) 证书"
  echo "  4) 🎭 安装轻量 Nginx / Caddy 反代并启动 Web 配置面板"
  echo "  0) 退出脚本"
  echo -e "${CYAN}----------------------------------------------------------------------${NC}"
  read -r -p "请选择操作编号 [默认 1]: " MODE < /dev/tty || MODE="1"
  MODE="${MODE:-1}"
fi

case "$MODE" in
  1)
    install_base_deps
    install_trusttunnel_core
    setup_panel_files
    setup_certificates "$AUTO_CERT"
    start_web_panel
    ;;
  2)
    install_base_deps
    setup_panel_files
    setup_certificates "selfsigned"
    start_web_panel
    ;;
  3)
    read -r -p "请输入 VPS 公网 IP (直接回车自动检测): " INPUT_IP
    if [[ -z "$INPUT_IP" ]]; then
      bash "$SCRIPT_DIR/issue_cert.sh" --auto-ip --mode letsencrypt
    else
      bash "$SCRIPT_DIR/issue_cert.sh" --ip "$INPUT_IP" --mode letsencrypt
    fi
    ;;
  4)
    read -r -p "请选择反代引擎 [1=Nginx (默认), 2=Caddy]: " P_CHOICE
    if [[ "$P_CHOICE" == "2" ]]; then
      PROXY_ENGINE="caddy"
    else
      PROXY_ENGINE="nginx"
    fi
    install_base_deps
    install_optional_proxy "$PROXY_ENGINE"
    install_trusttunnel_core
    setup_panel_files
    setup_certificates "$AUTO_CERT"
    start_web_panel
    ;;
  *)
    echo "已退出。"
    exit 0
    ;;
esac
