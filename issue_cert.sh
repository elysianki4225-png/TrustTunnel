#!/bin/bash
set -e

# ==============================================================================
# TrustTunnel 一键 SSL/TLS 证书申请与安装脚本 (支持 nip.io / sslip.io / 自定义域名 / 自签名兜底)
# 默认完全兼容 nip.io Let's Encrypt ECC 证书逻辑，并支持命令行传参与 Web 面板直接调用
# ==============================================================================

# ==================== 默认配置项 (可直接修改或通过参数覆盖) ====================
VPS_IP="${VPS_IP:-156.246.95.165}"
NIP_PROVIDER="${NIP_PROVIDER:-nip.io}"          # 可选: nip.io 或 sslip.io
DOMAIN="${DOMAIN:-}"
SSL_EMAIL="${SSL_EMAIL:-}"
CERT_DIR="${CERT_DIR:-/etc/ssl/ip-certs}"
CERT_MODE="${CERT_MODE:-letsencrypt}"           # letsencrypt | zerossl | selfsigned
AUTO_DETECT_IP="${AUTO_DETECT_IP:-false}"

# ==================== 解析命令行参数 ====================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip)
      VPS_IP="$2"
      shift 2
      ;;
    --auto-ip)
      AUTO_DETECT_IP="true"
      shift
      ;;
    --domain)
      DOMAIN="$2"
      shift 2
      ;;
    --provider)
      NIP_PROVIDER="$2"
      shift 2
      ;;
    --email)
      SSL_EMAIL="$2"
      shift 2
      ;;
    --cert-dir)
      CERT_DIR="$2"
      shift 2
      ;;
    --mode)
      CERT_MODE="$2"
      shift 2
      ;;
    -h|--help)
      echo "用法: bash issue_cert.sh [选项]"
      echo "  --ip <IP>            指定 VPS 公网 IP (默认: $VPS_IP)"
      echo "  --auto-ip            自动检测当前服务器公网 IPv4"
      echo "  --domain <DOMAIN>    指定自定义域名 (默认自动使用 \${VPS_IP}.nip.io)"
      echo "  --provider <后缀>    IP 泛解析服务商: nip.io 或 sslip.io (默认: nip.io)"
      echo "  --cert-dir <目录>    证书输出目录 (默认: /etc/ssl/ip-certs)"
      echo "  --mode <模式>        letsencrypt (默认) | zerossl | selfsigned (ECC自签)"
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

if [[ "$AUTO_DETECT_IP" == "true" ]] || [[ "$VPS_IP" == "AUTO" ]]; then
  DETECTED_IP=$(curl -fsSL4 --max-time 6 https://api.ipify.org 2>/dev/null || curl -fsSL4 --max-time 6 https://ifconfig.me 2>/dev/null || echo "")
  if [[ -n "$DETECTED_IP" ]]; then
    VPS_IP="$DETECTED_IP"
  fi
fi

if [[ -z "$DOMAIN" ]]; then
  DOMAIN="${VPS_IP}.${NIP_PROVIDER}"
fi

if [[ -z "$SSL_EMAIL" ]]; then
  SSL_EMAIL="ssl_admin_${VPS_IP//./_}@gmail.com"
fi

mkdir -p "$CERT_DIR"

# ==================== 模式分支: ECC 自签名极速证书 (无需 80 端口) ====================
if [[ "$CERT_MODE" == "selfsigned" ]]; then
  echo "=== [ECC 自签模式] 正在为 $DOMAIN (IP: $VPS_IP) 生成 Prime256v1 ECC 证书 ==="
  SAN_EXT="DNS:${DOMAIN}"
  if [[ "$VPS_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN_EXT="DNS:${DOMAIN},IP:${VPS_IP}"
  fi
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -days 3650 -nodes \
    -keyout "$CERT_DIR/ip.key" \
    -out "$CERT_DIR/ip.crt" \
    -subj "/CN=${DOMAIN}" \
    -addext "subjectAltName=${SAN_EXT}"
  chmod 600 "$CERT_DIR/ip.key"
  chmod 644 "$CERT_DIR/ip.crt"
  echo "=================================================="
  echo " ECC 自签名证书生成与安装完成！"
  echo " 证书域名: $DOMAIN"
  echo " 私钥路径: $CERT_DIR/ip.key"
  echo " 证书路径: $CERT_DIR/ip.crt"
  echo "=================================================="
  exit 0
fi

# ==================== 标准 Let's Encrypt / acme.sh 流程 ====================
echo "=== 1. 安装基础依赖 (curl, socat, cron, openssl) ==="
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y curl socat cron openssl
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y curl socat cronie openssl
elif command -v yum >/dev/null 2>&1; then
  yum install -y curl socat cronie openssl
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache curl socat openssl
fi

echo "=== 2. 安装/更新 acme.sh 客户端 ==="
if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
  curl https://get.acme.sh | sh -s email="$SSL_EMAIL"
fi
source ~/.bashrc 2>/dev/null || true
export PATH="$HOME/.acme.sh:$PATH"

echo "=== 3. 临时释放 80 端口用于验证 ==="
systemctl stop nginx 2>/dev/null || true
systemctl stop caddy 2>/dev/null || true

CA_SERVER="letsencrypt"
if [[ "$CERT_MODE" == "zerossl" ]]; then
  CA_SERVER="zerossl"
fi

echo "=== 4. 申请 Let's Encrypt ECC 证书 ($DOMAIN) ==="
~/.acme.sh/acme.sh --set-default-ca --server "$CA_SERVER"
~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone --server "$CA_SERVER" --keylength ec-256 --force

echo "=== 5. 安装证书到系统标准目录 ($CERT_DIR) ==="
mkdir -p "$CERT_DIR"
~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
  --key-file       "$CERT_DIR/ip.key"  \
  --fullchain-file "$CERT_DIR/ip.crt"  \
  --reloadcmd      "systemctl reload trusttunnel 2>/dev/null || kill -HUP \$(pidof trusttunnel_endpoint) 2>/dev/null || true"

echo "=== 6. 恢复 Web 服务与热重载 TrustTunnel ==="
systemctl start nginx 2>/dev/null || true
systemctl start caddy 2>/dev/null || true
systemctl reload trusttunnel 2>/dev/null || kill -HUP $(pidof trusttunnel_endpoint) 2>/dev/null || true

echo "=================================================="
echo " 证书申请与安装完成！"
echo " 证书域名: $DOMAIN"
echo " 私钥路径: $CERT_DIR/ip.key"
echo " 证书路径: $CERT_DIR/ip.crt"
echo " 证书到期检查命令: ~/.acme.sh/acme.sh --list"
echo "=================================================="
