#!/usr/bin/env python3
"""
TrustTunnel All-in-One Web Configuration & Camouflage Management Server
Zero third-party Python dependencies (runs on standard Python 3.9+ / 3.11+).
Provides:
  1. Responsive Web GUI & REST API for 100% of TrustTunnel Endpoint features
  2. Built-in Camouflage Static Website Server (Tetris / Calculator / Todo / Resume / Custom HTML)
  3. Nginx & Caddy Reverse Proxy Config Generator & Service Controller
  4. Let's Encrypt nip.io / Domain / Self-Signed ECC Certificate Manager (issue_cert.sh integration)
  5. Bit-exact TrustTunnel DeepLink v2 (tt://?) TLV Encoder & Decoder + Client TOML Exporter
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import http.server
import json
import mimetypes
import os
import platform
import re
import secrets
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = Path(__file__).resolve().parent / "static"
CAMOUFLAGE_DIR = BASE_DIR / "camouflage"
TEMPLATES_DIR = BASE_DIR / "templates"
DATA_DIR = BASE_DIR / "data"
STATE_FILE = DATA_DIR / "panel_state.json"

# Determine writable TrustTunnel config directory (/opt/trusttunnel if root, else ./data/trusttunnel)
DEFAULT_TT_DIR = Path("/opt/trusttunnel")


def get_tt_dir() -> Path:
    env_dir = os.environ.get("TRUSTTUNNEL_DIR")
    if env_dir:
        p = Path(env_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p
    if os.geteuid() == 0:
        DEFAULT_TT_DIR.mkdir(parents=True, exist_ok=True)
        return DEFAULT_TT_DIR
    fallback = DATA_DIR / "trusttunnel"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def get_cert_dir() -> Path:
    if os.geteuid() == 0:
        p = Path("/etc/ssl/ip-certs")
        try:
            p.mkdir(parents=True, exist_ok=True)
            return p
        except OSError:
            pass
    fallback = DATA_DIR / "certs"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


# ==============================================================================
# TrustTunnel Deep-Link v2 (tt://?) Binary TLV Encoder & Decoder (DEEP_LINK.md)
# ==============================================================================

TAG_VERSION = 0x00
TAG_HOSTNAME = 0x01
TAG_ADDRESS = 0x02
TAG_CUSTOM_SNI = 0x03
TAG_HAS_IPV6 = 0x04
TAG_USERNAME = 0x05
TAG_PASSWORD = 0x06
TAG_SKIP_VERIFICATION = 0x07
TAG_CERTIFICATE = 0x08
TAG_UPSTREAM_PROTOCOL = 0x09
TAG_ANTI_DPI = 0x0A
TAG_CLIENT_RANDOM_PREFIX = 0x0B
TAG_NAME = 0x0C
TAG_DNS_UPSTREAMS = 0x0D
TAG_SUBSCRIPTION_URL = 0x0E
TAG_CLIENT_RANDOM_AUTH_KEY = 0x0F

CURRENT_DEEPLINK_VERSION = 2
PROTOCOL_MAP = {"http2": 0x01, "http3": 0x02}
PROTOCOL_REV_MAP = {0x01: "http2", 0x02: "http3"}

_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]+-----\s*\n([\sA-Za-z0-9+/=]+?)\n-----END [A-Z0-9 ]+-----"
)


def encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint must be non-negative")
    if value <= 0x3F:
        return value.to_bytes(1, "big")
    if value <= 0x3FFF:
        return (value | 0x4000).to_bytes(2, "big")
    if value <= 0x3FFFFFFF:
        return (value | 0x80000000).to_bytes(4, "big")
    if value <= 0x3FFFFFFFFFFFFFFF:
        return (value | 0xC000000000000000).to_bytes(8, "big")
    raise ValueError("varint overflow")


def decode_varint(data: bytes, offset: int) -> Tuple[int, int]:
    if offset >= len(data):
        raise ValueError("unexpected end of varint")
    first = data[offset]
    prefix = first >> 6
    length = 1 << prefix
    if offset + length > len(data):
        raise ValueError("truncated varint")
    raw = int.from_bytes(data[offset : offset + length], "big")
    mask = (1 << (8 * length - 2)) - 1
    return raw & mask, offset + length


def tlv(tag: int, value: bytes) -> bytes:
    return encode_varint(tag) + encode_varint(len(value)) + value


def pem_to_der(pem: str) -> bytes:
    blocks = _PEM_RE.findall(pem)
    if not blocks:
        return b""
    der = bytearray()
    for b64 in blocks:
        der += base64.b64decode(b64)
    return bytes(der)


def encode_string_array(strings: List[str]) -> bytes:
    buf = bytearray()
    for s in strings:
        b = s.encode("utf-8")
        buf += encode_varint(len(b)) + b
    return bytes(buf)


def decode_string_array(raw: bytes) -> List[str]:
    out: List[str] = []
    off = 0
    while off < len(raw):
        ln, off = decode_varint(raw, off)
        out.append(raw[off : off + ln].decode("utf-8", errors="replace"))
        off += ln
    return out


def percent_encode_userinfo(s: str) -> str:
    out = []
    for b in s.encode("utf-8"):
        ch = chr(b)
        if ch.isalnum() or ch in "-._~":
            out.append(ch)
        else:
            out.append(f"%{b:02X}")
    return "".join(out)


def build_subscription_url(base_url: str, username: str, password: str) -> str:
    rest = base_url[len("https://") :] if base_url.startswith("https://") else base_url
    idx = len(rest)
    for sep in ("/", "?", "#"):
        p = rest.find(sep)
        if p != -1 and p < idx:
            idx = p
    authority, tail = rest[:idx], rest[idx:]
    if "@" in authority:
        authority = authority.rsplit("@", 1)[1]
    return f"https://{percent_encode_userinfo(username)}:{percent_encode_userinfo(password)}@{authority}{tail}"


def encode_deeplink(cfg: Dict[str, Any], subscription_only: bool = False) -> str:
    buf = bytearray()
    buf += tlv(TAG_VERSION, encode_varint(CURRENT_DEEPLINK_VERSION))

    sub_url = cfg.get("subscription_url") or ""
    if subscription_only and sub_url:
        buf += tlv(TAG_SUBSCRIPTION_URL, sub_url.encode("utf-8"))
        encoded = base64.urlsafe_b64encode(bytes(buf)).rstrip(b"=").decode("ascii")
        return f"tt://?{encoded}"

    for tag, key in [
        (TAG_HOSTNAME, "hostname"),
        (TAG_USERNAME, "username"),
        (TAG_PASSWORD, "password"),
    ]:
        val = cfg.get(key)
        if val:
            buf += tlv(tag, str(val).encode("utf-8"))

    for addr in cfg.get("addresses", []):
        if addr:
            buf += tlv(TAG_ADDRESS, str(addr).encode("utf-8"))

    if cfg.get("client_random_prefix"):
        buf += tlv(TAG_CLIENT_RANDOM_PREFIX, str(cfg["client_random_prefix"]).encode("utf-8"))

    if cfg.get("client_random_auth_key"):
        buf += tlv(TAG_CLIENT_RANDOM_AUTH_KEY, str(cfg["client_random_auth_key"]).encode("utf-8"))

    if cfg.get("custom_sni"):
        buf += tlv(TAG_CUSTOM_SNI, str(cfg["custom_sni"]).encode("utf-8"))

    if cfg.get("has_ipv6") is False:
        buf += tlv(TAG_HAS_IPV6, b"\x00")

    if cfg.get("skip_verification") is True:
        buf += tlv(TAG_SKIP_VERIFICATION, b"\x01")

    if cfg.get("anti_dpi") is True:
        buf += tlv(TAG_ANTI_DPI, b"\x01")

    cert_pem = cfg.get("certificate") or ""
    if cert_pem and not cfg.get("cert_is_system_verifiable", False):
        der = pem_to_der(cert_pem)
        if der:
            buf += tlv(TAG_CERTIFICATE, der)

    proto = cfg.get("upstream_protocol", "http2")
    if proto in PROTOCOL_MAP and proto != "http2":
        buf += tlv(TAG_UPSTREAM_PROTOCOL, bytes([PROTOCOL_MAP[proto]]))

    if cfg.get("name"):
        buf += tlv(TAG_NAME, str(cfg["name"]).encode("utf-8"))

    dns_list = cfg.get("dns_upstreams") or []
    if dns_list:
        buf += tlv(TAG_DNS_UPSTREAMS, encode_string_array(dns_list))

    if sub_url and sub_url.startswith("https://"):
        buf += tlv(TAG_SUBSCRIPTION_URL, sub_url.encode("utf-8"))

    encoded = base64.urlsafe_b64encode(bytes(buf)).rstrip(b"=").decode("ascii")
    return f"tt://?{encoded}"


def decode_deeplink(uri: str) -> Dict[str, Any]:
    s = uri.strip()
    if s.startswith("tt://?"):
        s = s[len("tt://?") :]
    elif s.startswith("tt://"):
        s = s[len("tt://") :]
    pad = "=" * ((4 - len(s) % 4) % 4)
    raw = base64.urlsafe_b64decode(s + pad)
    out: Dict[str, Any] = {
        "version": 0,
        "hostname": "",
        "addresses": [],
        "custom_sni": "",
        "has_ipv6": True,
        "username": "",
        "password": "",
        "skip_verification": False,
        "has_embedded_certificate": False,
        "certificate_der_bytes": 0,
        "upstream_protocol": "http2",
        "anti_dpi": False,
        "client_random_prefix": "",
        "client_random_auth_key": "",
        "name": "",
        "dns_upstreams": [],
        "subscription_url": "",
    }
    off = 0
    while off < len(raw):
        tag, off = decode_varint(raw, off)
        ln, off = decode_varint(raw, off)
        val = raw[off : off + ln]
        off += ln
        if tag == TAG_VERSION:
            v, _ = decode_varint(val, 0)
            out["version"] = v
        elif tag == TAG_HOSTNAME:
            out["hostname"] = val.decode("utf-8", errors="replace")
        elif tag == TAG_ADDRESS:
            out["addresses"].append(val.decode("utf-8", errors="replace"))
        elif tag == TAG_CUSTOM_SNI:
            out["custom_sni"] = val.decode("utf-8", errors="replace")
        elif tag == TAG_HAS_IPV6:
            out["has_ipv6"] = bool(val and val[0] == 1)
        elif tag == TAG_USERNAME:
            out["username"] = val.decode("utf-8", errors="replace")
        elif tag == TAG_PASSWORD:
            out["password"] = val.decode("utf-8", errors="replace")
        elif tag == TAG_SKIP_VERIFICATION:
            out["skip_verification"] = bool(val and val[0] == 1)
        elif tag == TAG_CERTIFICATE:
            out["has_embedded_certificate"] = len(val) > 0
            out["certificate_der_bytes"] = len(val)
        elif tag == TAG_UPSTREAM_PROTOCOL:
            v, _ = decode_varint(val, 0)
            out["upstream_protocol"] = PROTOCOL_REV_MAP.get(v, f"unknown({v})")
        elif tag == TAG_ANTI_DPI:
            out["anti_dpi"] = bool(val and val[0] == 1)
        elif tag == TAG_CLIENT_RANDOM_PREFIX:
            out["client_random_prefix"] = val.decode("utf-8", errors="replace")
        elif tag == TAG_NAME:
            out["name"] = val.decode("utf-8", errors="replace")
        elif tag == TAG_DNS_UPSTREAMS:
            out["dns_upstreams"] = decode_string_array(val)
        elif tag == TAG_SUBSCRIPTION_URL:
            out["subscription_url"] = val.decode("utf-8", errors="replace")
        elif tag == TAG_CLIENT_RANDOM_AUTH_KEY:
            out["client_random_auth_key"] = val.decode("utf-8", errors="replace")
    return out


def compose_client_toml(cfg: Dict[str, Any]) -> str:
    addrs = ", ".join(f'"{a}"' for a in cfg.get("addresses", []))
    dns_list = ", ".join(f'"{d}"' for d in cfg.get("dns_upstreams", []))
    cert_str = "" if cfg.get("cert_is_system_verifiable", False) else (cfg.get("certificate") or "")
    lines = [
        "# TrustTunnel Client Configuration (Generated by TrustTunnel Web Panel)",
        "# Usage: sudo ./trusttunnel_client -c trusttunnel_client.toml",
        "# Or convert via setup_wizard: ./setup_wizard --mode non-interactive --endpoint_config <this_file> --settings trusttunnel_client.toml",
        "",
        f'hostname = "{cfg.get("hostname", "")}"',
        f"addresses = [{addrs}]",
        f'custom_sni = "{cfg.get("custom_sni", "")}"',
        f'has_ipv6 = {"true" if cfg.get("has_ipv6", True) else "false"}',
        f'username = "{cfg.get("username", "")}"',
        f'password = "{cfg.get("password", "")}"',
        f'client_random_prefix = "{cfg.get("client_random_prefix", "")}"',
        f'client_random_auth_key = "{cfg.get("client_random_auth_key", "")}"',
        f'skip_verification = {"true" if cfg.get("skip_verification", False) else "false"}',
    ]
    if cert_str:
        lines.append(f'certificate = """\n{cert_str.strip()}\n"""')
    else:
        lines.append('certificate = ""')
    lines.extend(
        [
            f'upstream_protocol = "{cfg.get("upstream_protocol", "http2")}"',
            f'anti_dpi = {"true" if cfg.get("anti_dpi", True) else "false"}',
            f'name = "{cfg.get("name", "TrustTunnel Stealth Node")}"',
            f"dns_upstreams = [{dns_list}]",
        ]
    )
    if cfg.get("subscription_url"):
        lines.append(f'subscription_url = "{cfg["subscription_url"]}"')
    return "\n".join(lines) + "\n"


# ==============================================================================
# Certificate Generation & Inspection Helpers
# ==============================================================================


def ensure_default_certificate(cert_dir: Path, domain: str, vps_ip: str) -> Tuple[Path, Path]:
    cert_file = cert_dir / "ip.crt"
    key_file = cert_dir / "ip.key"
    if cert_file.exists() and key_file.exists() and cert_file.stat().st_size > 0:
        return cert_file, key_file

    cert_dir.mkdir(parents=True, exist_ok=True)
    san = f"DNS:{domain}"
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", vps_ip):
        san += f",IP:{vps_ip}"
    cmd = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:prime256v1",
        "-days",
        "3650",
        "-nodes",
        "-keyout",
        str(key_file),
        "-out",
        str(cert_file),
        "-subj",
        f"/CN={domain}",
        "-addext",
        f"subjectAltName={san}",
    ]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return cert_file, key_file


def inspect_certificate(cert_path: str) -> Dict[str, Any]:
    p = Path(cert_path)
    if not p.exists() or p.stat().st_size == 0:
        return {"exists": False, "path": cert_path}
    try:
        pem = p.read_text(encoding="utf-8", errors="replace")
        res = subprocess.run(
            ["openssl", "x509", "-in", str(p), "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        info: Dict[str, Any] = {
            "exists": True,
            "path": cert_path,
            "pem": pem,
            "raw_info": res.stdout.strip(),
            "is_letsencrypt": "Let's Encrypt" in res.stdout or "ZeroSSL" in res.stdout,
        }
        for line in res.stdout.splitlines():
            if line.startswith("subject="):
                info["subject"] = line[len("subject=") :].strip()
            elif line.startswith("issuer="):
                info["issuer"] = line[len("issuer=") :].strip()
            elif line.startswith("notBefore="):
                info["not_before"] = line[len("notBefore=") :].strip()
            elif line.startswith("notAfter="):
                info["not_after"] = line[len("notAfter=") :].strip()
            elif "Fingerprint=" in line:
                info["fingerprint"] = line.split("=", 1)[1].strip()
        return info
    except Exception as e:
        return {"exists": True, "path": cert_path, "error": str(e)}


# ==============================================================================
# Default Panel State & TOML / Proxy Configuration Generators
# ==============================================================================


def build_default_state() -> Dict[str, Any]:
    cert_dir = get_cert_dir()
    vps_ip = os.environ.get("VPS_IP", "156.246.95.165")
    domain = f"{vps_ip}.nip.io"
    cert_file, key_file = ensure_default_certificate(cert_dir, domain, vps_ip)
    default_auth_key = secrets.token_hex(16)
    default_prefix = f"{secrets.token_hex(4)}/f0f0f0f0"

    return {
        "meta": {
            "panel_title": "TrustTunnel 智控面板",
            "obfuscation_preset": "stealth_max",
            "camouflage_port": 8080,
            "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
        "cert": {
            "vps_ip": vps_ip,
            "nip_provider": "nip.io",
            "domain": domain,
            "ssl_email": f"ssl_admin_{vps_ip.replace('.', '_')}@gmail.com",
            "cert_dir": str(cert_dir),
            "cert_chain_path": str(cert_file),
            "private_key_path": str(key_file),
            "cert_mode": "letsencrypt",
            "system_verifiable": False,
        },
        "camouflage": {
            "enabled": True,
            "architecture": "tt_native_reverse_proxy",  # tt_native_reverse_proxy | nginx_stream_sni | caddy_front
            "proxy_Server_type": "builtin",  # builtin | nginx | caddy
            "template": "tetris",  # tetris | calculator | todo | resume | custom
            "listen_address": "127.0.0.1:8080",
            "path_mask": "/",
            "h3_backward_compatibility": False,
            "custom_html": "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Welcome</title></head><body style='background:#0f172a;color:#f8fafc;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0'><div><h1>Service Online</h1><p>All systems operational.</p></div></body></html>",
        },
        "vpn": {
            "listen_address": "0.0.0.0:443",
            "ipv6_available": True,
            "allow_private_network_connections": False,
            "tls_handshake_timeout_secs": 10,
            "client_listener_timeout_secs": 600,
            "connection_establishment_timeout_secs": 30,
            "tcp_connections_timeout_secs": 604800,
            "udp_connections_timeout_secs": 300,
            "auth_failure_status_code": 407,
            "non_connect_auth_failure_status_code": 404,
            "default_max_http2_conns_per_client": 32,
            "default_max_http3_conns_per_client": 8,
            "ping_enable": False,
            "ping_path": "/ping",
            "speedtest_enable": False,
            "speedtest_path": "/speedtest",
            "listen_protocols": {
                "http1_enabled": True,
                "http1_upload_buffer_size": 32768,
                "http2_enabled": True,
                "http2_initial_connection_window_size": 8388608,
                "http2_initial_stream_window_size": 131072,
                "http2_max_concurrent_streams": 1000,
                "http2_max_frame_size": 16384,
                "http2_header_table_size": 65536,
                "quic_enabled": True,
                "quic_recv_udp_payload_size": 1350,
                "quic_send_udp_payload_size": 1350,
                "quic_initial_max_data": 104857600,
                "quic_initial_max_stream_data_bidi_local": 1048576,
                "quic_initial_max_stream_data_bidi_remote": 1048576,
                "quic_initial_max_stream_data_uni": 1048576,
                "quic_initial_max_streams_bidi": 4096,
                "quic_initial_max_streams_uni": 4096,
                "quic_max_connection_window": 25165824,
                "quic_max_stream_window": 16777216,
                "quic_disable_active_migration": True,
                "quic_enable_early_data": True,
                "quic_message_queue_capacity": 4096,
            },
            "forward_protocol": {
                "mode": "direct",  # direct | socks5
                "socks5_address": "127.0.0.1:1080",
                "socks5_extended_auth": False,
            },
            "icmp": {
                "enabled": False,
                "interface_name": "eth0",
                "request_timeout_secs": 3,
                "recv_message_queue_capacity": 256,
            },
            "metrics": {
                "enabled": True,
                "address": "127.0.0.1:1987",
                "request_timeout_secs": 3,
                "per_client_metrics": True,
            },
            "subscription": {
                "enabled": False,
                "hostname": domain,
                "path": "/subscription",
                "address": f"{vps_ip}:443",
                "name": "TrustTunnel 旗舰混淆节点",
                "dns_upstreams": ["https://1.1.1.1/dns-query", "tls://1.1.1.1"],
                "custom_sni": "",
                "client_random_prefix": "",
            },
        },
        "hosts": {
            "main_hosts": [
                {
                    "hostname": domain,
                    "cert_chain_path": str(cert_file),
                    "private_key_path": str(key_file),
                    "allowed_sni": [f"cdn.{domain}", f"static.{domain}"],
                }
            ],
            "ping_hosts": [],
            "speedtest_hosts": [],
            "reverse_proxy_hosts": [],
        },
        "clients": [
            {
                "username": "vip_user",
                "password": secrets.token_urlsafe(12),
                "note": "默认高速主力账号",
                "max_http2_conns": 32,
                "max_http3_conns": 8,
                "upstream_protocol": "http3",
                "anti_dpi": True,
                "custom_sni": "",
                "use_auth_key": False,
                "use_random_prefix": False,
                "dns_upstreams": ["https://1.1.1.1/dns-query", "tls://1.1.1.1"],
            }
        ],
        "rules": {
            "enabled": True,
            "default_auth_key": default_auth_key,
            "default_random_prefix": default_prefix,
            "items": [
                {
                    "id": "rule-auth-key",
                    "cidr": "",
                    "client_random_prefix": "",
                    "client_random_auth_key": default_auth_key,
                    "action": "allow",
                    "note": "SNI 派生密钥握手放行规则 (HKDF+AES)",
                },
                {
                    "id": "rule-prefix",
                    "cidr": "",
                    "client_random_prefix": default_prefix,
                    "client_random_auth_key": "",
                    "action": "allow",
                    "note": "TLS ClientRandom 掩码前缀放行规则",
                },
            ],
        },
    }


def generate_vpn_toml(state: Dict[str, Any], tt_dir: Path) -> str:
    vpn = state["vpn"]
    cam = state["camouflage"]
    lp = vpn["listen_protocols"]
    fp = vpn["forward_protocol"]
    sub = vpn["subscription"]

    creds_path = str(tt_dir / "credentials.toml")
    rules_path = str(tt_dir / "rules.toml")

    # Note: In TrustTunnel's subscription.rs, if [subscription] is present in vpn.toml AND
    # [reverse_proxy] is present, subscription.path cannot overlap reverse_proxy.path_mask ("/").
    # So if reverse_proxy is enabled with path_mask == "/", we serve subscriptions via the panel/proxy
    # or adjust path_mask when native [subscription] is explicitly enabled.
    effective_path_mask = cam.get("path_mask", "/") or "/"
    if not effective_path_mask.startswith("/"):
        effective_path_mask = "/" + effective_path_mask

    lines = [
        "# =============================================================================",
        "# TrustTunnel Main Endpoint Settings (vpn.toml)",
        "# Generated automatically by TrustTunnel Web Configuration Panel",
        "# =============================================================================",
        "",
        f'listen_address = "{vpn.get("listen_address", "0.0.0.0:443")}"',
        f'ipv6_available = {"true" if vpn.get("ipv6_available", True) else "false"}',
        f'allow_private_network_connections = {"true" if vpn.get("allow_private_network_connections", False) else "false"}',
        f'tls_handshake_timeout_secs = {int(vpn.get("tls_handshake_timeout_secs", 10))}',
        f'client_listener_timeout_secs = {int(vpn.get("client_listener_timeout_secs", 600))}',
        f'connection_establishment_timeout_secs = {int(vpn.get("connection_establishment_timeout_secs", 30))}',
        f'tcp_connections_timeout_secs = {int(vpn.get("tcp_connections_timeout_secs", 604800))}',
        f'udp_connections_timeout_secs = {int(vpn.get("udp_connections_timeout_secs", 300))}',
        f'credentials_file = "{creds_path}"',
    ]

    if state.get("rules", {}).get("enabled", True):
        lines.append(f'rules_file = "{rules_path}"')

    lines.extend(
        [
            f'auth_failure_status_code = {int(vpn.get("auth_failure_status_code", 407))}',
            f'non_connect_auth_failure_status_code = {int(vpn.get("non_connect_auth_failure_status_code", 404))}',
        ]
    )

    if vpn.get("default_max_http2_conns_per_client"):
        lines.append(
            f'default_max_http2_conns_per_client = {int(vpn["default_max_http2_conns_per_client"])}'
        )
    if vpn.get("default_max_http3_conns_per_client"):
        lines.append(
            f'default_max_http3_conns_per_client = {int(vpn["default_max_http3_conns_per_client"])}'
        )

    lines.extend(
        [
            f'ping_enable = {"true" if vpn.get("ping_enable", False) else "false"}',
            f'ping_path = "{vpn.get("ping_path", "/ping")}"',
            f'speedtest_enable = {"true" if vpn.get("speedtest_enable", False) else "false"}',
            f'speedtest_path = "{vpn.get("speedtest_path", "/speedtest")}"',
            "",
            "[listen_protocols]",
        ]
    )

    if lp.get("http1_enabled", True):
        lines.extend(
            [
                "",
                "[listen_protocols.http1]",
                f'upload_buffer_size = {int(lp.get("http1_upload_buffer_size", 32768))}',
            ]
        )

    if lp.get("http2_enabled", True):
        lines.extend(
            [
                "",
                "[listen_protocols.http2]",
                f'initial_connection_window_size = {int(lp.get("http2_initial_connection_window_size", 8388608))}',
                f'initial_stream_window_size = {int(lp.get("http2_initial_stream_window_size", 131072))}',
                f'max_concurrent_streams = {int(lp.get("http2_max_concurrent_streams", 1000))}',
                f'max_frame_size = {int(lp.get("http2_max_frame_size", 16384))}',
                f'header_table_size = {int(lp.get("http2_header_table_size", 65536))}',
            ]
        )

    if lp.get("quic_enabled", True):
        lines.extend(
            [
                "",
                "[listen_protocols.quic]",
                f'recv_udp_payload_size = {int(lp.get("quic_recv_udp_payload_size", 1350))}',
                f'send_udp_payload_size = {int(lp.get("quic_send_udp_payload_size", 1350))}',
                f'initial_max_data = {int(lp.get("quic_initial_max_data", 104857600))}',
                f'initial_max_stream_data_bidi_local = {int(lp.get("quic_initial_max_stream_data_bidi_local", 1048576))}',
                f'initial_max_stream_data_bidi_remote = {int(lp.get("quic_initial_max_stream_data_bidi_remote", 1048576))}',
                f'initial_max_stream_data_uni = {int(lp.get("quic_initial_max_stream_data_uni", 1048576))}',
                f'initial_max_streams_bidi = {int(lp.get("quic_initial_max_streams_bidi", 4096))}',
                f'initial_max_streams_uni = {int(lp.get("quic_initial_max_streams_uni", 4096))}',
                f'max_connection_window = {int(lp.get("quic_max_connection_window", 25165824))}',
                f'max_stream_window = {int(lp.get("quic_max_stream_window", 16777216))}',
                f'disable_active_migration = {"true" if lp.get("quic_disable_active_migration", True) else "false"}',
                f'enable_early_data = {"true" if lp.get("quic_enable_early_data", True) else "false"}',
                f'message_queue_capacity = {int(lp.get("quic_message_queue_capacity", 4096))}',
            ]
        )

    lines.append("")
    if fp.get("mode") == "socks5":
        lines.extend(
            [
                "[forward_protocol.socks5]",
                f'address = "{fp.get("socks5_address", "127.0.0.1:1080")}"',
                f'extended_auth = {"true" if fp.get("socks5_extended_auth", False) else "false"}',
            ]
        )
    else:
        lines.extend(["[forward_protocol]", "direct = {}"])

    if cam.get("enabled", True) and cam.get("architecture") == "tt_native_reverse_proxy":
        # Avoid path overlap if native [subscription] is also enabled in vpn.toml
        rp_mask = effective_path_mask
        if sub.get("enabled", False) and sub.get("path", "/subscription").startswith(rp_mask):
            rp_mask = "/web"
        lines.extend(
            [
                "",
                "[reverse_proxy]",
                f'server_address = "{cam.get("listen_address", "127.0.0.1:8080")}"',
                f'path_mask = "{rp_mask}"',
                f'h3_backward_compatibility = {"true" if cam.get("h3_backward_compatibility", False) else "false"}',
            ]
        )

    icmp = vpn.get("icmp", {})
    if icmp.get("enabled", False):
        lines.extend(
            [
                "",
                "[icmp]",
                f'interface_name = "{icmp.get("interface_name", "eth0")}"',
                f'request_timeout_secs = {int(icmp.get("request_timeout_secs", 3))}',
                f'recv_message_queue_capacity = {int(icmp.get("recv_message_queue_capacity", 256))}',
            ]
        )

    metrics = vpn.get("metrics", {})
    if metrics.get("enabled", True):
        lines.extend(
            [
                "",
                "[metrics]",
                f'address = "{metrics.get("address", "127.0.0.1:1987")}"',
                f'request_timeout_secs = {int(metrics.get("request_timeout_secs", 3))}',
                f'per_client_metrics = {"true" if metrics.get("per_client_metrics", True) else "false"}',
            ]
        )

    if sub.get("enabled", False):
        dns_arr = ", ".join(f'"{d}"' for d in sub.get("dns_upstreams", []))
        lines.extend(
            [
                "",
                "[subscription]",
                "enabled = true",
                f'hostname = "{sub.get("hostname") or state["cert"]["domain"]}"',
                f'path = "{sub.get("path", "/subscription")}"',
                f'address = "{sub.get("address") or (state["cert"]["vps_ip"] + ":443")}"',
                f'name = "{sub.get("name", "TrustTunnel Pro Node")}"',
                f"dns_upstreams = [{dns_arr}]",
            ]
        )
        if sub.get("custom_sni"):
            lines.append(f'custom_sni = "{sub["custom_sni"]}"')
        if sub.get("client_random_prefix"):
            lines.append(f'client_random_prefix = "{sub["client_random_prefix"]}"')

    return "\n".join(lines) + "\n"


def generate_hosts_toml(state: Dict[str, Any]) -> str:
    hosts = state["hosts"]
    lines = [
        "# =============================================================================",
        "# TrustTunnel TLS Hosts Settings (hosts.toml)",
        "# Supports SIGHUP hot-reload without disconnecting VPN clients",
        "# =============================================================================",
        "",
    ]

    for section in ("main_hosts", "ping_hosts", "speedtest_hosts", "reverse_proxy_hosts"):
        items = hosts.get(section) or []
        for item in items:
            lines.append(f"[[{section}]]")
            lines.append(f'hostname = "{item.get("hostname", "")}"')
            lines.append(f'cert_chain_path = "{item.get("cert_chain_path", "")}"')
            lines.append(f'private_key_path = "{item.get("private_key_path", "")}"')
            sni_list = item.get("allowed_sni") or []
            if sni_list:
                sni_str = ", ".join(f'"{s}"' for s in sni_list if s)
                lines.append(f"allowed_sni = [{sni_str}]")
            lines.append("")

    return "\n".join(lines)


def generate_credentials_toml(state: Dict[str, Any]) -> str:
    lines = [
        "# =============================================================================",
        "# TrustTunnel Client Credentials (credentials.toml)",
        "# =============================================================================",
        "",
    ]
    for c in state.get("clients", []):
        lines.append("[[client]]")
        lines.append(f'username = "{c.get("username", "")}"')
        lines.append(f'password = "{c.get("password", "")}"')
        if c.get("max_http2_conns"):
            lines.append(f'max_http2_conns = {int(c["max_http2_conns"])}')
        if c.get("max_http3_conns"):
            lines.append(f'max_http3_conns = {int(c["max_http3_conns"])}')
        lines.append("")
    return "\n".join(lines)


def generate_rules_toml(state: Dict[str, Any]) -> str:
    lines = [
        "# =============================================================================",
        "# TrustTunnel Connection Filtering & TLS Handshake Obfuscation Rules (rules.toml)",
        "# Evaluated top-to-bottom; first matching rule wins.",
        "# =============================================================================",
        "",
    ]
    for r in state.get("rules", {}).get("items", []):
        lines.append("[[rule]]")
        if r.get("cidr"):
            lines.append(f'cidr = "{r["cidr"]}"')
        if r.get("client_random_auth_key"):
            lines.append(f'client_random_auth_key = "{r["client_random_auth_key"]}"')
        elif r.get("client_random_prefix"):
            lines.append(f'client_random_prefix = "{r["client_random_prefix"]}"')
        lines.append(f'action = "{r.get("action", "allow")}"')
        lines.append("")
    return "\n".join(lines)


def get_active_camouflage_root(state: Dict[str, Any]) -> Path:
    tpl = state.get("camouflage", {}).get("template", "tetris")
    if tpl in ("tetris", "calculator", "todo", "resume"):
        return CAMOUFLAGE_DIR / tpl
    custom_dir = DATA_DIR / "camouflage_custom"
    custom_dir.mkdir(parents=True, exist_ok=True)
    index_file = custom_dir / "index.html"
    index_file.write_text(
        state.get("camouflage", {}).get("custom_html", "<h1>Welcome</h1>"),
        encoding="utf-8",
    )
    return custom_dir


def generate_nginx_conf(state: Dict[str, Any]) -> str:
    cam = state["camouflage"]
    cert = state["cert"]
    root_dir = str(get_active_camouflage_root(state))
    if cam.get("architecture") == "nginx_stream_sni":
        tpl = (TEMPLATES_DIR / "nginx-stream-sni.conf").read_text(encoding="utf-8")
        return (
            tpl.replace("{{VPN_HOSTNAME}}", cert.get("domain", "example.com"))
            .replace("{{TT_INTERNAL_PORT}}", "8443")
            .replace("{{CERT_PATH}}", cert.get("cert_chain_path", "/etc/ssl/ip-certs/ip.crt"))
            .replace("{{KEY_PATH}}", cert.get("private_key_path", "/etc/ssl/ip-certs/ip.key"))
            .replace("{{CAMOUFLAGE_ROOT}}", root_dir)
        )
    tpl = (TEMPLATES_DIR / "nginx-reverse.conf").read_text(encoding="utf-8")
    return tpl.replace("{{CAMOUFLAGE_ROOT}}", root_dir)


def generate_caddyfile(state: Dict[str, Any]) -> str:
    root_dir = str(get_active_camouflage_root(state))
    tpl = (TEMPLATES_DIR / "Caddyfile.template").read_text(encoding="utf-8")
    return tpl.replace("{{CAMOUFLAGE_ROOT}}", root_dir)


def generate_issue_cert_script(state: Dict[str, Any]) -> str:
    cert = state["cert"]
    vps_ip = cert.get("vps_ip", "156.246.95.165")
    domain = cert.get("domain", f"{vps_ip}.nip.io")
    email = cert.get("ssl_email", f"ssl_admin_{vps_ip.replace('.', '_')}@gmail.com")
    cert_dir = cert.get("cert_dir", "/etc/ssl/ip-certs")
    return f"""#!/bin/bash
set -e

# ==================== 配置项 ====================
VPS_IP="{vps_ip}"
DOMAIN="{domain}"
SSL_EMAIL="{email}"
CERT_DIR="{cert_dir}"

echo "=== 1. 安装基础依赖 (curl, socat) ==="
apt update -y && apt install -y curl socat

echo "=== 2. 安装/更新 acme.sh 客户端 ==="
if [ ! -f "$HOME/.acme.sh/acme.sh" ]; then
    curl https://get.acme.sh | sh -s email=$SSL_EMAIL
fi
source ~/.bashrc || true
export PATH="$HOME/.acme.sh:$PATH"

echo "=== 3. 临时释放 80 端口用于验证 ==="
systemctl stop nginx 2>/dev/null || true

echo "=== 4. 申请 Let's Encrypt ECC 证书 ($DOMAIN) ==="
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --issue -d $DOMAIN --standalone --server letsencrypt --force

echo "=== 5. 安装证书到系统标准目录 ($CERT_DIR) ==="
mkdir -p $CERT_DIR
~/.acme.sh/acme.sh --install-cert -d $DOMAIN \\
  --key-file       $CERT_DIR/ip.key  \\
  --fullchain-file $CERT_DIR/ip.crt

echo "=== 6. 恢复 Web 服务 ==="
systemctl start nginx 2>/dev/null || true

echo "=================================================="
echo " 证书申请与安装完成！"
echo " 证书域名: $DOMAIN"
echo " 私钥路径: $CERT_DIR/ip.key"
echo " 证书路径: $CERT_DIR/ip.crt"
echo " 证书到期检查命令: ~/.acme.sh/acme.sh --list"
echo "=================================================="
"""


# ==============================================================================
# State Persistence & Config File Synchronization
# ==============================================================================

STATE_LOCK = threading.Lock()


def load_state() -> Dict[str, Any]:
    with STATE_LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
                return data
            except Exception:
                pass
        state = build_default_state()
        save_state_unlocked(state)
        return state


def save_state_unlocked(state: Dict[str, Any]) -> Dict[str, str]:
    state["meta"]["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

    tt_dir = get_tt_dir()
    vpn_toml = generate_vpn_toml(state, tt_dir)
    hosts_toml = generate_hosts_toml(state)
    creds_toml = generate_credentials_toml(state)
    rules_toml = generate_rules_toml(state)
    nginx_conf = generate_nginx_conf(state)
    caddy_conf = generate_caddyfile(state)

    (tt_dir / "vpn.toml").write_text(vpn_toml, encoding="utf-8")
    (tt_dir / "hosts.toml").write_text(hosts_toml, encoding="utf-8")
    (tt_dir / "credentials.toml").write_text(creds_toml, encoding="utf-8")
    (tt_dir / "rules.toml").write_text(rules_toml, encoding="utf-8")
    (tt_dir / "nginx-camouflage.conf").write_text(nginx_conf, encoding="utf-8")
    (tt_dir / "Caddyfile").write_text(caddy_conf, encoding="utf-8")

    return {
        "tt_dir": str(tt_dir),
        "vpn_toml": vpn_toml,
        "hosts_toml": hosts_toml,
        "credentials_toml": creds_toml,
        "rules_toml": rules_toml,
        "nginx_conf": nginx_conf,
        "caddyfile": caddy_conf,
        "issue_cert_sh": generate_issue_cert_script(state),
    }


def save_state(state: Dict[str, Any]) -> Dict[str, str]:
    with STATE_LOCK:
        return save_state_unlocked(state)


# ==============================================================================
# Client Configuration Builder (DeepLink tt://? + TOML + Subscription)
# ==============================================================================


def build_client_export(state: Dict[str, Any], username: str, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    overrides = overrides or {}
    clients = state.get("clients", [])
    user = next((c for c in clients if c.get("username") == username), None)
    if not user:
        if clients:
            user = clients[0]
        else:
            raise ValueError(f"User '{username}' not found")

    cert = state["cert"]
    vpn = state["vpn"]
    hosts = state["hosts"]
    rules = state.get("rules", {})

    main_host = (hosts.get("main_hosts") or [{}])[0]
    hostname = overrides.get("hostname") or main_host.get("hostname") or cert.get("domain") or "vpn.example.com"

    listen_addr = vpn.get("listen_address", "0.0.0.0:443")
    port = listen_addr.rsplit(":", 1)[-1] if ":" in listen_addr else "443"
    vps_ip = overrides.get("address") or cert.get("vps_ip") or "156.246.95.165"
    if ":" not in vps_ip:
        endpoint_addr = f"{vps_ip}:{port}"
    else:
        endpoint_addr = vps_ip

    cert_path = main_host.get("cert_chain_path") or cert.get("cert_chain_path") or ""
    cert_pem = ""
    if cert_path and Path(cert_path).exists():
        cert_pem = Path(cert_path).read_text(encoding="utf-8", errors="replace")

    use_auth_key = overrides.get("use_auth_key", user.get("use_auth_key", False))
    use_random_prefix = overrides.get("use_random_prefix", user.get("use_random_prefix", False))

    auth_key = ""
    random_prefix = ""
    if use_auth_key:
        auth_key = overrides.get("client_random_auth_key") or rules.get("default_auth_key") or ""
    elif use_random_prefix:
        random_prefix = overrides.get("client_random_prefix") or rules.get("default_random_prefix") or ""

    sub_cfg = vpn.get("subscription", {})
    sub_url = ""
    if sub_cfg.get("enabled") or overrides.get("include_subscription", True):
        sub_host = sub_cfg.get("hostname") or hostname
        sub_path = sub_cfg.get("path") or "/subscription"
        port_part = f":{port}" if port not in ("443", "0") else ""
        base_sub = f"https://{sub_host}{port_part}{sub_path}"
        sub_url = build_subscription_url(base_sub, user["username"], user["password"])

    export_cfg = {
        "hostname": hostname,
        "addresses": [endpoint_addr],
        "custom_sni": overrides.get("custom_sni", user.get("custom_sni", "")),
        "has_ipv6": overrides.get("has_ipv6", vpn.get("ipv6_available", True)),
        "username": user["username"],
        "password": user["password"],
        "client_random_prefix": random_prefix,
        "client_random_auth_key": auth_key,
        "skip_verification": overrides.get("skip_verification", False),
        "certificate": cert_pem,
        "cert_is_system_verifiable": cert.get("system_verifiable", False),
        "upstream_protocol": overrides.get("upstream_protocol", user.get("upstream_protocol", "http3")),
        "anti_dpi": overrides.get("anti_dpi", user.get("anti_dpi", True)),
        "name": overrides.get("name") or f"TrustTunnel · {user['username']}",
        "dns_upstreams": overrides.get("dns_upstreams") or user.get("dns_upstreams") or ["https://1.1.1.1/dns-query", "tls://1.1.1.1"],
        "subscription_url": sub_url if sub_cfg.get("enabled") else "",
    }

    deeplink_uri = encode_deeplink(export_cfg, subscription_only=False)
    toml_str = compose_client_toml(export_cfg)

    sub_only_cfg = dict(export_cfg)
    sub_only_cfg["subscription_url"] = sub_url
    deeplink_sub_only = encode_deeplink(sub_only_cfg, subscription_only=True)

    return {
        "username": user["username"],
        "deeplink": deeplink_uri,
        "deeplink_subscription_only": deeplink_sub_only,
        "subscription_url": sub_url,
        "toml": toml_str,
        "config": export_cfg,
        "decoded_check": decode_deeplink(deeplink_uri),
    }


# ==============================================================================
# Runtime Status & Metrics Collector
# ==============================================================================


def get_runtime_status(state: Dict[str, Any]) -> Dict[str, Any]:
    tt_dir = get_tt_dir()
    endpoint_bin = Path("/opt/trusttunnel/trusttunnel_endpoint")
    if not endpoint_bin.exists():
        endpoint_bin = tt_dir / "trusttunnel_endpoint"

    # Check if trusttunnel_endpoint process is running
    pgrep = subprocess.run(
        ["pgrep", "-f", "trusttunnel_endpoint"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    tt_running = pgrep.returncode == 0 and bool(pgrep.stdout.strip())

    nginx_installed = shutil.which("nginx") is not None
    caddy_installed = shutil.which("caddy") is not None

    # Fetch live metrics from TrustTunnel Prometheus /metrics and /clients if reachable
    metrics_cfg = state.get("vpn", {}).get("metrics", {})
    metrics_addr = metrics_cfg.get("address", "127.0.0.1:1987")
    live_clients: List[Dict[str, Any]] = []
    metrics_ok = False
    if tt_running and metrics_cfg.get("enabled", True):
        try:
            with urllib.request.urlopen(f"http://{metrics_addr}/clients", timeout=1.5) as resp:
                if resp.status == 200:
                    live_clients = json.loads(resp.read().decode("utf-8"))
                    metrics_ok = True
        except Exception:
            pass

    cert_info = inspect_certificate(state["cert"].get("cert_chain_path", ""))

    return {
        "endpoint_binary_installed": endpoint_bin.exists(),
        "endpoint_binary_path": str(endpoint_bin),
        "endpoint_running": tt_running,
        "endpoint_pids": pgrep.stdout.strip().splitlines() if tt_running else [],
        "camouflage_server_running": True,
        "camouflage_port": state.get("meta", {}).get("camouflage_port", 8080),
        "active_camouflage_template": state.get("camouflage", {}).get("template", "tetris"),
        "nginx_installed": nginx_installed,
        "caddy_installed": caddy_installed,
        "metrics_reachable": metrics_ok,
        "live_clients": live_clients,
        "certificate": cert_info,
        "tt_dir": str(tt_dir),
        "platform": f"{platform.system()} {platform.machine()}",
    }


# ==============================================================================
# Camouflage Static HTTP Server (Runs on 127.0.0.1:8080 / 0.0.0.0:8080)
# ==============================================================================


class CamouflageHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return  # Keep logs clean

    def do_GET(self) -> None:
        state = load_state()
        root_dir = get_active_camouflage_root(state)
        parsed = urllib.parse.urlparse(self.path)
        rel = parsed.path.lstrip("/") or "index.html"
        target = (root_dir / rel).resolve()
        if not str(target).startswith(str(root_dir.resolve())) or not target.is_file():
            target = root_dir / "index.html"

        if target.is_file():
            content = target.read_bytes()
            ctype, _ = mimetypes.guess_type(str(target))
            self.send_response(200)
            self.send_header("Content-Type", f"{ctype or 'text/html'}; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ==============================================================================
# Main Web Configuration Panel HTTP Handler
# ==============================================================================


class PanelHTTPHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[TT-Panel] {self.address_string()} - {format % args}\n")

    def _send_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 1. API Routes
        if path == "/api/state":
            state = load_state()
            files = save_state(state)
            status = get_runtime_status(state)
            exports = [build_client_export(state, c["username"]) for c in state.get("clients", [])]
            self._send_json(
                {
                    "ok": True,
                    "state": state,
                    "files": files,
                    "status": status,
                    "exports": exports,
                }
            )
            return

        if path == "/api/detect-ip":
            detected = ""
            for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
                try:
                    with urllib.request.urlopen(url, timeout=3) as resp:
                        ip_txt = resp.read().decode("utf-8").strip()
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_txt):
                            detected = ip_txt
                            break
                except Exception:
                    pass
            if not detected:
                detected = load_state()["cert"].get("vps_ip", "156.246.95.165")
            self._send_json({"ok": True, "ip": detected})
            return

        # Public/Basic-Auth Subscription Endpoint (/subscription)
        if path == "/subscription":
            state = load_state()
            auth_hdr = self.headers.get("Authorization", "")
            matched_user = None
            if auth_hdr.startswith("Basic "):
                try:
                    decoded = base64.b64decode(auth_hdr[6:]).decode("utf-8")
                    u, p = decoded.split(":", 1)
                    matched_user = next(
                        (c for c in state.get("clients", []) if c["username"] == u and c["password"] == p),
                        None,
                    )
                except Exception:
                    pass
            if not matched_user:
                q = urllib.parse.parse_qs(parsed.query)
                u_q = (q.get("user") or [""])[0]
                if u_q:
                    matched_user = next((c for c in state.get("clients", []) if c["username"] == u_q), None)
            if not matched_user and state.get("clients"):
                matched_user = state["clients"][0]

            if not matched_user:
                self._send_json({"error": "Unauthorized"}, status=401)
                return

            exp = build_client_export(state, matched_user["username"])
            cfg = exp["config"]
            sub_json = {
                "version": 1,
                "hostname": cfg["hostname"],
                "address": cfg["addresses"][0],
                "username": cfg["username"],
                "password": cfg["password"],
                "has_ipv6": cfg["has_ipv6"],
                "upstream_protocol": cfg["upstream_protocol"],
                "anti_dpi": cfg["anti_dpi"],
                "skip_verification": cfg["skip_verification"],
                "name": cfg["name"],
                "dns_upstreams": cfg["dns_upstreams"],
            }
            if cfg.get("certificate") and not cfg.get("cert_is_system_verifiable"):
                sub_json["certificate"] = cfg["certificate"]
            if cfg.get("custom_sni"):
                sub_json["custom_sni"] = cfg["custom_sni"]
            if cfg.get("client_random_prefix"):
                sub_json["client_random_prefix"] = cfg["client_random_prefix"]
            self._send_json(sub_json)
            return

        # Live Camouflage Preview Route (/camouflage/<template>)
        if path.startswith("/camouflage/"):
            parts = path.strip("/").split("/")
            tpl_name = parts[1] if len(parts) >= 2 else "tetris"
            state = load_state()
            if tpl_name == "active":
                tpl_name = state.get("camouflage", {}).get("template", "tetris")
            if tpl_name in ("tetris", "calculator", "todo", "resume"):
                target = CAMOUFLAGE_DIR / tpl_name / "index.html"
                content = target.read_bytes()
            else:
                content = state.get("camouflage", {}).get("custom_html", "<h1>Welcome</h1>").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return

        # Serve static frontend assets
        rel = path.lstrip("/") or "index.html"
        target = (STATIC_DIR / rel).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            target = STATIC_DIR / "index.html"

        content = target.read_bytes()
        ctype, _ = mimetypes.guess_type(str(target))
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype or 'text/html'}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json()
        except Exception as e:
            self._send_json({"ok": False, "error": f"Invalid JSON: {e}"}, status=400)
            return

        if path == "/api/state":
            state = load_state()
            for key in ("meta", "cert", "camouflage", "vpn", "hosts", "clients", "rules"):
                if key in body:
                    state[key] = body[key]
            # Keep main_hosts[0] synchronized with cert paths if user updated cert section
            if state.get("hosts", {}).get("main_hosts"):
                state["hosts"]["main_hosts"][0]["hostname"] = state["cert"]["domain"]
                state["hosts"]["main_hosts"][0]["cert_chain_path"] = state["cert"]["cert_chain_path"]
                state["hosts"]["main_hosts"][0]["private_key_path"] = state["cert"]["private_key_path"]

            files = save_state(state)
            status = get_runtime_status(state)
            exports = [build_client_export(state, c["username"]) for c in state.get("clients", [])]
            self._send_json(
                {
                    "ok": True,
                    "message": "配置已保存并同步生成全部 TOML 与反代配置文件",
                    "state": state,
                    "files": files,
                    "status": status,
                    "exports": exports,
                }
            )
            return

        if path == "/api/preset":
            preset = body.get("preset", "stealth_max")
            state = load_state()
            state["meta"]["obfuscation_preset"] = preset
            lp = state["vpn"]["listen_protocols"]
            if preset == "stealth_max":
                state["vpn"]["auth_failure_status_code"] = 407
                state["vpn"]["non_connect_auth_failure_status_code"] = 404
                lp["http1_enabled"] = True
                lp["http2_enabled"] = True
                lp["http2_initial_stream_window_size"] = 131072
                lp["http2_max_concurrent_streams"] = 1000
                lp["http2_max_frame_size"] = 16384
                lp["quic_enabled"] = True
                lp["quic_enable_early_data"] = True
                lp["quic_disable_active_migration"] = True
                state["camouflage"]["enabled"] = True
                state["camouflage"]["architecture"] = "tt_native_reverse_proxy"
                for c in state.get("clients", []):
                    c["anti_dpi"] = True
                    c["upstream_protocol"] = "http3"
            elif preset == "quic_turbo":
                state["vpn"]["auth_failure_status_code"] = 407
                state["vpn"]["non_connect_auth_failure_status_code"] = 404
                lp["quic_enabled"] = True
                lp["quic_max_connection_window"] = 33554432
                lp["quic_max_stream_window"] = 16777216
                lp["quic_recv_udp_payload_size"] = 1350
                lp["quic_send_udp_payload_size"] = 1350
                for c in state.get("clients", []):
                    c["upstream_protocol"] = "http3"
                    c["anti_dpi"] = False
            elif preset == "compat_http2":
                state["vpn"]["auth_failure_status_code"] = 407
                state["vpn"]["non_connect_auth_failure_status_code"] = 407
                lp["http1_enabled"] = True
                lp["http2_enabled"] = True
                lp["quic_enabled"] = True
                for c in state.get("clients", []):
                    c["upstream_protocol"] = "http2"
                    c["anti_dpi"] = True

            files = save_state(state)
            exports = [build_client_export(state, c["username"]) for c in state.get("clients", [])]
            self._send_json(
                {
                    "ok": True,
                    "message": f"已一键应用【{preset}】混淆预设参数",
                    "state": state,
                    "files": files,
                    "exports": exports,
                }
            )
            return

        if path == "/api/export":
            state = load_state()
            username = body.get("username") or (state["clients"][0]["username"] if state.get("clients") else "")
            overrides = body.get("overrides") or {}
            exp = build_client_export(state, username, overrides)
            self._send_json({"ok": True, "export": exp})
            return

        if path == "/api/deeplink/decode":
            uri = body.get("uri", "")
            try:
                decoded = decode_deeplink(uri)
                self._send_json({"ok": True, "decoded": decoded})
            except Exception as e:
                self._send_json({"ok": False, "error": f"DeepLink 解析失败: {e}"}, status=400)
            return

        if path == "/api/cert/issue":
            state = load_state()
            cert = state["cert"]
            vps_ip = body.get("vps_ip") or cert.get("vps_ip", "156.246.95.165")
            provider = body.get("nip_provider") or cert.get("nip_provider", "nip.io")
            domain = body.get("domain") or f"{vps_ip}.{provider}"
            mode = body.get("cert_mode") or cert.get("cert_mode", "selfsigned")
            cert_dir = get_cert_dir()

            cert["vps_ip"] = vps_ip
            cert["nip_provider"] = provider
            cert["domain"] = domain
            cert["cert_mode"] = mode
            cert["cert_dir"] = str(cert_dir)
            cert["cert_chain_path"] = str(cert_dir / "ip.crt")
            cert["private_key_path"] = str(cert_dir / "ip.key")
            cert["system_verifiable"] = mode in ("letsencrypt", "zerossl")

            if state.get("hosts", {}).get("main_hosts"):
                state["hosts"]["main_hosts"][0]["hostname"] = domain
                state["hosts"]["main_hosts"][0]["cert_chain_path"] = cert["cert_chain_path"]
                state["hosts"]["main_hosts"][0]["private_key_path"] = cert["private_key_path"]

            script_path = BASE_DIR / "issue_cert.sh"
            cmd = [
                "bash",
                str(script_path),
                "--ip",
                vps_ip,
                "--domain",
                domain,
                "--cert-dir",
                str(cert_dir),
                "--mode",
                mode,
            ]
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            # If Let's Encrypt standalone failed in sandbox/offline environment, auto-generate ECC cert so files exist
            if proc.returncode != 0 and not (cert_dir / "ip.crt").exists():
                ensure_default_certificate(cert_dir, domain, vps_ip)
                cert["system_verifiable"] = False

            files = save_state(state)
            status = get_runtime_status(state)
            exports = [build_client_export(state, c["username"]) for c in state.get("clients", [])]
            self._send_json(
                {
                    "ok": True,
                    "returncode": proc.returncode,
                    "log": proc.stdout,
                    "state": state,
                    "files": files,
                    "status": status,
                    "exports": exports,
                }
            )
            return

        if path == "/api/cert/upload":
            state = load_state()
            cert_pem = body.get("cert_pem", "").strip()
            key_pem = body.get("key_pem", "").strip()
            domain = body.get("domain") or state["cert"]["domain"]
            if not cert_pem or not key_pem:
                self._send_json({"ok": False, "error": "证书内容与私钥内容不能为空"}, status=400)
                return
            cert_dir = get_cert_dir()
            c_path = cert_dir / "ip.crt"
            k_path = cert_dir / "ip.key"
            c_path.write_text(cert_pem + "\n", encoding="utf-8")
            k_path.write_text(key_pem + "\n", encoding="utf-8")
            state["cert"]["domain"] = domain
            state["cert"]["cert_chain_path"] = str(c_path)
            state["cert"]["private_key_path"] = str(k_path)
            if state.get("hosts", {}).get("main_hosts"):
                state["hosts"]["main_hosts"][0]["hostname"] = domain
                state["hosts"]["main_hosts"][0]["cert_chain_path"] = str(c_path)
                state["hosts"]["main_hosts"][0]["private_key_path"] = str(k_path)
            files = save_state(state)
            status = get_runtime_status(state)
            exports = [build_client_export(state, c["username"]) for c in state.get("clients", [])]
            self._send_json(
                {
                    "ok": True,
                    "message": "自定义证书与私钥已写入并生效",
                    "state": state,
                    "files": files,
                    "status": status,
                    "exports": exports,
                }
            )
            return

        if path == "/api/service":
            action = body.get("action", "reload")
            state = load_state()
            files = save_state(state)
            logs: List[str] = []

            if action == "reload_hosts":
                r = subprocess.run(
                    ["sh", "-c", "systemctl reload trusttunnel 2>/dev/null || kill -HUP $(pidof trusttunnel_endpoint) 2>/dev/null || echo 'SIGHUP signal prepared (endpoint service not active in container)'"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                logs.append(r.stdout.strip() or "已向 TrustTunnel 发送 SIGHUP 热重载信号")
            elif action in ("start", "restart", "stop"):
                tt_dir_str = files["tt_dir"]
                r = subprocess.run(
                    ["sh", "-c", f"systemctl {action} trusttunnel 2>&1 || echo '已在配置目录 {tt_dir_str} 生成最新配置 (Systemd 服务将在 VPS 宿主机执行 {action})'"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                logs.append(r.stdout.strip())
            elif action == "install_endpoint":
                r = subprocess.run(
                    ["sh", "-c", "curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s - -a y 2>&1"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=90,
                )
                logs.append(r.stdout.strip())

            status = get_runtime_status(state)
            self._send_json({"ok": True, "action": action, "log": "\n".join(logs), "status": status})
            return

        self._send_json({"ok": False, "error": f"Unknown endpoint: {path}"}, status=404)


def run_servers(host: str, port: int, camouflage_port: int) -> None:
    state = load_state()
    state["meta"]["camouflage_port"] = camouflage_port
    save_state(state)

    # Start Camouflage Static Origin Server in background thread
    try:
        cam_server = ThreadedHTTPServer((host, camouflage_port), CamouflageHTTPHandler)
        cam_thread = threading.Thread(target=cam_server.serve_forever, daemon=True)
        cam_thread.start()
        print(f"[Camouflage Origin] Serving active static HTML site on http://{host}:{camouflage_port}")
    except OSError as e:
        print(f"[Camouflage Origin] Warning: Could not bind port {camouflage_port}: {e}")

    panel_server = ThreadedHTTPServer((host, port), PanelHTTPHandler)
    print(f"[TrustTunnel Web Panel] Listening on http://{host}:{port}")
    panel_server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="TrustTunnel Web Configuration & Camouflage Panel")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8880, help="Web panel port (default: 8880)")
    parser.add_argument(
        "--camouflage-port",
        type=int,
        default=8080,
        help="Local camouflage static HTML origin port (default: 8080)",
    )
    args = parser.parse_args()
    run_servers(args.host, args.port, args.camouflage_port)


if __name__ == "__main__":
    main()
