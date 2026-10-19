/* TrustTunnel Web Configuration & Camouflage Panel Frontend Logic */

let APP_STATE = null;
let APP_EXPORTS = [];
let APP_FILES = {};
let APP_STATUS = {};

function showToast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.borderColor = isError ? '#f43f5e' : '#38bdf8';
  el.style.display = 'block';
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => {
    el.style.display = 'none';
  }, 3200);
}

function renderQR(containerEl, text) {
  if (!containerEl || !text) return;
  try {
    if (typeof qrcode === 'function') {
      const qr = qrcode(0, 'L');
      qr.addData(text);
      qr.make();
      containerEl.innerHTML = qr.createSvgTag({ cellSize: 3, margin: 2, scalable: true });
      const svg = containerEl.querySelector('svg');
      if (svg) {
        svg.style.width = '180px';
        svg.style.height = '180px';
        svg.style.display = 'block';
      }
      return;
    }
  } catch (e) {
    // Fallback if payload exceeds QR version 40
    console.warn('QR fallback:', e);
  }
  containerEl.innerHTML = `<div style="width:180px;height:180px;display:flex;align-items:center;justify-content:center;color:#0f172a;font-size:0.78rem;text-align:center;padding:12px;">二维码已生成<br/>请直接复制右侧 tt:// 链接导入</div>`;
}

function switchTab(tabId) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  const target = document.getElementById(tabId);
  if (target) target.classList.add('active');

  document.querySelectorAll('.nav-btn, .mobile-nav button').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
}

window.switchTab = switchTab;

function copyString(str, label = '内容') {
  navigator.clipboard.writeText(str).then(() => {
    showToast(`✅ 已复制${label}到剪贴板`);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = str;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    showToast(`✅ 已复制${label}到剪贴板`);
  });
}

function copyText(elementId) {
  const el = document.getElementById(elementId);
  if (el) copyString(el.textContent, '配置内容');
}
window.copyText = copyText;

function downloadFile(filename, content) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function populateUI() {
  if (!APP_STATE) return;
  const s = APP_STATE;
  const cert = s.cert || {};
  const cam = s.camouflage || {};
  const vpn = s.vpn || {};
  const lp = vpn.listen_protocols || {};
  const fp = vpn.forward_protocol || {};
  const icmp = vpn.icmp || {};
  const metrics = vpn.metrics || {};
  const sub = vpn.subscription || {};
  const mainHost = ((s.hosts || {}).main_hosts || [{}])[0] || {};
  const rules = s.rules || {};

  // Top bar pills
  document.getElementById('st-cert-domain').textContent = cert.domain || '未设置';
  const presetMap = {
    stealth_max: '🛡️ 旗舰抗 DPI 混淆',
    quic_turbo: '⚡ 极速 QUIC 流媒体',
    compat_http2: '🌐 高兼容 HTTP/2'
  };
  document.getElementById('st-preset-label').textContent = presetMap[(s.meta || {}).obfuscation_preset] || '自定义混淆';

  // Tab 1: Wizard
  document.getElementById('wiz-vps-ip').value = cert.vps_ip || '';
  document.getElementById('wiz-domain').value = cert.domain || '';
  document.getElementById('wiz-cert-mode').value = cert.cert_mode || 'letsencrypt';

  document.querySelectorAll('[data-preset]').forEach(card => {
    card.classList.toggle('selected', card.dataset.preset === (s.meta || {}).obfuscation_preset);
  });

  document.querySelectorAll('.cam-tpl-card').forEach(card => {
    card.classList.toggle('selected', card.dataset.tpl === cam.template);
  });

  // Populate primary export in Wizard
  if (APP_EXPORTS.length > 0) {
    const exp0 = APP_EXPORTS[0];
    document.getElementById('wiz-deeplink-text').textContent = exp0.deeplink;
    const subUrl = `${window.location.origin}/subscription?user=${encodeURIComponent(exp0.username)}`;
    document.getElementById('wiz-sub-url').value = exp0.subscription_url || subUrl;
    renderQR(document.getElementById('wiz-qr-box'), exp0.deeplink);
  }

  // Tab 2: Users
  renderUsersList();

  // Tab 3: Camouflage & Reverse Proxy
  document.querySelectorAll('.arch-card').forEach(card => {
    card.classList.toggle('selected', card.dataset.arch === cam.architecture);
  });
  document.getElementById('cam-enabled').checked = cam.enabled !== false;
  document.getElementById('cam-listen-addr').value = cam.listen_address || '127.0.0.1:8080';
  document.getElementById('cam-path-mask').value = cam.path_mask || '/';
  document.getElementById('cam-h3-compat').checked = !!cam.h3_backward_compatibility;
  document.getElementById('cam-custom-html').value = cam.custom_html || '';
  const iframe = document.getElementById('cam-preview-iframe');
  if (iframe && iframe.dataset.loadedTpl !== cam.template) {
    iframe.src = `/camouflage/${cam.template || 'tetris'}`;
    iframe.dataset.loadedTpl = cam.template;
  }

  // Tab 4: Certificates & Hosts
  document.getElementById('cert-vps-ip').value = cert.vps_ip || '';
  document.getElementById('cert-nip-provider').value = cert.nip_provider || 'nip.io';
  document.getElementById('cert-domain').value = cert.domain || '';
  document.getElementById('cert-email').value = cert.ssl_email || '';
  document.getElementById('cert-dir').value = cert.cert_dir || '/etc/ssl/ip-certs';
  document.getElementById('cert-mode').value = cert.cert_mode || 'letsencrypt';

  const cInfo = APP_STATUS.certificate || {};
  const certBox = document.getElementById('cert-status-box');
  if (cInfo.exists) {
    certBox.innerHTML =
      `✅ 当前证书文件已就绪: ${cInfo.path}\n` +
      `颁发给 (Subject) : ${cInfo.subject || '-'}\n` +
      `颁发者 (Issuer)  : ${cInfo.issuer || '-'}\n` +
      `有效期 (Validity): ${cInfo.not_before || '-'}  -->  ${cInfo.not_after || '-'}\n` +
      `SHA256 指纹      : ${cInfo.fingerprint || '-'}`;
  } else {
    certBox.textContent = `⚠️ 证书路径尚未生成 (${cInfo.path || ''})，请点击右上角【立即执行证书生成 / 申请】按钮。`;
  }

  document.getElementById('host-main-hostname').value = mainHost.hostname || cert.domain || '';
  document.getElementById('host-allowed-sni').value = (mainHost.allowed_sni || []).join(', ');
  document.getElementById('host-cert-path').value = mainHost.cert_chain_path || cert.cert_chain_path || '';
  document.getElementById('host-key-path').value = mainHost.private_key_path || cert.private_key_path || '';

  // Tab 5: Protocol & Anti-DPI
  document.getElementById('rules-enabled').checked = rules.enabled !== false;
  document.getElementById('rules-default-auth-key').value = rules.default_auth_key || '';
  document.getElementById('rules-default-prefix').value = rules.default_random_prefix || '';
  renderRulesList();

  document.getElementById('vpn-listen-address').value = vpn.listen_address || '0.0.0.0:443';
  document.getElementById('vpn-auth-code').value = String(vpn.auth_failure_status_code || 407);
  document.getElementById('vpn-non-connect-code').value = String(vpn.non_connect_auth_failure_status_code || 404);
  document.getElementById('vpn-max-h2').value = vpn.default_max_http2_conns_per_client ?? 32;
  document.getElementById('vpn-max-h3').value = vpn.default_max_http3_conns_per_client ?? 8;
  document.getElementById('vpn-tls-timeout').value = vpn.tls_handshake_timeout_secs ?? 10;
  document.getElementById('vpn-listener-timeout').value = vpn.client_listener_timeout_secs ?? 600;
  document.getElementById('vpn-conn-timeout').value = vpn.connection_establishment_timeout_secs ?? 30;
  document.getElementById('vpn-tcp-timeout').value = vpn.tcp_connections_timeout_secs ?? 604800;
  document.getElementById('vpn-udp-timeout').value = vpn.udp_connections_timeout_secs ?? 300;
  document.getElementById('vpn-ipv6').checked = vpn.ipv6_available !== false;
  document.getElementById('vpn-private-net').checked = !!vpn.allow_private_network_connections;

  document.getElementById('lp-h1-enable').checked = lp.http1_enabled !== false;
  document.getElementById('lp-h1-buf').value = lp.http1_upload_buffer_size ?? 32768;
  document.getElementById('lp-h2-enable').checked = lp.http2_enabled !== false;
  document.getElementById('lp-h2-conn-win').value = lp.http2_initial_connection_window_size ?? 8388608;
  document.getElementById('lp-h2-stream-win').value = lp.http2_initial_stream_window_size ?? 131072;
  document.getElementById('lp-h2-streams').value = lp.http2_max_concurrent_streams ?? 1000;
  document.getElementById('lp-h2-frame').value = lp.http2_max_frame_size ?? 16384;
  document.getElementById('lp-h2-header').value = lp.http2_header_table_size ?? 65536;
  document.getElementById('lp-quic-enable').checked = lp.quic_enabled !== false;
  document.getElementById('lp-quic-recv-mtu').value = lp.quic_recv_udp_payload_size ?? 1350;
  document.getElementById('lp-quic-send-mtu').value = lp.quic_send_udp_payload_size ?? 1350;
  document.getElementById('lp-quic-max-data').value = lp.quic_initial_max_data ?? 104857600;
  document.getElementById('lp-quic-conn-win').value = lp.quic_max_connection_window ?? 25165824;
  document.getElementById('lp-quic-stream-win').value = lp.quic_max_stream_window ?? 16777216;
  document.getElementById('lp-quic-queue').value = lp.quic_message_queue_capacity ?? 4096;
  document.getElementById('lp-quic-early').checked = lp.quic_enable_early_data !== false;
  document.getElementById('lp-quic-migration').checked = lp.quic_disable_active_migration !== false;

  document.getElementById('fp-mode').value = fp.mode || 'direct';
  document.getElementById('fp-socks5-addr').value = fp.socks5_address || '127.0.0.1:1080';
  document.getElementById('fp-socks5-auth').checked = !!fp.socks5_extended_auth;

  document.getElementById('icmp-enabled').checked = !!icmp.enabled;
  document.getElementById('icmp-iface').value = icmp.interface_name || 'eth0';
  document.getElementById('icmp-timeout').value = icmp.request_timeout_secs ?? 3;

  document.getElementById('sub-enabled').checked = !!sub.enabled;
  document.getElementById('sub-path').value = sub.path || '/subscription';
  document.getElementById('metrics-enabled').checked = metrics.enabled !== false;
  document.getElementById('metrics-per-client').checked = metrics.per_client_metrics !== false;
  document.getElementById('metrics-addr').value = metrics.address || '127.0.0.1:1987';
  document.getElementById('vpn-ping-enable').checked = !!vpn.ping_enable;
  document.getElementById('vpn-speedtest-enable').checked = !!vpn.speedtest_enable;

  // Tab 6: Raw Config Files
  document.getElementById('files-tt-dir').textContent = APP_FILES.tt_dir || '/opt/trusttunnel';
  document.getElementById('raw-vpn-toml').textContent = APP_FILES.vpn_toml || '';
  document.getElementById('raw-hosts-toml').textContent = APP_FILES.hosts_toml || '';
  document.getElementById('raw-rules-toml').textContent = APP_FILES.rules_toml || '';
  document.getElementById('raw-creds-toml').textContent = APP_FILES.credentials_toml || '';
  document.getElementById('raw-nginx-conf').textContent =
    `# === Nginx 伪装配置 ===\n${APP_FILES.nginx_conf || ''}\n\n# === Caddyfile 伪装配置 ===\n${APP_FILES.caddyfile || ''}`;
  document.getElementById('raw-issue-cert').textContent = APP_FILES.issue_cert_sh || '';
}

function renderUsersList() {
  const container = document.getElementById('users-list-container');
  const clients = APP_STATE.clients || [];
  container.innerHTML = clients.map((c, idx) => {
    const exp = APP_EXPORTS.find(e => e.username === c.username) || APP_EXPORTS[0] || {};
    return `
      <div style="background:var(--bg-input);border:1px solid var(--border);border-radius:14px;padding:16px;">
        <div class="form-grid" style="margin-bottom:12px;">
          <div class="field">
            <label>用户名 (username)</label>
            <input type="text" value="${c.username || ''}" onchange="updateClientField(${idx}, 'username', this.value)" />
          </div>
          <div class="field">
            <label>密码 (password)</label>
            <input type="text" value="${c.password || ''}" onchange="updateClientField(${idx}, 'password', this.value)" />
          </div>
          <div class="field">
            <label>传输协议 (upstream_protocol)</label>
            <select onchange="updateClientField(${idx}, 'upstream_protocol', this.value)">
              <option value="http3" ${c.upstream_protocol === 'http3' ? 'selected' : ''}>HTTP/3 (QUIC 极速抗封锁)</option>
              <option value="http2" ${c.upstream_protocol === 'http2' ? 'selected' : ''}>HTTP/2 (TCP 标准高兼容)</option>
            </select>
          </div>
          <div class="field">
            <label>自定义伪装 SNI (可选)</label>
            <input type="text" value="${c.custom_sni || ''}" placeholder="留空默认使用主域名" onchange="updateClientField(${idx}, 'custom_sni', this.value)" />
          </div>
          <div class="field">
            <label>最大 H2 / H3 连接数</label>
            <div style="display:flex;gap:8px;">
              <input type="number" value="${c.max_http2_conns || 32}" onchange="updateClientField(${idx}, 'max_http2_conns', Number(this.value))" title="Max HTTP/2" />
              <input type="number" value="${c.max_http3_conns || 8}" onchange="updateClientField(${idx}, 'max_http3_conns', Number(this.value))" title="Max HTTP/3" />
            </div>
          </div>
          <div class="switch-row">
            <span>客户端 Anti-DPI 混淆</span>
            <input type="checkbox" ${c.anti_dpi !== false ? 'checked' : ''} onchange="updateClientField(${idx}, 'anti_dpi', this.checked)" />
          </div>
          <div class="switch-row">
            <span>绑定 TLS 握手机密密钥 (auth_key)</span>
            <input type="checkbox" ${c.use_auth_key ? 'checked' : ''} onchange="updateClientField(${idx}, 'use_auth_key', this.checked)" />
          </div>
          <div class="switch-row">
            <span>绑定 ClientRandom 掩码前缀</span>
            <input type="checkbox" ${c.use_random_prefix ? 'checked' : ''} onchange="updateClientField(${idx}, 'use_random_prefix', this.checked)" />
          </div>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;padding-top:10px;border-top:1px dashed var(--border);">
          <div style="display:flex;gap:8px;flex-wrap:wrap;">
            <button class="btn btn-sm" onclick="copyUserDeeplink(${idx})">📋 复制 tt:// 链接</button>
            <button class="btn btn-secondary btn-sm" onclick="downloadUserToml(${idx})">⬇️ 下载 .toml 配置</button>
          </div>
          ${clients.length > 1 ? `<button class="btn btn-danger btn-sm" onclick="removeUser(${idx})">🗑️ 删除账号</button>` : ''}
        </div>
      </div>
    `;
  }).join('');
}

window.updateClientField = (idx, field, val) => {
  APP_STATE.clients[idx][field] = val;
  if (field === 'use_auth_key' && val) APP_STATE.clients[idx].use_random_prefix = false;
  if (field === 'use_random_prefix' && val) APP_STATE.clients[idx].use_auth_key = false;
  saveAllState();
};

window.copyUserDeeplink = idx => {
  const c = APP_STATE.clients[idx];
  const exp = APP_EXPORTS.find(e => e.username === c.username) || APP_EXPORTS[0];
  if (exp) copyString(exp.deeplink, `${c.username} 的 tt:// 链接`);
};

window.downloadUserToml = idx => {
  const c = APP_STATE.clients[idx];
  const exp = APP_EXPORTS.find(e => e.username === c.username) || APP_EXPORTS[0];
  if (exp) downloadFile(`trusttunnel_${c.username}.toml`, exp.toml);
};

window.removeUser = idx => {
  APP_STATE.clients.splice(idx, 1);
  saveAllState();
};

function renderRulesList() {
  const container = document.getElementById('rules-list-container');
  const items = (APP_STATE.rules && APP_STATE.rules.items) || [];
  container.innerHTML = items.map((r, idx) => `
    <div style="display:grid;grid-template-columns:1fr 1.4fr 1.4fr 120px auto;gap:10px;align-items:center;background:var(--bg-input);padding:10px 12px;border-radius:10px;border:1px solid var(--border);">
      <input type="text" placeholder="CIDR (如 192.168.1.0/24 或留空)" value="${r.cidr || ''}" onchange="updateRuleField(${idx}, 'cidr', this.value)" />
      <input type="text" placeholder="client_random_auth_key (32位Hex)" value="${r.client_random_auth_key || ''}" onchange="updateRuleField(${idx}, 'client_random_auth_key', this.value)" />
      <input type="text" placeholder="client_random_prefix (如 a0b0/f0f0)" value="${r.client_random_prefix || ''}" onchange="updateRuleField(${idx}, 'client_random_prefix', this.value)" />
      <select onchange="updateRuleField(${idx}, 'action', this.value)">
        <option value="allow" ${r.action === 'allow' ? 'selected' : ''}>allow 放行</option>
        <option value="deny" ${r.action === 'deny' ? 'selected' : ''}>deny 拦截</option>
      </select>
      <button class="btn btn-danger btn-sm" onclick="removeRule(${idx})">删除</button>
    </div>
  `).join('');
}

window.updateRuleField = (idx, field, val) => {
  APP_STATE.rules.items[idx][field] = val;
};

window.removeRule = idx => {
  APP_STATE.rules.items.splice(idx, 1);
  renderRulesList();
};

function collectFormIntoState() {
  if (!APP_STATE) return;
  const s = APP_STATE;

  s.cert.vps_ip = document.getElementById('cert-vps-ip').value.trim() || document.getElementById('wiz-vps-ip').value.trim();
  s.cert.nip_provider = document.getElementById('cert-nip-provider').value;
  s.cert.domain = document.getElementById('cert-domain').value.trim() || document.getElementById('wiz-domain').value.trim();
  s.cert.ssl_email = document.getElementById('cert-email').value.trim();
  s.cert.cert_dir = document.getElementById('cert-dir').value.trim();
  s.cert.cert_mode = document.getElementById('cert-mode').value;

  s.camouflage.enabled = document.getElementById('cam-enabled').checked;
  s.camouflage.listen_address = document.getElementById('cam-listen-addr').value.trim();
  s.camouflage.path_mask = document.getElementById('cam-path-mask').value.trim() || '/';
  s.camouflage.h3_backward_compatibility = document.getElementById('cam-h3-compat').checked;
  s.camouflage.custom_html = document.getElementById('cam-custom-html').value;

  if (s.hosts && s.hosts.main_hosts && s.hosts.main_hosts[0]) {
    s.hosts.main_hosts[0].hostname = document.getElementById('host-main-hostname').value.trim() || s.cert.domain;
    s.hosts.main_hosts[0].allowed_sni = document.getElementById('host-allowed-sni').value
      .split(',')
      .map(x => x.trim())
      .filter(Boolean);
    s.hosts.main_hosts[0].cert_chain_path = document.getElementById('host-cert-path').value.trim();
    s.hosts.main_hosts[0].private_key_path = document.getElementById('host-key-path').value.trim();
  }

  s.rules.enabled = document.getElementById('rules-enabled').checked;
  s.rules.default_auth_key = document.getElementById('rules-default-auth-key').value.trim();
  s.rules.default_random_prefix = document.getElementById('rules-default-prefix').value.trim();

  const vpn = s.vpn;
  vpn.listen_address = document.getElementById('vpn-listen-address').value.trim();
  vpn.auth_failure_status_code = Number(document.getElementById('vpn-auth-code').value);
  vpn.non_connect_auth_failure_status_code = Number(document.getElementById('vpn-non-connect-code').value);
  vpn.default_max_http2_conns_per_client = Number(document.getElementById('vpn-max-h2').value);
  vpn.default_max_http3_conns_per_client = Number(document.getElementById('vpn-max-h3').value);
  vpn.tls_handshake_timeout_secs = Number(document.getElementById('vpn-tls-timeout').value);
  vpn.client_listener_timeout_secs = Number(document.getElementById('vpn-listener-timeout').value);
  vpn.connection_establishment_timeout_secs = Number(document.getElementById('vpn-conn-timeout').value);
  vpn.tcp_connections_timeout_secs = Number(document.getElementById('vpn-tcp-timeout').value);
  vpn.udp_connections_timeout_secs = Number(document.getElementById('vpn-udp-timeout').value);
  vpn.ipv6_available = document.getElementById('vpn-ipv6').checked;
  vpn.allow_private_network_connections = document.getElementById('vpn-private-net').checked;

  const lp = vpn.listen_protocols;
  lp.http1_enabled = document.getElementById('lp-h1-enable').checked;
  lp.http1_upload_buffer_size = Number(document.getElementById('lp-h1-buf').value);
  lp.http2_enabled = document.getElementById('lp-h2-enable').checked;
  lp.http2_initial_connection_window_size = Number(document.getElementById('lp-h2-conn-win').value);
  lp.http2_initial_stream_window_size = Number(document.getElementById('lp-h2-stream-win').value);
  lp.http2_max_concurrent_streams = Number(document.getElementById('lp-h2-streams').value);
  lp.http2_max_frame_size = Number(document.getElementById('lp-h2-frame').value);
  lp.http2_header_table_size = Number(document.getElementById('lp-h2-header').value);
  lp.quic_enabled = document.getElementById('lp-quic-enable').checked;
  lp.quic_recv_udp_payload_size = Number(document.getElementById('lp-quic-recv-mtu').value);
  lp.quic_send_udp_payload_size = Number(document.getElementById('lp-quic-send-mtu').value);
  lp.quic_initial_max_data = Number(document.getElementById('lp-quic-max-data').value);
  lp.quic_max_connection_window = Number(document.getElementById('lp-quic-conn-win').value);
  lp.quic_max_stream_window = Number(document.getElementById('lp-quic-stream-win').value);
  lp.quic_message_queue_capacity = Number(document.getElementById('lp-quic-queue').value);
  lp.quic_enable_early_data = document.getElementById('lp-quic-early').checked;
  lp.quic_disable_active_migration = document.getElementById('lp-quic-migration').checked;

  vpn.forward_protocol.mode = document.getElementById('fp-mode').value;
  vpn.forward_protocol.socks5_address = document.getElementById('fp-socks5-addr').value.trim();
  vpn.forward_protocol.socks5_extended_auth = document.getElementById('fp-socks5-auth').checked;

  vpn.icmp.enabled = document.getElementById('icmp-enabled').checked;
  vpn.icmp.interface_name = document.getElementById('icmp-iface').value.trim();
  vpn.icmp.request_timeout_secs = Number(document.getElementById('icmp-timeout').value);

  vpn.subscription.enabled = document.getElementById('sub-enabled').checked;
  vpn.subscription.path = document.getElementById('sub-path').value.trim() || '/subscription';
  vpn.subscription.hostname = s.cert.domain;
  vpn.subscription.address = `${s.cert.vps_ip}:443`;

  vpn.metrics.enabled = document.getElementById('metrics-enabled').checked;
  vpn.metrics.per_client_metrics = document.getElementById('metrics-per-client').checked;
  vpn.metrics.address = document.getElementById('metrics-addr').value.trim();
  vpn.ping_enable = document.getElementById('vpn-ping-enable').checked;
  vpn.speedtest_enable = document.getElementById('vpn-speedtest-enable').checked;
}

async function fetchState() {
  const res = await fetch('/api/state');
  const data = await res.json();
  if (data.ok) {
    APP_STATE = data.state;
    APP_FILES = data.files;
    APP_STATUS = data.status;
    APP_EXPORTS = data.exports;
    populateUI();
  }
}

async function saveAllState(customMsg) {
  collectFormIntoState();
  const res = await fetch('/api/state', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(APP_STATE)
  });
  const data = await res.json();
  if (data.ok) {
    APP_STATE = data.state;
    APP_FILES = data.files;
    APP_STATUS = data.status;
    APP_EXPORTS = data.exports;
    populateUI();
    showToast(customMsg || data.message || '✅ 配置已保存并生效');
  } else {
    showToast(data.error || '保存失败', true);
  }
}

async function controlService(action) {
  const res = await fetch('/api/service', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action })
  });
  const data = await res.json();
  const logBox = document.getElementById('service-log-box');
  if (logBox) {
    logBox.style.display = 'block';
    logBox.textContent = data.log || '执行完成';
  }
  showToast(`✅ 服务操作 [${action}] 已执行`);
}
window.controlService = controlService;

document.addEventListener('DOMContentLoaded', () => {
  fetchState();

  // Tab navigation
  document.querySelectorAll('.nav-btn, .mobile-nav button').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
  });

  // Sync wizard IP -> domain
  const wizIp = document.getElementById('wiz-vps-ip');
  const wizDomain = document.getElementById('wiz-domain');
  wizIp.addEventListener('input', () => {
    const ip = wizIp.value.trim();
    if (ip) {
      wizDomain.value = `${ip}.nip.io`;
      document.getElementById('cert-vps-ip').value = ip;
      document.getElementById('cert-domain').value = `${ip}.nip.io`;
    }
  });

  document.getElementById('cert-vps-ip').addEventListener('input', e => {
    const ip = e.target.value.trim();
    const prov = document.getElementById('cert-nip-provider').value || 'nip.io';
    if (ip) {
      document.getElementById('cert-domain').value = `${ip}.${prov}`;
      wizIp.value = ip;
      wizDomain.value = `${ip}.${prov}`;
    }
  });

  // Auto-detect IP
  document.getElementById('wiz-detect-ip-btn').addEventListener('click', async () => {
    const res = await fetch('/api/detect-ip');
    const data = await res.json();
    if (data.ip) {
      wizIp.value = data.ip;
      wizDomain.value = `${data.ip}.nip.io`;
      document.getElementById('cert-vps-ip').value = data.ip;
      document.getElementById('cert-domain').value = `${data.ip}.nip.io`;
      showToast(`🔍 已检测到公网 IP: ${data.ip}`);
    }
  });

  // Obfuscation Preset Cards
  document.querySelectorAll('[data-preset]').forEach(card => {
    card.addEventListener('click', async () => {
      const preset = card.dataset.preset;
      const res = await fetch('/api/preset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset })
      });
      const data = await res.json();
      if (data.ok) {
        APP_STATE = data.state;
        APP_FILES = data.files;
        APP_EXPORTS = data.exports;
        populateUI();
        showToast(data.message);
      }
    });
  });

  // Camouflage Template Cards
  document.querySelectorAll('.cam-tpl-card').forEach(card => {
    card.addEventListener('click', () => {
      if (!APP_STATE) return;
      APP_STATE.camouflage.template = card.dataset.tpl;
      saveAllState(`🎭 已切换伪装网站为：${card.querySelector('h4').textContent}`);
    });
  });

  // Reverse Proxy Architecture Cards
  document.querySelectorAll('.arch-card').forEach(card => {
    card.addEventListener('click', () => {
      if (!APP_STATE) return;
      APP_STATE.camouflage.architecture = card.dataset.arch;
      saveAllState(`🏗️ 已切换反代架构模式`);
    });
  });

  document.getElementById('use-custom-html-btn').addEventListener('click', () => {
    if (!APP_STATE) return;
    APP_STATE.camouflage.template = 'custom';
    saveAllState('🎨 已切换为自定义单页 HTML 伪装');
  });

  // Save buttons
  document.getElementById('save-all-btn').addEventListener('click', () => saveAllState());
  document.getElementById('wiz-apply-btn').addEventListener('click', () => {
    document.getElementById('cert-vps-ip').value = wizIp.value.trim();
    document.getElementById('cert-domain').value = wizDomain.value.trim();
    document.getElementById('cert-mode').value = document.getElementById('wiz-cert-mode').value;
    saveAllState('🚀 节点配置已生成，请直接扫码或复制链接连接！');
  });

  // Copy & Download in Wizard
  document.getElementById('copy-wiz-deeplink').addEventListener('click', () => {
    copyString(document.getElementById('wiz-deeplink-text').textContent, 'tt:// 节点链接');
  });
  document.getElementById('copy-wiz-sub').addEventListener('click', () => {
    copyString(document.getElementById('wiz-sub-url').value, 'HTTPS 订阅链接');
  });
  document.getElementById('download-wiz-toml').addEventListener('click', () => {
    if (APP_EXPORTS.length > 0) {
      downloadFile('trusttunnel_client.toml', APP_EXPORTS[0].toml);
    }
  });

  // Issue Certificate buttons
  async function triggerIssueCert(fromWiz = false) {
    const vps_ip = fromWiz ? wizIp.value.trim() : document.getElementById('cert-vps-ip').value.trim();
    const domain = fromWiz ? wizDomain.value.trim() : document.getElementById('cert-domain').value.trim();
    const cert_mode = fromWiz ? document.getElementById('wiz-cert-mode').value : document.getElementById('cert-mode').value;
    showToast('⏳ 正在执行证书签发与安装...');
    const res = await fetch('/api/cert/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ vps_ip, domain, cert_mode: cert_mode === 'custom' ? 'selfsigned' : cert_mode })
    });
    const data = await res.json();
    if (data.ok) {
      APP_STATE = data.state;
      APP_FILES = data.files;
      APP_STATUS = data.status;
      APP_EXPORTS = data.exports;
      populateUI();
      const logEl = document.getElementById('cert-exec-log');
      if (logEl) {
        logEl.style.display = 'block';
        logEl.textContent = data.log || '证书生成完成';
      }
      showToast('🔒 证书签发与配置同步完成！');
    }
  }

  document.getElementById('wiz-issue-cert-btn').addEventListener('click', () => triggerIssueCert(true));
  document.getElementById('cert-run-script-btn').addEventListener('click', () => triggerIssueCert(false));

  // Upload Custom Cert
  document.getElementById('upload-cert-btn').addEventListener('click', async () => {
    const cert_pem = document.getElementById('custom-cert-pem').value.trim();
    const key_pem = document.getElementById('custom-key-pem').value.trim();
    const domain = document.getElementById('cert-domain').value.trim();
    const res = await fetch('/api/cert/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cert_pem, key_pem, domain })
    });
    const data = await res.json();
    if (data.ok) {
      APP_STATE = data.state;
      APP_FILES = data.files;
      APP_STATUS = data.status;
      APP_EXPORTS = data.exports;
      populateUI();
      showToast(data.message);
    } else {
      showToast(data.error || '上传失败', true);
    }
  });

  // Hot reload hosts
  document.getElementById('hot-reload-hosts-btn').addEventListener('click', async () => {
    await saveAllState();
    await controlService('reload_hosts');
  });

  // Add user
  document.getElementById('add-user-btn').addEventListener('click', () => {
    APP_STATE.clients.push({
      username: `user_${APP_STATE.clients.length + 1}`,
      password: randomHex(8),
      max_http2_conns: 32,
      max_http3_conns: 8,
      upstream_protocol: 'http3',
      anti_dpi: true,
      custom_sni: '',
      use_auth_key: false,
      use_random_prefix: false,
      dns_upstreams: ['https://1.1.1.1/dns-query', 'tls://1.1.1.1']
    });
    saveAllState('➕ 已新增客户端账号');
  });

  // Decode DeepLink
  document.getElementById('decode-dl-btn').addEventListener('click', async () => {
    const uri = document.getElementById('decode-dl-input').value.trim() ||
      (APP_EXPORTS[0] && APP_EXPORTS[0].deeplink) || '';
    document.getElementById('decode-dl-input').value = uri;
    const res = await fetch('/api/deeplink/decode', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ uri })
    });
    const data = await res.json();
    const out = document.getElementById('decode-dl-output');
    out.style.display = 'block';
    out.textContent = data.ok ? JSON.stringify(data.decoded, null, 2) : data.error;
  });

  // Rules controls
  document.getElementById('regen-auth-key-btn').addEventListener('click', () => {
    const newKey = randomHex(16);
    document.getElementById('rules-default-auth-key').value = newKey;
    if (APP_STATE.rules.items.length > 0 && APP_STATE.rules.items[0].client_random_auth_key) {
      APP_STATE.rules.items[0].client_random_auth_key = newKey;
    }
    saveAllState('🎲 已生成全新 32 位 SNI 握手机密密钥');
  });

  document.getElementById('add-rule-btn').addEventListener('click', () => {
    APP_STATE.rules.items.push({
      id: `rule-${Date.now()}`,
      cidr: '',
      client_random_prefix: `${randomHex(4)}/f0f0f0f0`,
      client_random_auth_key: '',
      action: 'allow'
    });
    renderRulesList();
  });
});
