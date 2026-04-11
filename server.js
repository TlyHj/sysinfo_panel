const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');
const INITIAL_PASSWORD_PATH = path.join(DATA_DIR, 'initial-password.txt');
const ALERTS_STATE_PATH = path.join(DATA_DIR, 'alerts-state.json');
const FORCE_PUBLIC_IP = '8.137.127.174';
const PORT = Number.parseInt(process.env.PORT || '18888', 10);
const HOST = process.env.HOST || '127.0.0.1';
const BASE_PATH = process.env.BASE_PATH || '/sysinfo';
const SESSION_COOKIE = 'sysinfo_panel_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DEFAULT_USERNAME = 'admin';
const DEFAULT_PASSWORD = '123456';

function run(cmd) {
  try {
    return execSync(cmd, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      timeout: 5000,
    }).trim();
  } catch {
    return 'N/A';
  }
}

function htmlEscape(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return 'N/A';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let n = bytes;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function truncateMiddle(str, max = 42) {
  const s = String(str || '');
  if (s.length <= max) return s;
  const keep = Math.max(8, Math.floor((max - 3) / 2));
  return `${s.slice(0, keep)}...${s.slice(-keep)}`;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function ensureRuntimeFiles() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(path.join(ROOT, 'logs'), { recursive: true });
  if (!fs.existsSync(CONFIG_PATH)) {
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = hashPassword(DEFAULT_PASSWORD, salt);
    fs.writeFileSync(CONFIG_PATH, JSON.stringify({
      username: DEFAULT_USERNAME,
      salt,
      passwordHash,
    }, null, 2));
  }
  if (!fs.existsSync(INITIAL_PASSWORD_PATH)) {
    fs.writeFileSync(INITIAL_PASSWORD_PATH, `${DEFAULT_PASSWORD}\n`);
  }
  if (!fs.existsSync(ALERTS_STATE_PATH)) {
    fs.writeFileSync(ALERTS_STATE_PATH, JSON.stringify({ acknowledged: {}, recovered: [] }, null, 2));
  }
}

function readAlertsState() {
  ensureRuntimeFiles();
  try {
    const raw = fs.readFileSync(ALERTS_STATE_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      acknowledged: parsed && typeof parsed.acknowledged === 'object' && parsed.acknowledged ? parsed.acknowledged : {},
      recovered: Array.isArray(parsed?.recovered) ? parsed.recovered : [],
    };
  } catch {
    return { acknowledged: {}, recovered: [] };
  }
}

function writeAlertsState(state) {
  ensureRuntimeFiles();
  fs.writeFileSync(ALERTS_STATE_PATH, JSON.stringify({
    acknowledged: state?.acknowledged || {},
    recovered: Array.isArray(state?.recovered) ? state.recovered.slice(0, 50) : [],
  }, null, 2));
}

function getAlertId(item) {
  return crypto.createHash('sha1').update(`${item.level}|${item.text}`).digest('hex').slice(0, 12);
}

function acknowledgeAlertById(id) {
  const state = readAlertsState();
  state.acknowledged[id] = { at: Date.now() };
  writeAlertsState(state);
}

function readAuthConfig() {
  ensureRuntimeFiles();
  const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
  const parsed = JSON.parse(raw);
  return {
    username: parsed.username || DEFAULT_USERNAME,
    salt: parsed.salt,
    passwordHash: parsed.passwordHash,
  };
}

function verifyPassword(password) {
  const config = readAuthConfig();
  const candidate = hashPassword(password, config.salt);
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(config.passwordHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function getSessionSecret() {
  return readAuthConfig().passwordHash;
}

function createSessionValue(username) {
  const payload = Buffer.from(JSON.stringify({
    u: username,
    e: Date.now() + SESSION_TTL_MS,
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', getSessionSecret()).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function verifySessionValue(token) {
  if (!token || !token.includes('.')) return false;
  const [payload, sig] = token.split('.', 2);
  const expected = crypto.createHmac('sha256', getSessionSecret()).update(payload).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!decoded || decoded.e < Date.now()) return false;
    return decoded.u === readAuthConfig().username;
  } catch {
    return false;
  }
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    out[key] = decodeURIComponent(value);
  }
  return out;
}

function setCookie(res, name, value, maxAgeSeconds) {
  const attrs = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString('utf8');
      if (body.length > 1024 * 1024) {
        reject(new Error('body too large'));
        req.destroy();
      }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function redirect(res, location) {
  res.writeHead(302, { Location: location });
  res.end('');
}

function unauthorized(req, res) {
  const wantsJson = (req.headers.accept || '').includes('application/json');
  if (wantsJson) {
    res.writeHead(401, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }
  redirect(res, `${BASE_PATH}/login`);
}

function isAuthenticated(req) {
  const cookies = parseCookies(req);
  return verifySessionValue(cookies[SESSION_COOKIE]);
}

function getListenSummary() {
  const raw = run("ss -ltn 2>/dev/null | awk 'NR>1 {print $4}' | sort -u | head -n 12");
  if (!raw || raw === 'N/A') return '未知';
  const lines = raw.split('\n').map(s => s.trim()).filter(Boolean);
  return lines.length ? lines.join(' ｜ ') : '未知';
}

function getModuleStatus(key, data) {
  if (key === 'alerts') {
    if (data.alerts.counts.critical > 0) return { text: `${data.alerts.counts.critical} 个严重`, tone: 'danger' };
    if (data.alerts.counts.warn > 0) return { text: `${data.alerts.counts.warn} 个告警`, tone: 'warn' };
    return { text: '正常', tone: 'ok' };
  }
  if (key === 'logs') {
    if (!data.logs || !data.logs.content || data.logs.content === 'N/A') return { text: '无数据', tone: 'warn' };
    if (/error|failed|fatal|panic|crit|emerg|denied/i.test(data.logs.content)) return { text: '有异常', tone: 'warn' };
    return { text: '可查看', tone: 'ok' };
  }
  if (key === 'services') {
    if (!data.serviceDetail || !data.serviceDetail.present) return { text: '无数据', tone: 'warn' };
    if (data.serviceDetail.active !== 'active') return { text: '有异常', tone: 'danger' };
    return { text: '正常', tone: 'ok' };
  }
  if (key === 'docker') {
    if (!data.docker || data.docker === 'N/A') return { text: '无数据', tone: 'warn' };
    if (!(data.dockerContainers || []).length) return { text: '空', tone: 'idle' };
    if (data.dockerDetail && data.dockerDetail.present && data.dockerDetail.state === 'danger') return { text: '有异常', tone: 'danger' };
    const bad = data.dockerContainers.filter(c => c.state === 'danger');
    if (bad.length) return { text: `${bad.length} 异常`, tone: 'danger' };
    return { text: '正常', tone: 'ok' };
  }
  if (key === 'services') {
    const present = (data.services || []).filter(s => s.present);
    if (!present.length) return { text: '无数据', tone: 'warn' };
    const failed = present.filter(s => s.active !== 'active');
    if (failed.length) return { text: `${failed.length} 异常`, tone: 'danger' };
    return { text: '正常', tone: 'ok' };
  }
  if (key === 'network') return { text: data.interfaces.length ? '正常' : '无数据', tone: data.interfaces.length ? 'ok' : 'warn' };
  if (key === 'disk') {
    const bad = (data.diskUsage || []).filter(d => Number.isFinite(d.usePercent) && d.usePercent >= 85);
    if (bad.length) return { text: `${bad.length} 偏高`, tone: bad.some(d => d.usePercent >= 95) ? 'danger' : 'warn' };
    return { text: data.disk && data.disk !== 'N/A' ? '正常' : '无数据', tone: data.disk && data.disk !== 'N/A' ? 'ok' : 'warn' };
  }
  if (key === 'ports') return { text: data.listening && data.listening !== 'N/A' ? '正常' : '无数据', tone: data.listening && data.listening !== 'N/A' ? 'ok' : 'warn' };
  if (key === 'processes') return { text: data.top && data.top !== 'N/A' ? '正常' : '无数据', tone: data.top && data.top !== 'N/A' ? 'ok' : 'warn' };
  if (key === 'sessions') return { text: data.who && data.who !== 'N/A' ? '正常' : '无数据', tone: data.who && data.who !== 'N/A' ? 'ok' : 'warn' };
  if (key === 'logins') return { text: data.lastLogins && data.lastLogins !== 'N/A' ? '正常' : '无数据', tone: data.lastLogins && data.lastLogins !== 'N/A' ? 'ok' : 'warn' };
  return { text: '正常', tone: 'ok' };
}

function formatBeijingTime(date = new Date()) {
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date).replace(/\//g, '-');
}

function getRefreshSeconds(input) {
  const n = Number.parseInt(String(input || ''), 10);
  if (Number.isFinite(n) && n >= 0 && n <= 3600) return n;
  return 15;
}

function formatRefreshLabel(seconds) {
  if (!seconds) return '自动刷新已关闭';
  if (seconds < 60) return `${seconds} 秒自动刷新`;
  if (seconds % 60 === 0) return `${Math.floor(seconds / 60)} 分钟自动刷新`;
  return `${seconds} 秒自动刷新`;
}

function formatPercent(value, total) {
  if (!Number.isFinite(value) || !Number.isFinite(total) || total <= 0) return 'N/A';
  return `${((value / total) * 100).toFixed(1)}%`;
}

function buildRefreshOptions(refreshSeconds) {
  const baseOptions = [0, 5, 30, 60, 300];
  const values = new Set(baseOptions);
  if (refreshSeconds > 0 && !values.has(refreshSeconds)) values.add(refreshSeconds);
  const sorted = Array.from(values).sort((a, b) => a - b);
  return sorted.map(v => `<option value="${v}"${v === refreshSeconds ? ' selected' : ''}>${formatRefreshLabel(v)}</option>`).join('')
    + `<option value="custom">自定义时间</option>`;
}

function parseDiskUsage(raw) {
  if (!raw || raw === 'N/A') return [];
  const lines = raw.split('\n').map(s => s.trim()).filter(Boolean);
  if (lines.length <= 1) return [];
  return lines.slice(1).map(line => {
    const parts = line.split(/\s+/);
    return {
      filesystem: parts[0] || 'unknown',
      size: parts[1] || 'N/A',
      used: parts[2] || 'N/A',
      avail: parts[3] || 'N/A',
      usePercent: Number.parseInt((parts[4] || '').replace('%', ''), 10),
      mount: parts[5] || 'N/A',
    };
  }).filter(item => item.mount !== 'N/A');
}

function parseDockerContainers(raw) {
  if (!raw || raw === 'N/A') return [];
  const lines = raw.split('\n').map(s => s.trimEnd()).filter(Boolean);
  if (lines.length <= 1) return [];
  return lines.slice(1).map(line => {
    const parts = line.split('\t');
    const name = parts[0]?.trim() || 'unknown';
    const image = parts[1]?.trim() || 'N/A';
    const status = parts[2]?.trim() || 'N/A';
    const ports = parts[3]?.trim() || '-';
    const lower = status.toLowerCase();
    const running = lower.startsWith('up');
    const unhealthy = lower.includes('unhealthy');
    const restarting = lower.includes('restarting');
    const exited = lower.startsWith('exited') || lower.startsWith('created') || lower.startsWith('dead');
    let state = 'ok';
    if (unhealthy || restarting || exited) state = 'danger';
    else if (!running) state = 'warn';
    return { name, image, status, ports, running, unhealthy, restarting, exited, state };
  });
}

function getServiceSnapshot() {
  const names = ['openclaw', 'docker', 'nginx', 'ssh', 'fail2ban', 'tailscaled', 'caddy'];
  return names.map(name => {
    const raw = run(`bash -lc 'if systemctl cat ${name}.service >/dev/null 2>&1; then echo "present"; echo "active=$(systemctl is-active ${name}.service 2>/dev/null || true)"; echo "enabled=$(systemctl is-enabled ${name}.service 2>/dev/null || true)"; echo "sub=$(systemctl show ${name}.service -p SubState --value 2>/dev/null || true)"; else echo "missing"; fi'`);
    if (!raw || raw === 'N/A' || raw.startsWith('missing')) {
      return { name, present: false, active: 'missing', enabled: 'N/A', sub: 'N/A' };
    }
    const map = Object.fromEntries(raw.split('\n').slice(1).map(line => {
      const idx = line.indexOf('=');
      return idx === -1 ? [line, ''] : [line.slice(0, idx), line.slice(idx + 1)];
    }));
    return {
      name,
      present: true,
      active: map.active || 'unknown',
      enabled: map.enabled || 'unknown',
      sub: map.sub || 'unknown',
    };
  });
}

function getLogsSnapshot(selected = 'syslog') {
  const sources = [
    { key: 'syslog', label: '系统日志', cmd: "bash -lc 'journalctl -n 120 --no-pager 2>/dev/null || tail -n 120 /var/log/syslog 2>/dev/null || true'" },
    { key: 'openclaw', label: 'OpenClaw', cmd: "bash -lc 'journalctl -u openclaw -n 120 --no-pager 2>/dev/null || true'" },
    { key: 'nginx', label: 'Nginx', cmd: "bash -lc 'journalctl -u nginx -n 120 --no-pager 2>/dev/null || tail -n 120 /var/log/nginx/error.log 2>/dev/null || true'" },
    { key: 'docker', label: 'Docker', cmd: "bash -lc 'journalctl -u docker -n 120 --no-pager 2>/dev/null || true'" },
    { key: 'auth', label: '认证日志', cmd: "bash -lc 'journalctl -t sshd -n 120 --no-pager 2>/dev/null || tail -n 120 /var/log/auth.log 2>/dev/null || true'" },
  ];
  const source = sources.find(item => item.key === selected) || sources[0];
  const content = run(source.cmd) || 'N/A';
  return { selected: source.key, label: source.label, content: content || 'N/A', sources };
}

const MANAGED_SERVICES = ['openclaw', 'docker', 'nginx', 'ssh', 'fail2ban', 'tailscaled', 'caddy'];
const SERVICE_ACTIONS = ['start', 'stop', 'restart'];
const DOCKER_ACTIONS = ['start', 'stop', 'restart'];

function runServiceAction(service, action) {
  if (!MANAGED_SERVICES.includes(service) || !SERVICE_ACTIONS.includes(action)) {
    return { ok: false, message: '非法操作' };
  }
  try {
    execSync(`systemctl ${action} ${service}.service`, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 15000,
    });
    const active = run(`systemctl is-active ${service}.service 2>/dev/null || true`) || 'unknown';
    return { ok: true, message: `${service} 已执行 ${action}，当前状态 ${active}` };
  } catch (err) {
    const stderr = String(err?.stderr || err?.stdout || '').trim();
    return { ok: false, message: stderr || `${service} 执行 ${action} 失败` };
  }
}

function getServiceDetailSnapshot(selected = 'openclaw') {
  const allowed = MANAGED_SERVICES;
  const service = allowed.includes(selected) ? selected : allowed[0];
  const raw = run(`bash -lc 'if systemctl cat ${service}.service >/dev/null 2>&1; then echo "present=yes"; echo "name=${service}"; systemctl show ${service}.service -p Id -p Description -p ActiveState -p SubState -p UnitFileState -p MainPID -p ExecMainStartTimestamp -p FragmentPath --value 2>/dev/null | awk "NR==1{print \"id=\"\$0} NR==2{print \"description=\"\$0} NR==3{print \"active=\"\$0} NR==4{print \"sub=\"\$0} NR==5{print \"enabled=\"\$0} NR==6{print \"mainpid=\"\$0} NR==7{print \"startedAt=\"\$0} NR==8{print \"fragment=\"\$0}"; else echo "present=no"; fi'`);
  const lines = String(raw || '').split('\n').filter(Boolean);
  const map = Object.fromEntries(lines.map(line => {
    const idx = line.indexOf('=');
    return idx === -1 ? [line, ''] : [line.slice(0, idx), line.slice(idx + 1)];
  }));
  const present = map.present === 'yes';
  const logs = present ? run(`bash -lc 'journalctl -u ${service} -n 80 --no-pager 2>/dev/null || true'`) : 'N/A';
  return {
    selected: service,
    present,
    options: allowed,
    id: map.id || `${service}.service`,
    description: map.description || 'N/A',
    active: map.active || 'missing',
    sub: map.sub || 'N/A',
    enabled: map.enabled || 'N/A',
    mainpid: map.mainpid || 'N/A',
    startedAt: map.startedAt || 'N/A',
    fragment: map.fragment || 'N/A',
    logs: logs || 'N/A',
  };
}

function runDockerAction(container, action) {
  if (!container || !DOCKER_ACTIONS.includes(action)) {
    return { ok: false, message: '非法操作' };
  }
  try {
    execSync(`docker ${action} ${container}`, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 20000,
    });
    const status = run(`bash -lc 'docker inspect --format "{{.State.Status}}" ${container} 2>/dev/null || true'`) || 'unknown';
    return { ok: true, message: `${container} 已执行 ${action}，当前状态 ${status}` };
  } catch (err) {
    const stderr = String(err?.stderr || err?.stdout || '').trim();
    return { ok: false, message: stderr || `${container} 执行 ${action} 失败` };
  }
}

function getDockerDetailSnapshot(containers, selected = '') {
  const options = (containers || []).map(c => c.name).filter(Boolean);
  const chosen = options.includes(selected) ? selected : (options[0] || '');
  if (!chosen) {
    return {
      selected: '',
      present: false,
      options,
      name: 'N/A',
      image: 'N/A',
      status: 'N/A',
      state: 'idle',
      ports: '-',
      startedAt: 'N/A',
      command: 'N/A',
      restartCount: 'N/A',
      logs: 'N/A',
    };
  }
  const raw = run(`bash -lc 'docker inspect --format "name={{.Name}}\nimage={{.Config.Image}}\nstatus={{.State.Status}}\nrunning={{.State.Running}}\nstartedAt={{.State.StartedAt}}\nrestartCount={{.RestartCount}}\ncommand={{json .Config.Cmd}}\nports={{json .NetworkSettings.Ports}}" ${chosen} 2>/dev/null || true'`);
  const map = Object.fromEntries(String(raw || '').split('\n').filter(Boolean).map(line => {
    const idx = line.indexOf('=');
    return idx === -1 ? [line, ''] : [line.slice(0, idx), line.slice(idx + 1)];
  }));
  const fromList = (containers || []).find(c => c.name === chosen);
  const status = map.status || fromList?.status || 'unknown';
  let state = fromList?.state || 'warn';
  if (status === 'running') state = 'ok';
  else if (['restarting', 'dead', 'exited'].includes(status)) state = 'danger';
  const logs = run(`bash -lc 'docker logs --tail 80 ${chosen} 2>&1 || true'`) || 'N/A';
  return {
    selected: chosen,
    present: true,
    options,
    name: chosen,
    image: map.image || fromList?.image || 'N/A',
    status,
    state,
    ports: fromList?.ports || '-',
    startedAt: map.startedAt || 'N/A',
    command: map.command || 'N/A',
    restartCount: map.restartCount || '0',
    logs,
  };
}

function parseTopProcesses(raw) {
  if (!raw || raw === 'N/A') return [];
  const lines = raw.split('\n').map(s => s.trimEnd()).filter(Boolean);
  if (lines.length <= 1) return [];
  return lines.slice(1).map(line => {
    const parts = line.trim().split(/\s+/, 8);
    const [pid, ppid, user, cpu, mem, etime, comm, args] = parts;
    const cpuNum = Number.parseFloat(cpu || '0');
    const memNum = Number.parseFloat(mem || '0');
    let state = 'ok';
    if (cpuNum >= 60 || memNum >= 25) state = 'danger';
    else if (cpuNum >= 25 || memNum >= 10) state = 'warn';
    return {
      pid: pid || 'N/A',
      ppid: ppid || 'N/A',
      user: user || 'N/A',
      cpu: Number.isFinite(cpuNum) ? cpuNum : 0,
      mem: Number.isFinite(memNum) ? memNum : 0,
      etime: etime || 'N/A',
      comm: comm || 'N/A',
      args: args || comm || 'N/A',
      state,
    };
  });
}

function getAlertSummary(data) {
  const alerts = [];
  const load1 = Number(data.overview.loadavg?.[0] || 0);
  const cpuCount = Math.max(1, Number(data.overview.cpuCount || 1));
  const memUsage = data.overview.totalMem > 0 ? (data.overview.usedMem / data.overview.totalMem) * 100 : 0;

  if (load1 >= cpuCount * 1.5) {
    alerts.push({ level: 'critical', text: `1 分钟负载过高：${load1.toFixed(2)} / ${cpuCount} 核` });
  } else if (load1 >= cpuCount) {
    alerts.push({ level: 'warn', text: `1 分钟负载偏高：${load1.toFixed(2)} / ${cpuCount} 核` });
  }

  if (memUsage >= 90) {
    alerts.push({ level: 'critical', text: `内存占用过高：${memUsage.toFixed(1)}%` });
  } else if (memUsage >= 80) {
    alerts.push({ level: 'warn', text: `内存占用偏高：${memUsage.toFixed(1)}%` });
  }

  for (const disk of data.diskUsage || []) {
    if (!Number.isFinite(disk.usePercent)) continue;
    if (disk.usePercent >= 95) {
      alerts.push({ level: 'critical', text: `磁盘空间危险：${disk.mount} 已用 ${disk.usePercent}%` });
    } else if (disk.usePercent >= 85) {
      alerts.push({ level: 'warn', text: `磁盘空间偏高：${disk.mount} 已用 ${disk.usePercent}%` });
    }
  }

  for (const svc of data.services || []) {
    if (!svc.present) continue;
    if (['openclaw', 'docker', 'nginx', 'ssh'].includes(svc.name) && svc.active !== 'active') {
      alerts.push({ level: 'critical', text: `关键服务异常：${svc.name} 当前为 ${svc.active}` });
    }
  }

  for (const c of data.dockerContainers || []) {
    if (c.unhealthy) alerts.push({ level: 'critical', text: `容器不健康：${c.name} (${c.status})` });
    else if (c.restarting || c.exited) alerts.push({ level: 'warn', text: `容器状态异常：${c.name} (${c.status})` });
  }

  for (const p of data.processes || []) {
    if (p.cpu >= 80) alerts.push({ level: 'critical', text: `高 CPU 进程：PID ${p.pid} ${p.comm} 占用 ${p.cpu.toFixed(1)}%` });
    else if (p.cpu >= 50) alerts.push({ level: 'warn', text: `CPU 偏高进程：PID ${p.pid} ${p.comm} 占用 ${p.cpu.toFixed(1)}%` });
    if (p.mem >= 30) alerts.push({ level: 'warn', text: `高内存进程：PID ${p.pid} ${p.comm} 占用 ${p.mem.toFixed(1)}%` });
  }

  const state = readAlertsState();
  const withIds = alerts.map(item => ({ ...item, id: getAlertId(item) }));
  const currentIds = new Set(withIds.map(item => item.id));
  const active = [];
  const acknowledged = [];
  for (const item of withIds) {
    if (state.acknowledged[item.id]) acknowledged.push(item);
    else active.push(item);
  }
  const recovered = [];
  for (const [id, meta] of Object.entries(state.acknowledged || {})) {
    if (!currentIds.has(id)) {
      recovered.unshift({ id, text: `告警已恢复：${id}`, level: 'info', at: meta?.at || Date.now() });
      delete state.acknowledged[id];
    }
  }
  const recoveredMerged = [...recovered, ...(state.recovered || [])].slice(0, 20);
  state.recovered = recoveredMerged;
  writeAlertsState(state);

  const counts = active.reduce((acc, item) => {
    acc[item.level] = (acc[item.level] || 0) + 1;
    return acc;
  }, { critical: 0, warn: 0, info: 0 });

  return {
    counts,
    items: active,
    acknowledged,
    recovered: recoveredMerged,
    total: withIds.length,
  };
}

function getData(logSource = 'syslog', serviceName = 'openclaw', containerName = '') {
  const cpus = os.cpus() || [];
  const nets = os.networkInterfaces();
  const interfaces = [];
  for (const [name, addrs] of Object.entries(nets)) {
    for (const addr of addrs || []) {
      interfaces.push({
        name,
        family: addr.family,
        address: addr.address,
        internal: addr.internal,
      });
    }
  }
  if (!interfaces.some(i => i.address === FORCE_PUBLIC_IP)) {
    interfaces.unshift({ name: 'public', family: 'IPv4', address: FORCE_PUBLIC_IP, internal: false });
  }

  const totalMem = os.totalmem();
  const freeMem = os.freemem();

  const disk = run('df -hP -x tmpfs -x devtmpfs 2>/dev/null | head -n 80');
  const services = getServiceSnapshot();
  const docker = run('docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null | head -n 80');
  const top = run('ps -eo pid,ppid,user,%cpu,%mem,etime,comm,args --sort=-%cpu | head -n 30');
  const logs = getLogsSnapshot(logSource);
  const serviceDetail = getServiceDetailSnapshot(serviceName);
  const dockerContainers = parseDockerContainers(docker);
  const dockerDetail = getDockerDetailSnapshot(dockerContainers, containerName);
  const data = {
    time: formatBeijingTime(),
    listenSummary: getListenSummary(),
    overview: {
      hostname: os.hostname(),
      platform: `${os.type()} ${os.release()}`,
      arch: os.arch(),
      uptimeSec: os.uptime(),
      loadavg: os.loadavg(),
      totalMem,
      freeMem,
      usedMem: totalMem - freeMem,
      cpuCount: cpus.length,
      cpuModel: cpus[0]?.model || 'N/A',
    },
    interfaces,
    disk,
    diskUsage: parseDiskUsage(disk),
    listening: run('ss -tulpn 2>/dev/null | head -n 80'),
    docker,
    dockerContainers,
    dockerDetail,
    top,
    processes: parseTopProcesses(top),
    logs,
    serviceDetail,
    who: run('who 2>/dev/null | head -n 30'),
    lastLogins: run('last -n 20 2>/dev/null'),
    services,
  };
  data.alerts = getAlertSummary(data);
  return data;
}

function moduleDefs(data) {
  const alertPreview = data.alerts.items.length
    ? data.alerts.items.map(item => `[${item.level.toUpperCase()}] ${item.text}`).join('\n')
    : (data.alerts.acknowledged?.length ? `当前告警已全部确认（${data.alerts.acknowledged.length} 条）` : '当前没有触发中的告警');
  const servicesPreview = (data.services || []).filter(s => s.present).map(s => `${s.name}\t${s.active}\t${s.enabled}\t${s.sub}`).join('\n') || 'N/A';
  const dockerPreview = (data.dockerContainers || []).map(c => `${c.name}\t${c.status}\t${c.ports}`).join('\n') || 'N/A';
  const processPreview = (data.processes || []).slice(0, 8).map(p => `${p.pid}\t${p.user}\tCPU ${p.cpu.toFixed(1)}%\tMEM ${p.mem.toFixed(1)}%\t${p.comm}`).join('\n') || 'N/A';
  const logsPreview = String(data.logs?.content || 'N/A').split('\n').slice(-8).join('\n') || 'N/A';
  const modules = [
    {
      key: 'overview',
      title: '系统概览',
      desc: `${data.overview.cpuCount} 核 ｜ 内存 ${formatBytes(data.overview.usedMem)} / ${formatBytes(data.overview.totalMem)}`,
      content: [
        ['主机名', data.overview.hostname],
        ['系统', data.overview.platform],
        ['架构', data.overview.arch],
        ['运行时长', `${(data.overview.uptimeSec / 3600).toFixed(1)} 小时`],
        ['负载', data.overview.loadavg.map(v => v.toFixed(2)).join(' / ')],
        ['CPU', `${data.overview.cpuModel} × ${data.overview.cpuCount}`],
        ['内存', `${formatBytes(data.overview.usedMem)} / ${formatBytes(data.overview.totalMem)}`],
      ],
    },
    {
      key: 'alerts',
      title: '告警中心',
      desc: `严重 ${data.alerts.counts.critical} ｜ 警告 ${data.alerts.counts.warn}`,
      content: alertPreview,
    },
    {
      key: 'services',
      title: '系统服务',
      desc: '查看关键 systemd 服务状态',
      content: servicesPreview,
    },
    {
      key: 'network',
      title: '网络接口',
      desc: `${data.interfaces.length} 条地址记录`,
      content: data.interfaces.map(i => `${i.name} ${i.family} ${i.address}${i.internal ? ' (internal)' : ''}`).join('\n') || 'N/A',
    },
    { key: 'disk', title: '磁盘使用', desc: `挂载点 ${data.diskUsage.length} 个`, content: data.disk },
    { key: 'ports', title: '监听端口', desc: '查看当前监听套接字与进程', content: data.listening },
    { key: 'docker', title: 'Docker 容器', desc: `共 ${(data.dockerContainers || []).length} 个容器`, content: dockerPreview },
    { key: 'processes', title: '进程监控', desc: `Top ${(data.processes || []).length} ｜ 按 CPU 排序`, content: processPreview },
    { key: 'logs', title: '日志查看', desc: `当前源：${data.logs?.label || '系统日志'}`, content: logsPreview },
    { key: 'sessions', title: '当前登录', desc: '查看当前登录会话', content: data.who },
    { key: 'logins', title: '最近登录记录', desc: '查看 last 登录记录', content: data.lastLogins },
  ];
  return modules.map(m => m.key === 'overview' ? m : { ...m, status: getModuleStatus(m.key, data) });
}

function layout(title, body, refreshSeconds = 0) {
  const nowMs = Date.now();
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  ${refreshSeconds > 0 ? `<meta http-equiv="refresh" content="${refreshSeconds}" />` : ''}
  <title>${title}</title>
  <style>
    :root { color-scheme: dark; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Inter, system-ui, sans-serif; background:
      radial-gradient(circle at 86% 10%, rgba(255, 225, 77, .28), transparent 16%),
      radial-gradient(circle at 10% 16%, rgba(34, 211, 238, .26), transparent 22%),
      radial-gradient(circle at 74% 76%, rgba(236, 72, 153, .16), transparent 18%),
      linear-gradient(135deg, #04070d 0%, #08101d 34%, #0b1220 58%, #10192d 100%);
      color: #e5edf7; }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 24px; position: relative; z-index: 1; }
    body::before { content:''; position:fixed; inset:0; pointer-events:none; background:
      linear-gradient(115deg, transparent 0 32%, rgba(255, 224, 102, .08) 32% 38%, transparent 38% 100%),
      linear-gradient(rgba(80, 227, 194, .06) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.028) 1px, transparent 1px);
      background-size: auto, 100% 6px, 6px 100%; opacity:.95; }
    body::after { content:''; position:fixed; inset:0; pointer-events:none; background:
      linear-gradient(90deg, transparent 0%, rgba(34,211,238,.12) 22%, transparent 40%, rgba(255,230,109,.10) 58%, transparent 76%),
      radial-gradient(circle at center, rgba(255,255,255,.05), transparent 55%),
      radial-gradient(circle at 80% 20%, rgba(255,230,109,.08), transparent 28%);
      mix-blend-mode:screen; animation: sweepGlow 8s linear infinite; }
    .fxLayer { position:fixed; inset:0; pointer-events:none; overflow:hidden; }
    .fxGrid { z-index:0; opacity:.9; }
    .fxGrid::before,
    .fxGrid::after { content:''; position:absolute; inset:-10% -10%; }
    .fxGrid::before { background:
      linear-gradient(90deg, rgba(255,255,255,.028) 1px, transparent 1px),
      linear-gradient(rgba(255,255,255,.022) 1px, transparent 1px);
      background-size: 24px 24px, 24px 24px;
      mask-image: radial-gradient(circle at center, black 38%, transparent 82%);
      opacity:.28; }
    .fxGrid::after { background:
      linear-gradient(90deg, transparent 0 24%, rgba(34,211,238,.16) 24% 26%, transparent 26% 100%),
      linear-gradient(transparent 0 44%, rgba(250,204,21,.12) 44% 46%, transparent 46% 100%);
      background-size: 160px 160px, 120px 120px;
      mix-blend-mode:screen;
      opacity:.26;
      animation: pixelDrift 24s linear infinite; }
    .fxPixels { z-index:0; opacity:.9; }
    .fxPixels::before,
    .fxPixels::after { content:''; position:absolute; inset:0; }
    .fxPixels::before { background:
      radial-gradient(circle at 16% 18%, rgba(34,211,238,.18) 0 1px, transparent 1.5px),
      radial-gradient(circle at 76% 22%, rgba(250,204,21,.16) 0 1px, transparent 1.5px),
      radial-gradient(circle at 68% 70%, rgba(244,114,182,.14) 0 1px, transparent 1.5px),
      radial-gradient(circle at 28% 78%, rgba(125,211,252,.14) 0 1px, transparent 1.5px),
      radial-gradient(circle at 88% 58%, rgba(34,211,238,.13) 0 1px, transparent 1.5px);
      background-size: 220px 220px, 260px 260px, 240px 240px, 280px 280px, 320px 320px;
      image-rendering: pixelated;
      filter: drop-shadow(0 0 6px rgba(34,211,238,.10));
      animation: pixelPulse 9s ease-in-out infinite; }
    .fxPixels::after { background:
      linear-gradient(90deg, rgba(34,211,238,.0) 0 20%, rgba(34,211,238,.10) 20% 21%, rgba(34,211,238,0) 21% 100%),
      linear-gradient(90deg, rgba(250,204,21,0) 0 74%, rgba(250,204,21,.12) 74% 75%, rgba(250,204,21,0) 75% 100%);
      background-size: 220px 220px, 300px 300px;
      mix-blend-mode:screen;
      opacity:.22;
      animation: pixelSweep 14s linear infinite; }
    .meteorField { z-index:0; }
    .meteor { position:absolute; right:-18vw; top:0; width:22vw; height:2px; border-radius:999px; background:linear-gradient(90deg, rgba(255,255,255,.98) 0%, rgba(255,255,255,.92) 4%, rgba(34,211,238,.86) 12%, rgba(34,211,238,.34) 28%, rgba(250,204,21,.12) 52%, rgba(250,204,21,0) 100%); box-shadow: 0 0 10px rgba(34,211,238,.26), 0 0 22px rgba(250,204,21,.16); transform: rotate(-22deg); opacity:0; }
    .meteor::after { content:''; position:absolute; left:-1px; top:-3px; width:8px; height:8px; background:#fff7c2; box-shadow: 0 0 10px rgba(255,243,176,.95), 0 0 20px rgba(34,211,238,.36); clip-path: polygon(50% 0, 100% 50%, 50% 100%, 0 50%); }
    .meteor.m1 { top:10%; animation: meteorFly1 8.5s linear infinite; animation-delay: .2s; }
    .meteor.m2 { top:22%; width:16vw; animation: meteorFly2 11s linear infinite; animation-delay: 1.6s; }
    .meteor.m3 { top:34%; width:20vw; animation: meteorFly3 9.5s linear infinite; animation-delay: 3.1s; }
    .meteor.m4 { top:48%; width:14vw; animation: meteorFly4 12.5s linear infinite; animation-delay: .9s; }
    .meteor.m5 { top:62%; width:18vw; animation: meteorFly5 10.5s linear infinite; animation-delay: 4.4s; }
    .meteor.m6 { top:74%; width:15vw; animation: meteorFly2 9.8s linear infinite; animation-delay: 5.8s; opacity:0; }
    .meteor.m7 { top:86%; width:19vw; animation: meteorFly4 13.2s linear infinite; animation-delay: 2.7s; opacity:0; }
    .topbar { display:flex; justify-content:space-between; align-items:flex-start; gap: 12px; margin-bottom: 18px; position:relative; padding-bottom:14px; }
    .topbar::after { content:''; position:absolute; left:0; right:0; bottom:0; height:1px; background:linear-gradient(90deg, rgba(34,211,238,.0), rgba(34,211,238,.5), rgba(250,204,21,.45), rgba(34,211,238,0)); }
    .title { margin: 0; font-size: 28px; text-shadow: 0 0 18px rgba(56,189,248,.18); letter-spacing:.04em; text-transform: uppercase; }
    .muted { color:#9fb0cb; }
    .heroStats { display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin: 0 0 16px; }
    .heroStat { position:relative; overflow:hidden; background: linear-gradient(180deg, rgba(16,24,39,.78), rgba(10,14,24,.66)); border:1px solid rgba(250, 204, 21, .24); border-radius: 16px; padding: 14px 16px; box-shadow: 0 10px 30px rgba(0,0,0,.18), 0 0 18px rgba(250,204,21,.08); clip-path: polygon(0 0, calc(100% - 16px) 0, 100% 16px, 100% 100%, 14px 100%, 0 calc(100% - 14px)); backdrop-filter: blur(8px); }
    .heroStat::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg, #22d3ee, #fde047, #f472b6); }
    .heroStat::after { content:''; position:absolute; inset:auto -20% 0 auto; width:120px; height:120px; border-radius:50%; background: radial-gradient(circle, rgba(250,204,21,.18), transparent 70%); }
    .heroLabel { font-size:12px; color:#8ea5c8; margin-bottom:8px; }
    .heroValue { font-size:22px; font-weight:800; color:#eaf4ff; }
    .heroSub { margin-top:6px; font-size:12px; color:#9fb0cb; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }
    .card { display:block; background:linear-gradient(180deg, rgba(18,26,43,.76), rgba(12,18,31,.68)); border:1px solid rgba(52, 211, 235, .24); border-radius:16px; padding:16px; box-shadow: 0 10px 30px rgba(0,0,0,.2), 0 0 0 1px rgba(34,211,238,.05) inset; color:inherit; text-decoration:none; transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease, background .22s ease; animation: fadeSlideIn .35s ease both; position:relative; overflow:hidden; clip-path: polygon(0 0, calc(100% - 18px) 0, 100% 18px, 100% 100%, 18px 100%, 0 calc(100% - 18px)); backdrop-filter: blur(8px); }
    .card::before { content:''; position:absolute; inset:0 auto 0 0; width:3px; background:linear-gradient(180deg, #22d3ee, #fde047, #e879f9); opacity:.9; }
    .card::after { content:''; position:absolute; top:12px; right:12px; width:56px; height:1px; background:linear-gradient(90deg, rgba(253,224,71,.0), rgba(253,224,71,.9)); box-shadow: 0 0 12px rgba(253,224,71,.35); }
    .card:hover { border-color:#22d3ee; transform: translateY(-4px) scale(1.01); box-shadow: 0 18px 38px rgba(8,145,178,.22), 0 0 0 1px rgba(253,224,71,.08) inset, 0 0 24px rgba(34,211,238,.12); background:linear-gradient(180deg, rgba(22,31,50,.98), rgba(14,22,36,.98)); }
    .cardTitle { font-size:18px; font-weight:800; margin:0 0 10px; letter-spacing:.03em; }
    .desc { font-size:13px; color:#9fb0cb; margin:0; transition: color .22s ease; }
    .statusRow { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:8px; }
    .status { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:800; letter-spacing:.04em; transition: transform .2s ease, box-shadow .2s ease; text-transform: uppercase; }
    .status.ok { background:#12351f; color:#86efac; border:1px solid #1f6f3d; }
    .status.warn { background:#3a2a12; color:#fdba74; border:1px solid #7c4a13; }
    .status.danger { background:#3b1620; color:#fca5a5; border:1px solid #9f1239; }
    .status.idle { background:#1f2937; color:#cbd5e1; border:1px solid #475569; }
    .alertBox { margin: 0 0 16px; padding: 14px 16px; border-radius: 14px; border:1px solid rgba(34,211,238,.22); background:linear-gradient(180deg, rgba(18,26,43,.72), rgba(12,18,31,.62)); box-shadow: 0 0 0 1px rgba(34,211,238,.05) inset; position:relative; overflow:hidden; backdrop-filter: blur(8px); }
    .alertBox::before { content:'ALERT FEED'; position:absolute; top:10px; right:14px; font-size:10px; letter-spacing:.14em; color:rgba(250,204,21,.58); }
    .alertBox.alertOverview::before { display:none; }
    .alertBox.danger { border-color:#fb7185; background:linear-gradient(180deg, rgba(51,16,29,.96), rgba(35,13,22,.96)); }
    .alertBox.warn { border-color:#f59e0b; background:linear-gradient(180deg, rgba(44,30,10,.96), rgba(30,20,8,.96)); }
    .alertList { margin:10px 0 0; padding-left:18px; color:#dbe7f6; }
    .alertList li { margin:6px 0; }
    .kv { display:grid; grid-template-columns: 86px 1fr; gap: 8px 12px; margin-top: 12px; }
    .value { min-width:0; word-break: break-all; overflow-wrap:anywhere; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .preview { margin-top:12px; padding:10px 12px; background:linear-gradient(180deg, rgba(8,16,30,.96), rgba(7,11,20,.98)); border:1px solid rgba(49,80,127,.7); border-radius:12px; color:#c8d6ec; font-size:12px; white-space:pre-wrap; word-break:break-word; max-height:92px; overflow:hidden; transition: border-color .22s ease, transform .22s ease, box-shadow .22s ease; box-shadow: inset 0 0 18px rgba(34,211,238,.03); }
    .card:hover .preview { border-color:#3b82f6; transform: translateY(-1px); box-shadow: inset 0 0 0 1px rgba(59,130,246,.18); }
    .actions { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
    .actions form { margin:0; display:inline-flex; }
    .btn { display:inline-flex; align-items:center; justify-content:center; min-height:44px; padding:10px 16px; border-radius:10px; background:linear-gradient(180deg, rgba(20,32,54,.96), rgba(13,22,38,.96)); border:1px solid rgba(34,211,238,.24); color:#f8fbff; text-decoration:none; cursor:pointer; transition: transform .18s ease, border-color .18s ease, background .18s ease, box-shadow .18s ease; white-space:nowrap; line-height:1.2; vertical-align:middle; box-shadow: 0 0 0 1px rgba(253,224,71,.04) inset; clip-path: polygon(0 0, calc(100% - 10px) 0, 100% 10px, 100% 100%, 10px 100%, 0 calc(100% - 10px)); font-weight:700; letter-spacing:.03em; }
    select.btn { appearance:auto; -webkit-appearance:menulist; padding-right:36px; }
    select.btn option { color:#eaf4ff; background:#0f172a; }
    select.btn optgroup { color:#fde047; background:#0b1220; }
    .btn:hover { transform: translateY(-1px); border-color:#fde047; background:linear-gradient(180deg, rgba(28,42,69,.98), rgba(18,29,48,.98)); box-shadow: 0 8px 22px rgba(250,204,21,.14), 0 0 18px rgba(34,211,238,.10); }
    .detail { background:linear-gradient(180deg, rgba(18,26,43,.72), rgba(12,18,31,.64)); border:1px solid rgba(34,211,238,.22); border-radius:16px; padding:52px 18px 18px; animation: fadeSlideIn .3s ease both; box-shadow: 0 0 0 1px rgba(34,211,238,.05) inset; position:relative; overflow:hidden; clip-path: polygon(0 0, calc(100% - 18px) 0, 100% 18px, 100% 100%, 18px 100%, 0 calc(100% - 18px)); backdrop-filter: blur(8px); }
    .detail::before { content:'MODULE VIEW'; position:absolute; top:16px; left:18px; font-size:10px; letter-spacing:.14em; color:rgba(34,211,238,.55); }
    .detailTools { display:flex; gap:10px; align-items:center; justify-content:space-between; flex-wrap:wrap; margin: 0 0 10px; min-height:44px; }
    .searchInput { min-width: 220px; flex:1; max-width: 360px; }
    .copyHint { font-size:12px; color:#8ea5c8; margin: 0 0 14px; }
    .filterHidden { display:none !important; }
    .floatingClock { position: fixed; right: 18px; bottom: 18px; z-index: 9999; min-width: 220px; max-width: min(280px, calc(100vw - 24px)); padding: 12px 14px; border-radius: 14px; background: linear-gradient(180deg, rgba(10,16,32,.70), rgba(16,24,39,.62)); border: 1px solid rgba(250,204,21,.36); box-shadow: 0 10px 30px rgba(0,0,0,.35), 0 0 18px rgba(250,204,21,.10); backdrop-filter: blur(10px); transition: transform .22s ease, box-shadow .22s ease, border-color .22s ease, background .22s ease; clip-path: polygon(0 0, calc(100% - 14px) 0, 100% 14px, 100% 100%, 14px 100%, 0 calc(100% - 14px)); }
    .floatingClock:hover { transform: translateY(-3px); box-shadow: 0 16px 36px rgba(250,204,21,.18), 0 0 22px rgba(34,211,238,.14); border-color:#22d3ee; background: linear-gradient(180deg, rgba(13,20,39,.96), rgba(18,28,46,.98)); }
    .floatingClockLabel { font-size: 12px; color:#9fb0cb; margin-bottom: 6px; }
    .floatingClockTime { font-size: 18px; font-weight: 700; color:#e5edf7; }
    .cyberPanel { position: fixed; right: 18px; top: 18px; z-index: 10000; width: min(360px, calc(100vw - 24px)); padding: 16px; border-radius: 16px; background: linear-gradient(180deg, rgba(10,16,32,.78), rgba(18,26,43,.70)); border: 1px solid rgba(250,204,21,.42); box-shadow: 0 18px 48px rgba(0,0,0,.42), 0 0 0 1px rgba(34,211,238,.08) inset, 0 0 22px rgba(250,204,21,.10); backdrop-filter: blur(14px); animation: fadeSlideIn .24s ease both; }
    .cyberPanel[hidden] { display:none; }
    .cyberPanelTitle { margin:0 0 6px; font-size:16px; font-weight:800; color:#dbeafe; letter-spacing:.04em; }
    .cyberPanelDesc { margin:0 0 14px; color:#9fb0cb; font-size:12px; }
    .cyberPanelRow { display:flex; gap:10px; align-items:center; }
    .cyberInput { flex:1; min-width:0; height:44px; padding:10px 14px; border-radius:12px; border:1px solid #31507f; background:rgba(8,13,25,.92); color:#e5edf7; outline:none; box-shadow: 0 0 0 1px rgba(37,99,235,.08) inset; }
    .cyberInput:focus { border-color:#38bdf8; box-shadow: 0 0 0 3px rgba(56,189,248,.14); }
    .status.ok, .status.warn, .status.danger { box-shadow: 0 0 0 rgba(0,0,0,0); }
    .status.ok { animation: pulseOk 2.8s ease-in-out infinite; }
    .status.warn { animation: pulseWarn 2.8s ease-in-out infinite; }
    .status.danger { animation: pulseDanger 1.8s ease-in-out infinite; }
    .login { max-width: 420px; margin: 8vh auto; background:linear-gradient(180deg, rgba(18,26,43,.76), rgba(12,18,31,.68)); border:1px solid rgba(250,204,21,.26); border-radius:16px; padding:24px; box-shadow: 0 10px 30px rgba(0,0,0,.25), 0 0 22px rgba(34,211,238,.08); clip-path: polygon(0 0, calc(100% - 18px) 0, 100% 18px, 100% 100%, 18px 100%, 0 calc(100% - 18px)); position:relative; overflow:hidden; backdrop-filter: blur(10px); }
    .login::before { content:'ACCESS NODE'; position:absolute; top:12px; right:16px; font-size:10px; letter-spacing:.14em; color:rgba(250,204,21,.55); }
    .field { display:flex; flex-direction:column; gap:8px; margin-top:12px; }
    input { width:100%; padding:12px 14px; border-radius:12px; border:1px solid #314667; background:#0a1020; color:#e5edf7; }
    .error { margin-top: 12px; padding: 10px 12px; border-radius: 10px; background:#3a1c1c; color:#fecaca; border:1px solid #7f1d1d; }
    pre { white-space: pre-wrap; word-break: break-word; overflow:auto; background:#0a1020; padding:14px; border-radius:12px; border:1px solid #263554; }
    @keyframes fadeSlideIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    @keyframes pulseOk {
      0%, 100% { box-shadow: 0 0 0 0 rgba(34,197,94,0); }
      50% { box-shadow: 0 0 0 6px rgba(34,197,94,.12); }
    }
    @keyframes pulseWarn {
      0%, 100% { box-shadow: 0 0 0 0 rgba(249,115,22,0); }
      50% { box-shadow: 0 0 0 6px rgba(249,115,22,.12); }
    }
    @keyframes pulseDanger {
      0%, 100% { box-shadow: 0 0 0 0 rgba(244,63,94,0); }
      50% { box-shadow: 0 0 0 8px rgba(244,63,94,.14); }
    }
    @keyframes sweepGlow {
      0% { transform: translateX(-25%); opacity:.15; }
      50% { opacity:.45; }
      100% { transform: translateX(25%); opacity:.15; }
    }
    @keyframes pixelDrift {
      0% { transform: translate3d(0, 0, 0); }
      100% { transform: translate3d(-32px, 20px, 0); }
    }
    @keyframes pixelPulse {
      0%, 100% { opacity:.24; transform: scale(1); }
      50% { opacity:.46; transform: scale(1.015); }
    }
    @keyframes pixelSweep {
      0% { transform: translateX(-4%); opacity:.12; }
      50% { opacity:.28; }
      100% { transform: translateX(4%); opacity:.12; }
    }
    @keyframes meteorFly1 {
      0%, 14% { transform: translate3d(0, 0, 0) rotate(-22deg); opacity:0; }
      18%, 34% { opacity:.88; }
      48%, 100% { transform: translate3d(-120vw, 44vh, 0) rotate(-22deg); opacity:0; }
    }
    @keyframes meteorFly2 {
      0%, 22% { transform: translate3d(0, 0, 0) rotate(-22deg); opacity:0; }
      28%, 40% { opacity:.72; }
      56%, 100% { transform: translate3d(-112vw, 38vh, 0) rotate(-22deg); opacity:0; }
    }
    @keyframes meteorFly3 {
      0%, 18% { transform: translate3d(0, 0, 0) rotate(-22deg); opacity:0; }
      24%, 38% { opacity:.9; }
      50%, 100% { transform: translate3d(-118vw, 42vh, 0) rotate(-22deg); opacity:0; }
    }
    @keyframes meteorFly4 {
      0%, 26% { transform: translate3d(0, 0, 0) rotate(-22deg); opacity:0; }
      30%, 42% { opacity:.66; }
      58%, 100% { transform: translate3d(-108vw, 34vh, 0) rotate(-22deg); opacity:0; }
    }
    @keyframes meteorFly5 {
      0%, 20% { transform: translate3d(0, 0, 0) rotate(-22deg); opacity:0; }
      26%, 38% { opacity:.8; }
      54%, 100% { transform: translate3d(-116vw, 40vh, 0) rotate(-22deg); opacity:0; }
    }
    @media (max-width: 900px) {
      .wrap { padding: 18px; }
      .topbar { flex-direction: column; align-items: stretch; }
      .actions { width: 100%; gap: 10px; }
      .actions form { flex: 1 1 auto; }
      .actions .btn { width: 100%; }
      .floatingClock { right: 14px; bottom: 14px; min-width: 200px; }
    }
    @media (max-width: 640px) {
      .wrap { padding: 14px; }
      .title { font-size: 24px; }
      .grid { grid-template-columns: 1fr; }
      .heroStats { grid-template-columns: 1fr 1fr; }
      .kv { grid-template-columns: 72px 1fr; }
      .card, .detail, .login { border-radius: 14px; }
      .floatingClock { right: 10px; bottom: 10px; left: 10px; min-width: 0; max-width: none; width: auto; padding: 10px 12px; }
      .floatingClockTime { font-size: 16px; }
      .cyberPanel { right: 10px; left: 10px; top: 10px; width: auto; }
      .cyberPanelRow { flex-direction: column; align-items: stretch; }
      .cyberPanelRow .btn { width: 100%; }
      .detailTools { flex-direction: column; align-items: stretch; }
      .searchInput { max-width: none; width: 100%; }
    }
  </style>
</head>
<body data-now-ms="${nowMs}">
<div class="fxLayer fxGrid"></div>
<div class="fxLayer fxPixels"></div>
<div class="fxLayer meteorField">
  <span class="meteor m1"></span>
  <span class="meteor m2"></span>
  <span class="meteor m3"></span>
  <span class="meteor m4"></span>
  <span class="meteor m5"></span>
  <span class="meteor m6"></span>
  <span class="meteor m7"></span>
</div>
${body}
<div class="floatingClock">
  <div class="floatingClockLabel">当前时间</div>
  <div class="floatingClockTime mono" data-live-now>${new Date(nowMs).toISOString().slice(0, 19).replace('T', ' ')}</div>
</div>
<div class="cyberPanel" id="customRefreshPanel" hidden>
  <div class="cyberPanelTitle">自定义刷新时间</div>
  <div class="cyberPanelDesc">输入 1-3600 秒。</div>
  <div class="cyberPanelRow">
    <input id="customRefreshInput" class="cyberInput mono" type="number" min="1" max="3600" step="1" value="20" placeholder="输入秒数" />
    <button id="customRefreshApply" class="btn" type="button">应用</button>
    <button id="customRefreshCancel" class="btn" type="button">取消</button>
  </div>
</div>
<script>
(() => {
  const pad = n => String(n).padStart(2, '0');
  const fmt = d => [
    d.getFullYear(), '-',
    pad(d.getMonth() + 1), '-',
    pad(d.getDate()), ' ',
    pad(d.getHours()), ':',
    pad(d.getMinutes()), ':',
    pad(d.getSeconds())
  ].join('');
  const baseMs = Number(document.body.dataset.nowMs || Date.now());
  const startedAt = Date.now();
  const tick = () => {
    const now = new Date(baseMs + (Date.now() - startedAt));
    for (const el of document.querySelectorAll('[data-live-now]')) {
      el.textContent = fmt(now);
    }
  };
  const customPanel = document.getElementById('customRefreshPanel');
  const customInput = document.getElementById('customRefreshInput');
  const customApply = document.getElementById('customRefreshApply');
  const customCancel = document.getElementById('customRefreshCancel');
  let customTargetSelect = null;

  const closeCustomPanel = () => {
    if (!customPanel) return;
    customPanel.hidden = true;
    if (customTargetSelect) {
      customTargetSelect.value = customTargetSelect.dataset.previousValue || '15';
    }
    customTargetSelect = null;
  };

  const submitCustomRefresh = () => {
    if (!customTargetSelect) return;
    const n = Number.parseInt(String(customInput.value || '').trim(), 10);
    if (!Number.isFinite(n) || n < 1 || n > 3600) {
      customInput.focus();
      customInput.select();
      return;
    }
    const url = new URL(customTargetSelect.form.action || window.location.href, window.location.origin);
    url.searchParams.set('refresh', String(n));
    window.location.href = url.toString();
  };

  window.handleRefreshSelect = (selectEl) => {
    if (selectEl.value !== 'custom') {
      selectEl.form.submit();
      return;
    }
    customTargetSelect = selectEl;
    if (customPanel) customPanel.hidden = false;
    if (customInput) {
      customInput.value = selectEl.dataset.previousValue || '20';
      customInput.focus();
      customInput.select();
    }
  };

  customApply?.addEventListener('click', submitCustomRefresh);
  customCancel?.addEventListener('click', closeCustomPanel);
  customInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitCustomRefresh();
    if (e.key === 'Escape') closeCustomPanel();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !customPanel?.hidden) closeCustomPanel();
  });
  for (const selectEl of document.querySelectorAll('[data-refresh-select]')) {
    selectEl.dataset.previousValue = selectEl.value;
    selectEl.addEventListener('focus', () => { selectEl.dataset.previousValue = selectEl.value; });
    selectEl.addEventListener('click', () => { selectEl.dataset.previousValue = selectEl.value; });
    selectEl.addEventListener('change', () => {
      if (selectEl.value !== 'custom') selectEl.dataset.previousValue = selectEl.value;
    });
  }
  for (const btn of document.querySelectorAll('[data-copy-content]')) {
    btn.addEventListener('click', async () => {
      const text = btn.getAttribute('data-copy-content') || '';
      try {
        await navigator.clipboard.writeText(text);
        const old = btn.textContent;
        btn.textContent = '复制成功';
        setTimeout(() => { btn.textContent = old; }, 1200);
      } catch {
        const old = btn.textContent;
        btn.textContent = '复制失败';
        setTimeout(() => { btn.textContent = old; }, 1200);
      }
    });
  }
  const filterInput = document.querySelector('[data-detail-filter]');
  const detailRoot = document.querySelector('[data-detail-content]');
  if (filterInput && detailRoot) {
    filterInput.addEventListener('input', () => {
      const keyword = String(filterInput.value || '').trim().toLowerCase();
      const rows = detailRoot.querySelectorAll('tr, li, .kv > div, pre');
      if (!rows.length) return;
      if (detailRoot.querySelector('table')) {
        detailRoot.querySelectorAll('tbody tr').forEach((row) => {
          row.classList.toggle('filterHidden', !!keyword && !row.textContent.toLowerCase().includes(keyword));
        });
        return;
      }
      if (detailRoot.querySelector('ul')) {
        detailRoot.querySelectorAll('li').forEach((row) => {
          row.classList.toggle('filterHidden', !!keyword && !row.textContent.toLowerCase().includes(keyword));
        });
        return;
      }
      if (detailRoot.querySelector('.kv')) {
        const cells = Array.from(detailRoot.querySelectorAll('.kv > div'));
        for (let i = 0; i < cells.length; i += 2) {
          const a = cells[i];
          const b = cells[i + 1];
          const text = ((a?.textContent || '') + ' ' + (b?.textContent || '')).toLowerCase();
          const hide = !!keyword && !text.includes(keyword);
          if (a) a.classList.toggle('filterHidden', hide);
          if (b) b.classList.toggle('filterHidden', hide);
        }
        return;
      }
      const pre = detailRoot.querySelector('pre');
      if (pre) {
        pre.classList.toggle('filterHidden', false);
      }
    });
  }
  tick();
  setInterval(tick, 1000);
})();
</script>
</body>
</html>`;
}

function renderLogin(errorMessage = '') {
  const body = `<div class="wrap">
    <div class="login">
      <h1 class="title">sysinfo-panel 登录</h1>
      <div class="muted">请输入用户名和密码</div>
      <div class="muted" style="margin-top:8px; font-size:12px;">默认账号密码：${DEFAULT_USERNAME} / ${DEFAULT_PASSWORD}</div>
      ${errorMessage ? `<div class="error">${htmlEscape(errorMessage)}</div>` : ''}
      <form method="post" action="${BASE_PATH}/login">
        <div class="field">
          <label for="username">用户名</label>
          <input id="username" name="username" type="text" autocomplete="username" required />
        </div>
        <div class="field">
          <label for="password">密码</label>
          <input id="password" name="password" type="password" autocomplete="current-password" required />
        </div>
        <div class="actions" style="margin-top:16px;">
          <button class="btn" type="submit">登录</button>
        </div>
      </form>
    </div>
  </div>`;
  return layout('sysinfo-panel 登录', body, false);
}

function renderHome(data, refreshSeconds = 15) {
  const modules = moduleDefs(data);
  const overview = modules.find(m => m.key === 'overview');
  const refreshLabel = formatRefreshLabel(refreshSeconds);
  const refreshOptions = buildRefreshOptions(refreshSeconds);
  const memPercent = formatPercent(data.overview.usedMem, data.overview.totalMem);
  const diskPeak = (data.diskUsage || []).reduce((max, item) => Number.isFinite(item.usePercent) ? Math.max(max, item.usePercent) : max, 0);
  const heroStats = [
    ['CPU 核心', String(data.overview.cpuCount || 'N/A'), truncateMiddle(data.overview.cpuModel || 'N/A', 32)],
    ['内存占用', memPercent, `${formatBytes(data.overview.usedMem)} / ${formatBytes(data.overview.totalMem)}`],
    ['磁盘峰值', diskPeak ? `${diskPeak}%` : 'N/A', `挂载点 ${(data.diskUsage || []).length} 个`],
    ['告警状态', String(data.alerts.counts.critical || data.alerts.counts.warn ? data.alerts.counts.critical + data.alerts.counts.warn : 0), `严重 ${data.alerts.counts.critical} / 警告 ${data.alerts.counts.warn}`],
  ].map(([label, value, sub]) => `<div class="heroStat"><div class="heroLabel">${htmlEscape(label)}</div><div class="heroValue mono">${htmlEscape(String(value))}</div><div class="heroSub">${htmlEscape(String(sub))}</div></div>`).join('');
  const cards = modules.filter(m => m.key !== 'overview').map(m => {
    const previewText = typeof m.content === 'string'
      ? m.content.split('\n').slice(0, 4).join('\n')
      : m.content.map(([k, v]) => `${k}: ${v}`).slice(0, 4).join('\n');
    return `<a class="card" href="${BASE_PATH}/module/${m.key}">
      <div class="statusRow">
        <div class="cardTitle">${htmlEscape(m.title)}</div>
        <span class="status ${htmlEscape(m.status.tone)}">● ${htmlEscape(m.status.text)}</span>
      </div>
      <p class="desc">${htmlEscape(m.desc)}</p>
      <div class="preview mono">${htmlEscape(previewText || 'N/A')}</div>
    </a>`;
  }).join('');

  const ovRows = overview.content.map(([k, v]) => {
    const value = (k === '主机名' || k === '系统') ? truncateMiddle(v, 36) : v;
    return `<div class="muted">${htmlEscape(k)}</div><div class="value mono" title="${htmlEscape(v)}">${htmlEscape(value)}</div>`;
  }).join('');

  const alertLevel = data.alerts.counts.critical > 0 ? 'danger' : (data.alerts.counts.warn > 0 ? 'warn' : 'ok');
  const alertSummary = data.alerts.items.length
    ? `<div style="display:grid; gap:10px; margin-top:12px;">${data.alerts.items.slice(0, 4).map(item => `<div style="padding:12px 14px; border-radius:14px; border:1px solid ${item.level === 'critical' ? 'rgba(255,76,76,.45)' : 'rgba(255,184,77,.35)'}; background:${item.level === 'critical' ? 'linear-gradient(180deg, rgba(255,76,76,.14), rgba(255,76,76,.05))' : 'linear-gradient(180deg, rgba(255,184,77,.12), rgba(255,184,77,.05))'}; box-shadow:${item.level === 'critical' ? '0 0 24px rgba(255,76,76,.12)' : '0 0 20px rgba(255,184,77,.08)'};"><div style="display:flex; justify-content:space-between; gap:10px; align-items:center;"><span class="status ${item.level === 'critical' ? 'danger' : 'warn'}">${htmlEscape(item.level.toUpperCase())}</span><span class="muted mono" style="font-size:12px;">${htmlEscape(item.id)}</span></div><div style="margin-top:8px; line-height:1.6; color:#f3f7ff;">${htmlEscape(item.text)}</div></div>`).join('')}</div>`
    : `<div class="muted" style="margin-top:10px;">${data.alerts.acknowledged?.length ? `当前告警已确认 ${data.alerts.acknowledged.length} 条` : '当前没有触发中的告警'}</div>`;

  const body = `<div class="wrap">
    <div class="topbar">
      <div>
        <h1 class="title">系统信息面板</h1>
        <div class="muted">${htmlEscape(refreshLabel)} ｜ 上次刷新 ${htmlEscape(data.time)}</div>
      </div>
      <div class="actions">
        <form method="get" action="${BASE_PATH}/">
          <select class="btn" name="refresh" data-refresh-select onchange="window.handleRefreshSelect(this)">${refreshOptions}</select>
        </form>
        <a class="btn" href="${BASE_PATH}/api/system" target="_blank">JSON</a>
        <form method="post" action="${BASE_PATH}/logout"><button class="btn" type="submit">退出登录</button></form>
      </div>
    </div>

    <div class="heroStats">${heroStats}</div>

    <div class="alertBox alertOverview ${htmlEscape(alertLevel)}" style="padding:18px 18px 16px; border-radius:18px; overflow:hidden; position:relative;">
      <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:14px; flex-wrap:wrap;">
        <div>
          <div class="cardTitle" style="margin-bottom:4px;">告警总览</div>
          <div class="desc">严重 ${data.alerts.counts.critical} ｜ 警告 ${data.alerts.counts.warn} ｜ 已确认 ${data.alerts.acknowledged?.length || 0}</div>
        </div>
        <div style="display:flex; gap:8px; flex-wrap:wrap;">
          <span class="status danger">严重 ${data.alerts.counts.critical}</span>
          <span class="status warn">警告 ${data.alerts.counts.warn}</span>
          <span class="status idle">已确认 ${data.alerts.acknowledged?.length || 0}</span>
        </div>
      </div>
      ${alertSummary}
      ${(data.alerts.acknowledged?.length || data.alerts.recovered?.length) ? `<div style="display:flex; gap:10px; flex-wrap:wrap; margin-top:14px;"><div style="flex:1; min-width:220px; padding:12px 14px; border-radius:14px; border:1px solid rgba(119,139,180,.24); background:rgba(16,26,44,.45);"><div class="muted" style="margin-bottom:6px;">已确认</div><div class="value mono">${htmlEscape(String(data.alerts.acknowledged?.length || 0))} 条</div></div><div style="flex:1; min-width:220px; padding:12px 14px; border-radius:14px; border:1px solid rgba(73,214,162,.2); background:rgba(10,34,28,.38);"><div class="muted" style="margin-bottom:6px;">最近恢复</div><div class="value mono">${htmlEscape(String(data.alerts.recovered?.length || 0))} 条</div></div></div>` : ''}
    </div>

    <div class="card" style="margin-bottom:16px; text-decoration:none;">
      <div class="cardTitle">系统概览</div>
      <p class="desc">核心指标保留在首页，长字段已做截断与换行保护</p>
      <div class="kv">${ovRows}</div>
    </div>

    <div class="grid">${cards}</div>
  </div>`;
  return layout('系统信息面板', body, refreshSeconds);
}

function renderModule(data, key, refreshSeconds = 15, actionNotice = null) {
  const mod = moduleDefs(data).find(m => m.key === key);
  if (!mod) return null;
  let contentHtml = '';
  if (key === 'services') {
    const rows = (data.services || []).map(s => `<tr>
      <td class="mono">${htmlEscape(s.name)}</td>
      <td><span class="status ${s.present ? (s.active === 'active' ? 'ok' : 'danger') : 'idle'}">${htmlEscape(s.active)}</span></td>
      <td class="mono">${htmlEscape(s.enabled)}</td>
      <td class="mono">${htmlEscape(s.sub)}</td>
    </tr>`).join('');
    const serviceOptions = (data.serviceDetail?.options || []).map(name => `<option value="${htmlEscape(name)}" ${name === data.serviceDetail.selected ? 'selected' : ''}>${htmlEscape(name)}</option>`).join('');
    const detailTone = !data.serviceDetail?.present ? 'idle' : (data.serviceDetail.active === 'active' ? 'ok' : 'danger');
    const noticeHtml = actionNotice ? `<div class="alertBox ${actionNotice.ok ? 'ok' : 'danger'}" style="margin-bottom:14px;"><div class="desc">${htmlEscape(actionNotice.message || '')}</div></div>` : '';
    contentHtml = `${noticeHtml}<div style="display:flex; gap:10px; flex-wrap:wrap; margin:0 0 14px;">
      <form method="get" action="${BASE_PATH}/module/services" class="actions" style="gap:10px;">
        <select class="btn" name="service">${serviceOptions}</select>
        <input type="hidden" name="refresh" value="${htmlEscape(String(refreshSeconds))}" />
        <button class="btn" type="submit">查看详情</button>
      </form>
      <form method="post" action="${BASE_PATH}/service-action" class="actions" style="gap:10px; align-items:center;">
        <input type="hidden" name="service" value="${htmlEscape(data.serviceDetail?.selected || '')}" />
        <input type="hidden" name="refresh" value="${htmlEscape(String(refreshSeconds))}" />
        <label class="muted" style="display:flex; align-items:center; gap:6px; font-size:12px;">
          <input type="checkbox" name="confirm" value="yes" required />
          我已确认本次服务操作
        </label>
        <button class="btn" type="submit" name="action" value="start">启动</button>
        <button class="btn" type="submit" name="action" value="restart">重启</button>
        <button class="btn" type="submit" name="action" value="stop">停止</button>
      </form>
    </div>
    <div style="overflow:auto; margin-bottom:16px;"><table style="width:100%; border-collapse:collapse;">
      <thead><tr><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">服务</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">状态</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">开机自启</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">子状态</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    <div class="card" style="text-decoration:none; margin-bottom:16px;">
      <div class="statusRow">
        <div class="cardTitle">服务详情：${htmlEscape(data.serviceDetail?.selected || 'N/A')}</div>
        <span class="status ${htmlEscape(detailTone)}">${htmlEscape(data.serviceDetail?.active || 'missing')}</span>
      </div>
      <div class="kv">
        <div class="muted">描述</div><div class="value mono">${htmlEscape(data.serviceDetail?.description || 'N/A')}</div>
        <div class="muted">子状态</div><div class="value mono">${htmlEscape(data.serviceDetail?.sub || 'N/A')}</div>
        <div class="muted">开机自启</div><div class="value mono">${htmlEscape(data.serviceDetail?.enabled || 'N/A')}</div>
        <div class="muted">MainPID</div><div class="value mono">${htmlEscape(data.serviceDetail?.mainpid || 'N/A')}</div>
        <div class="muted">启动时间</div><div class="value mono">${htmlEscape(data.serviceDetail?.startedAt || 'N/A')}</div>
        <div class="muted">单元文件</div><div class="value mono">${htmlEscape(data.serviceDetail?.fragment || 'N/A')}</div>
      </div>
    </div>
    <div class="copyHint">已附带该服务最近日志，默认 80 行。</div>
    <pre class="mono">${htmlEscape(data.serviceDetail?.logs || 'N/A')}</pre>`;
  } else if (key === 'docker') {
    const rows = (data.dockerContainers || []).map(c => `<tr>
      <td class="mono">${htmlEscape(c.name)}</td>
      <td class="mono">${htmlEscape(truncateMiddle(c.image, 42))}</td>
      <td><span class="status ${htmlEscape(c.state)}">${htmlEscape(c.status)}</span></td>
      <td class="mono">${htmlEscape(c.ports || '-')}</td>
    </tr>`).join('');
    const containerOptions = (data.dockerDetail?.options || []).map(name => `<option value="${htmlEscape(name)}" ${name === data.dockerDetail.selected ? 'selected' : ''}>${htmlEscape(name)}</option>`).join('');
    const noticeHtml = actionNotice ? `<div class="alertBox ${actionNotice.ok ? 'ok' : 'danger'}" style="margin-bottom:14px;"><div class="desc">${htmlEscape(actionNotice.message || '')}</div></div>` : '';
    contentHtml = rows
      ? `${noticeHtml}<div style="display:flex; gap:10px; flex-wrap:wrap; margin:0 0 14px;">
          <form method="get" action="${BASE_PATH}/module/docker" class="actions" style="gap:10px;">
            <select class="btn" name="container">${containerOptions}</select>
            <input type="hidden" name="refresh" value="${htmlEscape(String(refreshSeconds))}" />
            <button class="btn" type="submit">查看详情</button>
          </form>
          <form method="post" action="${BASE_PATH}/docker-action" class="actions" style="gap:10px; align-items:center;">
            <input type="hidden" name="container" value="${htmlEscape(data.dockerDetail?.selected || '')}" />
            <input type="hidden" name="refresh" value="${htmlEscape(String(refreshSeconds))}" />
            <label class="muted" style="display:flex; align-items:center; gap:6px; font-size:12px;">
              <input type="checkbox" name="confirm" value="yes" required />
              我已确认本次容器操作
            </label>
            <button class="btn" type="submit" name="action" value="start">启动</button>
            <button class="btn" type="submit" name="action" value="restart">重启</button>
            <button class="btn" type="submit" name="action" value="stop">停止</button>
          </form>
        </div>
        <div style="overflow:auto; margin-bottom:16px;"><table style="width:100%; border-collapse:collapse;">
          <thead><tr><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">容器</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">镜像</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">状态</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">端口</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>
        <div class="card" style="text-decoration:none; margin-bottom:16px;">
          <div class="statusRow">
            <div class="cardTitle">容器详情：${htmlEscape(data.dockerDetail?.name || 'N/A')}</div>
            <span class="status ${htmlEscape(data.dockerDetail?.state || 'idle')}">${htmlEscape(data.dockerDetail?.status || 'N/A')}</span>
          </div>
          <div class="kv">
            <div class="muted">镜像</div><div class="value mono">${htmlEscape(data.dockerDetail?.image || 'N/A')}</div>
            <div class="muted">端口</div><div class="value mono">${htmlEscape(data.dockerDetail?.ports || '-')}</div>
            <div class="muted">启动时间</div><div class="value mono">${htmlEscape(data.dockerDetail?.startedAt || 'N/A')}</div>
            <div class="muted">重启次数</div><div class="value mono">${htmlEscape(data.dockerDetail?.restartCount || '0')}</div>
            <div class="muted">命令</div><div class="value mono">${htmlEscape(data.dockerDetail?.command || 'N/A')}</div>
          </div>
        </div>
        <div class="copyHint">已附带该容器最近日志，默认 80 行。</div>
        <pre class="mono">${htmlEscape(data.dockerDetail?.logs || 'N/A')}</pre>`
      : `<div class="muted">当前没有容器</div>`;
  } else if (key === 'processes') {
    const rows = (data.processes || []).map(p => `<tr>
      <td class="mono">${htmlEscape(p.pid)}</td>
      <td class="mono">${htmlEscape(p.ppid)}</td>
      <td class="mono">${htmlEscape(p.user)}</td>
      <td><span class="status ${htmlEscape(p.state)}">CPU ${htmlEscape(p.cpu.toFixed(1))}%</span></td>
      <td><span class="status ${htmlEscape(p.mem >= 30 ? 'danger' : (p.mem >= 10 ? 'warn' : 'ok'))}">MEM ${htmlEscape(p.mem.toFixed(1))}%</span></td>
      <td class="mono">${htmlEscape(p.etime)}</td>
      <td class="mono">${htmlEscape(p.comm)}</td>
      <td class="mono" title="${htmlEscape(p.args)}">${htmlEscape(truncateMiddle(p.args, 68))}</td>
    </tr>`).join('');
    contentHtml = rows
      ? `<div style="overflow:auto;"><table style="width:100%; border-collapse:collapse;">
          <thead><tr><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">PID</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">PPID</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">用户</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">CPU</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">内存</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">运行时长</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">进程名</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">命令</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>`
      : `<div class="muted">当前没有可展示的进程数据</div>`;
  } else if (key === 'logs') {
    const sourceOptions = (data.logs?.sources || []).map(item => `<option value="${htmlEscape(item.key)}" ${item.key === data.logs.selected ? 'selected' : ''}>${htmlEscape(item.label)}</option>`).join('');
    contentHtml = `<div style="display:flex; gap:10px; flex-wrap:wrap; margin:0 0 14px;">
      <form method="get" action="${BASE_PATH}/module/logs" class="actions" style="gap:10px;">
        <select class="btn" name="source">${sourceOptions}</select>
        <input type="hidden" name="refresh" value="${htmlEscape(String(refreshSeconds))}" />
        <button class="btn" type="submit">切换日志源</button>
      </form>
    </div>
    <div class="copyHint">当前日志源：${htmlEscape(data.logs?.label || '系统日志')} ｜ 默认展示最近 120 行。</div>
    <pre class="mono">${htmlEscape(data.logs?.content || 'N/A')}</pre>`;
  } else if (key === 'alerts') {
    const activeHtml = data.alerts.items.length
      ? `<div style="display:grid; gap:12px;">${data.alerts.items.map(item => `<div style="padding:14px 16px; border-radius:16px; border:1px solid ${item.level === 'critical' ? 'rgba(255,76,76,.45)' : 'rgba(255,184,77,.35)'}; background:${item.level === 'critical' ? 'linear-gradient(180deg, rgba(255,76,76,.16), rgba(255,76,76,.05))' : 'linear-gradient(180deg, rgba(255,184,77,.12), rgba(255,184,77,.05))'};"><div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start; flex-wrap:wrap;"><div style="flex:1; min-width:240px;"><div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;"><span class="status ${item.level === 'critical' ? 'danger' : 'warn'}">${htmlEscape(item.level.toUpperCase())}</span><span class="muted mono" style="font-size:12px;">${htmlEscape(item.id)}</span></div><div style="margin-top:9px; line-height:1.7; color:#f4f7ff;">${htmlEscape(item.text)}</div></div><form method="post" action="${BASE_PATH}/alert-action" class="actions" style="gap:8px;"><input type="hidden" name="id" value="${htmlEscape(item.id)}" /><input type="hidden" name="refresh" value="${htmlEscape(String(refreshSeconds))}" /><button class="btn" type="submit">确认</button></form></div></div>`).join('')}</div>`
      : `<div class="muted">当前没有未确认告警</div>`;
    const ackHtml = data.alerts.acknowledged?.length
      ? `<div style="display:grid; gap:10px;">${data.alerts.acknowledged.map(item => `<div style="padding:12px 14px; border-radius:14px; border:1px solid rgba(119,139,180,.2); background:rgba(16,26,44,.42);"><span class="status idle">已确认</span><div style="margin-top:8px; color:#cbd7f5; line-height:1.65;">${htmlEscape(item.text)}</div></div>`).join('')}</div>`
      : `<div class="muted">当前没有已确认但未恢复的告警</div>`;
    const recoveredHtml = data.alerts.recovered?.length
      ? `<div style="display:grid; gap:10px;">${data.alerts.recovered.slice(0, 10).map(item => `<div style="padding:12px 14px; border-radius:14px; border:1px solid rgba(73,214,162,.18); background:rgba(10,34,28,.34);"><span class="status ok">已恢复</span><div style="margin-top:8px; color:#bdebdc; line-height:1.65;">${htmlEscape(item.text)}</div></div>`).join('')}</div>`
      : `<div class="muted">当前没有最近恢复记录</div>`;
    contentHtml = `<div class="card" style="text-decoration:none; margin-bottom:16px; border-color:rgba(255,107,107,.28); box-shadow:0 0 30px rgba(255,90,90,.08);"><div class="cardTitle">当前告警</div><p class="desc">只展示未确认的触发项，重点突出。</p>${activeHtml}</div><div class="card" style="text-decoration:none; margin-bottom:16px; opacity:.9;"><div class="cardTitle">已确认告警</div><p class="desc">问题仍存在，但已从强提醒区移出。</p>${ackHtml}</div><div class="card" style="text-decoration:none; opacity:.88;"><div class="cardTitle">最近恢复</div><p class="desc">已恢复的告警自动归档，视觉上更轻。</p>${recoveredHtml}</div>`;
  } else if (Array.isArray(mod.content)) {
    contentHtml = `<div class="kv">${mod.content.map(([k, v]) => `<div class="muted">${htmlEscape(k)}</div><div class="value mono">${htmlEscape(v)}</div>`).join('')}</div>`;
  } else {
    contentHtml = `<pre class="mono">${htmlEscape(mod.content || 'N/A')}</pre>`;
  }
  const refreshLabel = formatRefreshLabel(refreshSeconds);
  const refreshOptions = buildRefreshOptions(refreshSeconds);
  const moduleContentText = key === 'processes'
    ? (data.processes || []).map(p => `${p.pid}\t${p.ppid}\t${p.user}\tCPU ${p.cpu.toFixed(1)}%\tMEM ${p.mem.toFixed(1)}%\t${p.etime}\t${p.comm}\t${p.args}`).join('\n')
    : key === 'logs'
      ? String(data.logs?.content || '')
      : key === 'services'
        ? [`服务: ${data.serviceDetail?.selected || 'N/A'}`,
           `描述: ${data.serviceDetail?.description || 'N/A'}`,
           `状态: ${data.serviceDetail?.active || 'N/A'}`,
           `子状态: ${data.serviceDetail?.sub || 'N/A'}`,
           `开机自启: ${data.serviceDetail?.enabled || 'N/A'}`,
           `MainPID: ${data.serviceDetail?.mainpid || 'N/A'}`,
           `启动时间: ${data.serviceDetail?.startedAt || 'N/A'}`,
           `单元文件: ${data.serviceDetail?.fragment || 'N/A'}`,
           '',
           String(data.serviceDetail?.logs || 'N/A')].join('\n')
      : key === 'docker'
        ? [`容器: ${data.dockerDetail?.name || 'N/A'}`,
           `镜像: ${data.dockerDetail?.image || 'N/A'}`,
           `状态: ${data.dockerDetail?.status || 'N/A'}`,
           `端口: ${data.dockerDetail?.ports || '-'}`,
           `启动时间: ${data.dockerDetail?.startedAt || 'N/A'}`,
           `重启次数: ${data.dockerDetail?.restartCount || '0'}`,
           `命令: ${data.dockerDetail?.command || 'N/A'}`,
           '',
           String(data.dockerDetail?.logs || 'N/A')].join('\n')
        : Array.isArray(mod.content)
      ? mod.content.map(([k, v]) => `${k}: ${v}`).join('\n')
      : String(mod.content || '');
  const body = `<div class="wrap">
    <div class="topbar">
      <div>
        <h1 class="title">${htmlEscape(mod.title)}</h1>
        <div class="muted">${htmlEscape(mod.desc)} ｜ ${htmlEscape(refreshLabel)} ｜ 上次刷新 ${htmlEscape(data.time)}</div>
      </div>
      <div class="actions">
        <form method="get" action="${BASE_PATH}/module/${encodeURIComponent(key)}">
          <select class="btn" name="refresh" data-refresh-select onchange="window.handleRefreshSelect(this)">${refreshOptions}</select>
        </form>
        <a class="btn" href="${BASE_PATH}/">返回首页</a>
        <a class="btn" href="${BASE_PATH}/api/system" target="_blank">JSON</a>
        <form method="post" action="${BASE_PATH}/logout"><button class="btn" type="submit">退出登录</button></form>
      </div>
    </div>
    <div class="detail">
      <div class="detailTools">
        <input class="cyberInput searchInput" type="search" placeholder="筛选当前内容 / 表格行" data-detail-filter />
        <div class="actions">
          <button class="btn" type="button" data-copy-content="${htmlEscape(moduleContentText)}">复制当前模块</button>
        </div>
      </div>
      <div class="copyHint">支持当前模块内容搜索过滤与一键复制。</div>
      <div data-detail-content>${contentHtml}</div>
    </div>
  </div>`;
  return layout(`${mod.title} - 系统信息面板`, body, refreshSeconds);
}

async function handler(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  const method = req.method || 'GET';
  const pathname = url.pathname;
  const refreshSeconds = getRefreshSeconds(url.searchParams.get('refresh'));
  const logSource = String(url.searchParams.get('source') || 'syslog');
  const serviceName = String(url.searchParams.get('service') || 'openclaw');
  const containerName = String(url.searchParams.get('container') || '');
  const actionNotice = url.searchParams.has('action_ok') || url.searchParams.has('action_msg')
    ? { ok: url.searchParams.get('action_ok') === '1', message: String(url.searchParams.get('action_msg') || '') }
    : null;
  const isGetLike = method === 'GET' || method === 'HEAD';
  const isHome = pathname === '/' || pathname === BASE_PATH || pathname === `${BASE_PATH}/`;
  const isHealth = pathname === '/healthz' || pathname === `${BASE_PATH}/healthz`;
  const isApi = pathname === '/api/system' || pathname === `${BASE_PATH}/api/system`;
  const isLogin = pathname === '/login' || pathname === `${BASE_PATH}/login`;
  const isLogout = pathname === '/logout' || pathname === `${BASE_PATH}/logout`;
  const isServiceAction = pathname === '/service-action' || pathname === `${BASE_PATH}/service-action`;
  const isDockerAction = pathname === '/docker-action' || pathname === `${BASE_PATH}/docker-action`;
  const isAlertAction = pathname === '/alert-action' || pathname === `${BASE_PATH}/alert-action`;
  const modulePrefix = `${BASE_PATH}/module/`;
  const plainModulePrefix = '/module/';

  if (isGetLike && isHealth) {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(method === 'HEAD' ? '' : 'ok');
    return;
  }

  if (isGetLike && isLogin) {
    if (isAuthenticated(req)) {
      redirect(res, `${BASE_PATH}/`);
      return;
    }
    const body = renderLogin('');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(method === 'HEAD' ? '' : body);
    return;
  }

  if (method === 'POST' && isLogin) {
    try {
      const raw = await readRequestBody(req);
      const params = new URLSearchParams(raw);
      const username = String(params.get('username') || '');
      const password = String(params.get('password') || '');
      const config = readAuthConfig();
      if (username === config.username && verifyPassword(password)) {
        setCookie(res, SESSION_COOKIE, createSessionValue(username), Math.floor(SESSION_TTL_MS / 1000));
        redirect(res, `${BASE_PATH}/`);
        return;
      }
      const body = renderLogin('用户名或密码错误');
      res.writeHead(401, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(body);
      return;
    } catch {
      const body = renderLogin('请求解析失败');
      res.writeHead(400, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(body);
      return;
    }
  }

  if (method === 'POST' && isLogout) {
    clearCookie(res, SESSION_COOKIE);
    redirect(res, `${BASE_PATH}/login`);
    return;
  }

  if (!isAuthenticated(req)) {
    unauthorized(req, res);
    return;
  }

  if (method === 'POST' && isServiceAction) {
    try {
      const raw = await readRequestBody(req);
      const params = new URLSearchParams(raw);
      const service = String(params.get('service') || 'openclaw');
      const action = String(params.get('action') || 'restart');
      const refresh = getRefreshSeconds(params.get('refresh'));
      const confirmed = String(params.get('confirm') || '') === 'yes';
      const result = confirmed ? runServiceAction(service, action) : { ok: false, message: '请先勾选确认后再执行服务操作' };
      redirect(res, `${BASE_PATH}/module/services?service=${encodeURIComponent(service)}&refresh=${refresh}&action_ok=${result.ok ? '1' : '0'}&action_msg=${encodeURIComponent(result.message)}`);
      return;
    } catch {
      redirect(res, `${BASE_PATH}/module/services?service=${encodeURIComponent(serviceName)}&refresh=${refreshSeconds}&action_ok=0&action_msg=${encodeURIComponent('请求解析失败')}`);
      return;
    }
  }

  if (method === 'POST' && isDockerAction) {
    try {
      const raw = await readRequestBody(req);
      const params = new URLSearchParams(raw);
      const container = String(params.get('container') || '');
      const action = String(params.get('action') || 'restart');
      const refresh = getRefreshSeconds(params.get('refresh'));
      const confirmed = String(params.get('confirm') || '') === 'yes';
      const result = confirmed ? runDockerAction(container, action) : { ok: false, message: '请先勾选确认后再执行容器操作' };
      redirect(res, `${BASE_PATH}/module/docker?container=${encodeURIComponent(container)}&refresh=${refresh}&action_ok=${result.ok ? '1' : '0'}&action_msg=${encodeURIComponent(result.message)}`);
      return;
    } catch {
      redirect(res, `${BASE_PATH}/module/docker?container=${encodeURIComponent(containerName)}&refresh=${refreshSeconds}&action_ok=0&action_msg=${encodeURIComponent('请求解析失败')}`);
      return;
    }
  }

  if (method === 'POST' && isAlertAction) {
    try {
      const raw = await readRequestBody(req);
      const params = new URLSearchParams(raw);
      const id = String(params.get('id') || '');
      const refresh = getRefreshSeconds(params.get('refresh'));
      if (id) acknowledgeAlertById(id);
      redirect(res, `${BASE_PATH}/module/alerts?refresh=${refresh}`);
      return;
    } catch {
      redirect(res, `${BASE_PATH}/module/alerts?refresh=${refreshSeconds}`);
      return;
    }
  }

  if (isGetLike && isApi) {
    const body = JSON.stringify(getData(logSource, serviceName, containerName), null, 2);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(method === 'HEAD' ? '' : body);
    return;
  }

  if (isGetLike && isHome) {
    const body = renderHome(getData(logSource, serviceName, containerName), refreshSeconds);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(method === 'HEAD' ? '' : body);
    return;
  }

  if (isGetLike && (pathname.startsWith(modulePrefix) || pathname.startsWith(plainModulePrefix))) {
    const key = pathname.startsWith(modulePrefix)
      ? decodeURIComponent(pathname.slice(modulePrefix.length))
      : decodeURIComponent(pathname.slice(plainModulePrefix.length));
    const body = renderModule(getData(logSource, serviceName, containerName), key, refreshSeconds, (key === 'services' || key === 'docker') ? actionNotice : null);
    if (!body) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(method === 'HEAD' ? '' : 'Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(method === 'HEAD' ? '' : body);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(method === 'HEAD' ? '' : 'Not found');
}

ensureRuntimeFiles();

http.createServer((req, res) => {
  Promise.resolve(handler(req, res)).catch(err => {
    console.error('sysinfo-panel request error:', err);
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Internal Server Error');
  });
}).listen(PORT, HOST, () => {
  console.log(`sysinfo-panel http listening on http://${HOST}:${PORT}${BASE_PATH}/`);
});
