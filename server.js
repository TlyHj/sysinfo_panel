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
  if (key === 'docker') {
    if (!data.docker || data.docker === 'N/A') return { text: '无数据', tone: 'warn' };
    if (!(data.dockerContainers || []).length) return { text: '空', tone: 'idle' };
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

  const counts = alerts.reduce((acc, item) => {
    acc[item.level] = (acc[item.level] || 0) + 1;
    return acc;
  }, { critical: 0, warn: 0, info: 0 });

  return { counts, items: alerts };
}

function getData() {
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
    dockerContainers: parseDockerContainers(docker),
    top: run('ps -eo pid,ppid,user,%cpu,%mem,etime,comm,args --sort=-%cpu | head -n 30'),
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
    : '当前没有触发中的告警';
  const servicesPreview = (data.services || []).filter(s => s.present).map(s => `${s.name}\t${s.active}\t${s.enabled}\t${s.sub}`).join('\n') || 'N/A';
  const dockerPreview = (data.dockerContainers || []).map(c => `${c.name}\t${c.status}\t${c.ports}`).join('\n') || 'N/A';
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
    { key: 'processes', title: '高占用进程', desc: '按 CPU 排序展示进程', content: data.top },
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
    body { margin: 0; font-family: Inter, system-ui, sans-serif; background: #0b1220; color: #e5edf7; }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 24px; }
    .topbar { display:flex; justify-content:space-between; align-items:flex-start; gap: 12px; margin-bottom: 18px; }
    .title { margin: 0; font-size: 28px; }
    .muted { color:#9fb0cb; }
    .grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; }
    .card { display:block; background:#121a2b; border:1px solid #22304d; border-radius:16px; padding:16px; box-shadow: 0 10px 30px rgba(0,0,0,.2); color:inherit; text-decoration:none; transition: transform .22s ease, border-color .22s ease, box-shadow .22s ease, background .22s ease; animation: fadeSlideIn .35s ease both; }
    .card:hover { border-color:#3b82f6; transform: translateY(-4px); box-shadow: 0 18px 38px rgba(29,78,216,.18); background:#151f34; }
    .cardTitle { font-size:18px; font-weight:700; margin:0 0 10px; }
    .desc { font-size:13px; color:#9fb0cb; margin:0; transition: color .22s ease; }
    .statusRow { display:flex; align-items:center; justify-content:space-between; gap:8px; margin-bottom:8px; }
    .status { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; transition: transform .2s ease, box-shadow .2s ease; }
    .status.ok { background:#12351f; color:#86efac; border:1px solid #1f6f3d; }
    .status.warn { background:#3a2a12; color:#fdba74; border:1px solid #7c4a13; }
    .status.danger { background:#3b1620; color:#fca5a5; border:1px solid #9f1239; }
    .status.idle { background:#1f2937; color:#cbd5e1; border:1px solid #475569; }
    .alertBox { margin: 0 0 16px; padding: 14px 16px; border-radius: 14px; border:1px solid #22304d; background:#121a2b; }
    .alertBox.danger { border-color:#9f1239; background:#2a131a; }
    .alertBox.warn { border-color:#7c4a13; background:#2b1d10; }
    .alertList { margin:10px 0 0; padding-left:18px; color:#dbe7f6; }
    .alertList li { margin:6px 0; }
    .kv { display:grid; grid-template-columns: 86px 1fr; gap: 8px 12px; margin-top: 12px; }
    .value { min-width:0; word-break: break-all; overflow-wrap:anywhere; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .preview { margin-top:12px; padding:10px 12px; background:#0a1020; border:1px solid #263554; border-radius:12px; color:#c8d6ec; font-size:12px; white-space:pre-wrap; word-break:break-word; max-height:92px; overflow:hidden; transition: border-color .22s ease, transform .22s ease, box-shadow .22s ease; }
    .card:hover .preview { border-color:#3b82f6; transform: translateY(-1px); box-shadow: inset 0 0 0 1px rgba(59,130,246,.18); }
    .actions { display:flex; gap:12px; align-items:center; flex-wrap:wrap; }
    .actions form { margin:0; display:inline-flex; }
    .btn { display:inline-flex; align-items:center; justify-content:center; min-height:44px; padding:10px 16px; border-radius:10px; background:#1d2a44; border:1px solid #314667; color:#e5edf7; text-decoration:none; cursor:pointer; transition: transform .18s ease, border-color .18s ease, background .18s ease, box-shadow .18s ease; white-space:nowrap; line-height:1.2; vertical-align:middle; }
    .btn:hover { transform: translateY(-1px); border-color:#3b82f6; background:#213251; box-shadow: 0 8px 20px rgba(29,78,216,.16); }
    .detail { background:#121a2b; border:1px solid #22304d; border-radius:16px; padding:18px; animation: fadeSlideIn .3s ease both; }
    .floatingClock { position: fixed; right: 18px; bottom: 18px; z-index: 9999; min-width: 220px; max-width: min(280px, calc(100vw - 24px)); padding: 12px 14px; border-radius: 14px; background: rgba(10,16,32,.88); border: 1px solid #314667; box-shadow: 0 10px 30px rgba(0,0,0,.35); backdrop-filter: blur(10px); transition: transform .22s ease, box-shadow .22s ease, border-color .22s ease, background .22s ease; }
    .floatingClock:hover { transform: translateY(-3px); box-shadow: 0 16px 36px rgba(29,78,216,.18); border-color:#3b82f6; background: rgba(13,20,39,.94); }
    .floatingClockLabel { font-size: 12px; color:#9fb0cb; margin-bottom: 6px; }
    .floatingClockTime { font-size: 18px; font-weight: 700; color:#e5edf7; }
    .cyberPanel { position: fixed; right: 18px; top: 18px; z-index: 10000; width: min(360px, calc(100vw - 24px)); padding: 16px; border-radius: 16px; background: linear-gradient(180deg, rgba(10,16,32,.96), rgba(18,26,43,.94)); border: 1px solid rgba(59,130,246,.45); box-shadow: 0 18px 48px rgba(0,0,0,.42), 0 0 0 1px rgba(56,189,248,.08) inset; backdrop-filter: blur(14px); animation: fadeSlideIn .24s ease both; }
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
    .login { max-width: 420px; margin: 8vh auto; background:#121a2b; border:1px solid #22304d; border-radius:16px; padding:24px; box-shadow: 0 10px 30px rgba(0,0,0,.25); }
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
      .kv { grid-template-columns: 72px 1fr; }
      .card, .detail, .login { border-radius: 14px; }
      .floatingClock { right: 10px; bottom: 10px; left: 10px; min-width: 0; max-width: none; width: auto; padding: 10px 12px; }
      .floatingClockTime { font-size: 16px; }
      .cyberPanel { right: 10px; left: 10px; top: 10px; width: auto; }
      .cyberPanelRow { flex-direction: column; align-items: stretch; }
      .cyberPanelRow .btn { width: 100%; }
    }
  </style>
</head>
<body data-now-ms="${nowMs}">${body}
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
    ? `<ul class="alertList">${data.alerts.items.slice(0, 6).map(item => `<li>[${htmlEscape(item.level.toUpperCase())}] ${htmlEscape(item.text)}</li>`).join('')}</ul>`
    : '<div class="muted" style="margin-top:10px;">当前没有触发中的告警</div>';

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

    <div class="alertBox ${htmlEscape(alertLevel)}">
      <div class="cardTitle" style="margin-bottom:4px;">告警总览</div>
      <div class="desc">严重 ${data.alerts.counts.critical} ｜ 警告 ${data.alerts.counts.warn}</div>
      ${alertSummary}
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

function renderModule(data, key, refreshSeconds = 15) {
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
    contentHtml = `<div style="overflow:auto;"><table style="width:100%; border-collapse:collapse;">
      <thead><tr><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">服务</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">状态</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">开机自启</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">子状态</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
  } else if (key === 'docker') {
    const rows = (data.dockerContainers || []).map(c => `<tr>
      <td class="mono">${htmlEscape(c.name)}</td>
      <td class="mono">${htmlEscape(truncateMiddle(c.image, 42))}</td>
      <td><span class="status ${htmlEscape(c.state)}">${htmlEscape(c.status)}</span></td>
      <td class="mono">${htmlEscape(c.ports || '-')}</td>
    </tr>`).join('');
    contentHtml = rows
      ? `<div style="overflow:auto;"><table style="width:100%; border-collapse:collapse;">
          <thead><tr><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">容器</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">镜像</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">状态</th><th style="text-align:left; padding:10px; border-bottom:1px solid #263554;">端口</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>`
      : `<div class="muted">当前没有容器</div>`;
  } else if (key === 'alerts') {
    contentHtml = data.alerts.items.length
      ? `<ul class="alertList">${data.alerts.items.map(item => `<li><span class="status ${item.level === 'critical' ? 'danger' : 'warn'}">${htmlEscape(item.level.toUpperCase())}</span> ${htmlEscape(item.text)}</li>`).join('')}</ul>`
      : `<div class="muted">当前没有触发中的告警</div>`;
  } else if (Array.isArray(mod.content)) {
    contentHtml = `<div class="kv">${mod.content.map(([k, v]) => `<div class="muted">${htmlEscape(k)}</div><div class="value mono">${htmlEscape(v)}</div>`).join('')}</div>`;
  } else {
    contentHtml = `<pre class="mono">${htmlEscape(mod.content || 'N/A')}</pre>`;
  }
  const refreshLabel = formatRefreshLabel(refreshSeconds);
  const refreshOptions = buildRefreshOptions(refreshSeconds);
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
    <div class="detail">${contentHtml}</div>
  </div>`;
  return layout(`${mod.title} - 系统信息面板`, body, refreshSeconds);
}

async function handler(req, res) {
  const url = new URL(req.url, 'http://127.0.0.1');
  const method = req.method || 'GET';
  const pathname = url.pathname;
  const refreshSeconds = getRefreshSeconds(url.searchParams.get('refresh'));
  const isGetLike = method === 'GET' || method === 'HEAD';
  const isHome = pathname === '/' || pathname === BASE_PATH || pathname === `${BASE_PATH}/`;
  const isHealth = pathname === '/healthz' || pathname === `${BASE_PATH}/healthz`;
  const isApi = pathname === '/api/system' || pathname === `${BASE_PATH}/api/system`;
  const isLogin = pathname === '/login' || pathname === `${BASE_PATH}/login`;
  const isLogout = pathname === '/logout' || pathname === `${BASE_PATH}/logout`;
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

  if (isGetLike && isApi) {
    const body = JSON.stringify(getData(), null, 2);
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(method === 'HEAD' ? '' : body);
    return;
  }

  if (isGetLike && isHome) {
    const body = renderHome(getData(), refreshSeconds);
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(method === 'HEAD' ? '' : body);
    return;
  }

  if (isGetLike && (pathname.startsWith(modulePrefix) || pathname.startsWith(plainModulePrefix))) {
    const key = pathname.startsWith(modulePrefix)
      ? decodeURIComponent(pathname.slice(modulePrefix.length))
      : decodeURIComponent(pathname.slice(plainModulePrefix.length));
    const body = renderModule(getData(), key, refreshSeconds);
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
