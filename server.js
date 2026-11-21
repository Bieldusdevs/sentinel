'use strict';
// Sentinel - servidor local. Zero dependências.
// Segurança: escuta em 127.0.0.1 (e, se você ligar, num IP de VPN/rede privada), valida o header Host
// (anti DNS-rebinding), exige cabeçalho X-Sentinel em escritas (anti-CSRF) e sessão por cookie HttpOnly.
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const store = require('./lib/store');
const auth = require('./lib/auth');
const scope = require('./lib/scope');
const jobs = require('./lib/jobs');
const scanner = require('./lib/scanner');
const tools = require('./lib/tools');
const vault = require('./lib/vault');
const applock = require('./lib/applock');
const vm = require('./lib/vm');
const net = require('./lib/netutil');
const remote = require('./lib/remote');
const ai = require('./lib/ai');
const agents = require('./lib/agents');
const panic = require('./lib/panic');
const notes = require('./lib/notes');
const maps = require('./lib/maps');

const PORT = +process.env.SENTINEL_PORT || 7777;
const PUBLIC = path.join(__dirname, 'public');
const LAB_DIR = process.env.CYBERLAB_DIR || path.join(__dirname, '..', 'cyber-lab');
const COOKIE = 'sentinel_sid';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };

// ---------- util ----------
const json = (res, code, obj) => { const b = JSON.stringify(obj); res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }); res.end(b); };
const fail = (e) => ({ error: e.message || String(e) });

function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > limit) { reject(Object.assign(new Error('Corpo grande demais.'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { reject(Object.assign(new Error('JSON inválido.'), { status: 400 })); } });
    req.on('error', reject);
  });
}

function cookieOf(req, name) {
  const m = (req.headers.cookie || '').split(/;\s*/).find((c) => c.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}

const loopback = (addr) => addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';

function allowedHosts() {
  const hosts = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`, `[::1]:${PORT}`]);
  const r = remote.config(); if (r.enabled && r.bindIp) hosts.add(`${r.bindIp}:${PORT}`);
  return hosts;
}

// ---------- CPU ----------
let lastCpu = os.cpus().map((c) => ({ ...c.times }));
function cpuUsage() {
  const now = os.cpus().map((c) => ({ ...c.times }));
  let idle = 0, total = 0;
  now.forEach((t, i) => { const p = lastCpu[i]; const d = (k) => t[k] - p[k]; const tt = d('user') + d('nice') + d('sys') + d('idle') + d('irq'); total += tt; idle += d('idle'); });
  lastCpu = now;
  return total ? Math.round((1 - idle / total) * 100) : 0;
}

// ---------- cyber-lab ----------
let labJob = null;
function labState() {
  const exists = fs.existsSync(path.join(LAB_DIR, 'lab.py'));
  return { exists, dir: LAB_DIR, running: !!(labJob && labJob.status === 'running'), url: 'http://127.0.0.1:8080', jobId: labJob?.id || null };
}
function labStart() {
  if (!fs.existsSync(path.join(LAB_DIR, 'lab.py'))) throw new Error('cyber-lab não encontrado em ' + LAB_DIR);
  if (labJob && labJob.status === 'running') return labJob;
  labJob = jobs.create('lab', 'CyberLab (127.0.0.1:8080)');
  jobs.emit(labJob, 'Iniciando CyberLab em http://127.0.0.1:8080 (vulnerável de proposito, só local).', 'sys');
  jobs.runProcess(labJob, 'python', ['lab.py'], { cwd: LAB_DIR, env: { ...process.env, LAB_PORT: '8080', PYTHONUNBUFFERED: '1' } });
  store.audit('lab.start');
  return labJob;
}

// ---------- fs browser (seletor de arquivos para o cofre) ----------
function browse(p) {
  const target = path.resolve(p || os.homedir());
  if (target.toLowerCase().startsWith(path.resolve(store.DATA_DIR).toLowerCase())) throw new Error('Pasta protegida.');
  const items = fs.readdirSync(target, { withFileTypes: true }).map((d) => {
    let size = null; try { if (d.isFile()) size = fs.statSync(path.join(target, d.name)).size; } catch { /* sem acesso */ }
    return { name: d.name, dir: d.isDirectory(), size };
  }).sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name)).slice(0, 500);
  return { path: target, parent: path.dirname(target) === target ? null : path.dirname(target), items };
}
function drives() {
  const out = [];
  for (let c = 67; c <= 90; c++) { const d = String.fromCharCode(c) + ':\\'; try { fs.accessSync(d); out.push(d); } catch { /* ausente */ } }
  return out;
}

// ---------- rotas ----------
// Cada handler: async ({ req, res, url, body, params, ip, sid }) => objeto | undefined (se já respondeu)
const routes = [];
const route = (method, pattern, handler, opts = {}) => routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), handler, open: !!opts.open });

// -- auth (abertas) --
route('GET', '/api/auth/state', ({ sid }) => ({ setup: auth.isSetup(), authed: !!(sid && auth.sessionFor(sid)), needs2fa: auth.needs2fa() }), { open: true });
route('POST', '/api/auth/setup', ({ body, ip, res }) => {
  if (!loopback(ip)) throw Object.assign(new Error('A configuração inicial só e permitida nesta máquina.'), { status: 403 });
  const r = auth.setup(body.pin);
  const tok = auth.login({ pin: body.pin }, ip); setCookie(res, tok);
  return r;
}, { open: true });
route('POST', '/api/auth/login', ({ body, ip, res }) => { const tok = auth.login(body, ip); setCookie(res, tok); return { ok: true }; }, { open: true });
route('POST', '/api/auth/recover', ({ body, ip }) => auth.recover(body, ip), { open: true });
route('POST', '/api/auth/logout', ({ sid, res }) => { auth.logout(sid); res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`); return { ok: true }; });
route('POST', '/api/auth/pin', ({ body }) => { auth.changePin(body); return { ok: true }; });
route('POST', '/api/auth/2fa/begin', () => auth.totpBegin());
route('POST', '/api/auth/2fa/confirm', ({ body }) => { auth.totpConfirm(body.code); return { ok: true }; });
route('POST', '/api/auth/2fa/disable', ({ body }) => { auth.totpDisable(body.pin); return { ok: true }; });

function setCookie(res, tok) { res.setHeader('Set-Cookie', `${COOKIE}=${tok}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${12 * 3600}`); }

// -- sistema --
route('GET', '/api/system', () => ({
  host: os.hostname(), user: os.userInfo().username, platform: `${os.type()} ${os.release()}`, uptime: os.uptime(),
  cpu: os.cpus()[0]?.model, cores: os.cpus().length, cpuUsage: cpuUsage(),
  memTotal: os.totalmem(), memFree: os.freemem(), node: process.version,
  counts: { jobs: jobs.list().filter((j) => j.status === 'running').length, scope: scope.list().length, scans: scanner.history().length },
}));
route('GET', '/api/audit', () => ({ events: store.readAudit(300) }));
route('GET', '/api/fs', ({ url }) => browse(url.searchParams.get('path')));
route('GET', '/api/fs/drives', () => ({ drives: drives(), home: os.homedir() }));

// -- escopo --
route('GET', '/api/scope', () => ({ scope: scope.list() }));
route('POST', '/api/scope', ({ body }) => ({ scope: scope.add(body.value, body.note, body.attested) }));
route('DELETE', '/api/scope', ({ body }) => ({ scope: scope.remove(body.value) }));

// -- scans --
route('POST', '/api/scan/web', ({ body }) => ({ job: scanner.startWebScan(body.target, body.level).id }));
route('POST', '/api/scan/ports', ({ body }) => ({ job: scanner.startPortScan(body.target, body.ports).id }));
route('GET', '/api/scan/history', () => ({ history: scanner.history() }));
route('DELETE', '/api/scan/history', ({ body }) => { if (body.id) scanner.deleteHistory(body.id); else scanner.clearHistory(); return { ok: true }; });

// -- ferramentas externas --
route('GET', '/api/tools', async () => ({ tools: await tools.status(), presets: Object.keys(tools.NMAP_PRESETS) }));
route('POST', '/api/tools/run', async ({ body }) => ({ job: (await tools.run(body.tool, body.params || {})).id }));
route('POST', '/api/tools/install', ({ body }) => ({ job: tools.install(body.tool).id }));

// -- jobs --
route('GET', '/api/jobs', () => ({ jobs: jobs.list() }));
route('GET', '/api/jobs/:id', ({ params }) => { const j = jobs.get(params.id); if (!j) throw Object.assign(new Error('Job não encontrado.'), { status: 404 }); return { id: j.id, title: j.title, kind: j.kind, status: j.status, result: j.meta.result || null }; });
route('GET', '/api/jobs/:id/stream', ({ params, res }) => { const j = jobs.get(params.id); if (!j) throw Object.assign(new Error('Job não encontrado.'), { status: 404 }); jobs.stream(j, res); });
route('POST', '/api/jobs/:id/kill', ({ params }) => ({ ok: jobs.kill(params.id) }));

// -- cofre --
route('POST', '/api/vault/password', ({ body }) => vault.generatePassword(body));
route('POST', '/api/vault/passphrase', ({ body }) => vault.generatePassphrase(+body.words || 6));
route('POST', '/api/vault/encrypt', async ({ body }) => vault.encryptFile(body.path, body.password, { removeOriginal: !!body.removeOriginal }));
route('POST', '/api/vault/decrypt', async ({ body }) => vault.decryptFile(body.path, body.password));

// -- applock --
route('GET', '/api/applock', () => applock.state());
route('POST', '/api/applock/add', ({ body }) => applock.addApp(body.exe));
route('POST', '/api/applock/remove', ({ body }) => applock.removeApp(body.name));
route('POST', '/api/applock/idle', ({ body }) => applock.setIdle(body.min));
route('POST', '/api/applock/lock', () => applock.lock());
route('POST', '/api/applock/unlock', ({ body }) => applock.unlock(body.pin));
route('POST', '/api/applock/touch', () => { applock.touch(); return { ok: true }; });

// -- apagar de emergencia --
route('GET', '/api/panic', () => panic.state());
route('GET', '/api/panic/presets', () => panic.presets());
route('POST', '/api/panic/target', ({ body }) => panic.addTarget(body.path, body.note));
route('DELETE', '/api/panic/target', ({ body }) => panic.removeTarget(body.path));
route('POST', '/api/panic/overwrite', ({ body }) => panic.setOverwrite(body.on));
route('GET', '/api/panic/preview', () => panic.preview());
route('POST', '/api/panic/execute', ({ body }) => panic.execute(body));
route('POST', '/api/panic/backup', ({ body }) => panic.backupApp(body.dest, body.password));
route('POST', '/api/panic/selfdestruct', ({ body }) => panic.selfDestruct(body));

// -- notas --
route('GET', '/api/notes', () => ({ notes: notes.list() }));
route('POST', '/api/notes', ({ body }) => notes.upsert(body));
route('DELETE', '/api/notes', ({ body }) => { notes.remove(body.id); return { ok: true }; });

// -- mapas --
route('GET', '/api/maps/aviation', ({ url }) => maps.aviation(['lamin', 'lomin', 'lamax', 'lomax'].map((k) => +url.searchParams.get(k))));
route('GET', '/api/maps/weather/meta', async () => maps.rainviewerFrames());
route('GET', '/api/maps/threats', () => ({ state: maps.threatState(), legend: maps.BL_LISTS }));
route('POST', '/api/maps/threats/refresh', () => ({ job: maps.startThreatRefresh().id }));
route('GET', '/api/maps/tile/:provider/:z/:x/:y', async ({ params, res }) => {
  const t = await maps.tile(params.provider, params.z, params.x, params.y);
  res.writeHead(200, { 'Content-Type': t.type, 'Cache-Control': 'public, max-age=86400' }); res.end(t.buf);
});
route('GET', '/api/maps/weather/tile/:frame/:z/:x/:y', async ({ params, res }) => {
  const t = await maps.weatherTile(params.frame, params.z, params.x, params.y);
  res.writeHead(200, { 'Content-Type': t.type, 'Cache-Control': 'public, max-age=300' }); res.end(t.buf);
});

// -- VMs --
route('GET', '/api/vm/providers', () => vm.providers());
route('GET', '/api/vm/list', async () => ({ vms: await vm.list() }));
route('POST', '/api/vm/action', async ({ body }) => { await vm.action(body.provider, body.name, body.action); return { ok: true }; });
route('POST', '/api/vm/create', async ({ body }) => vm.create(body));

// -- rede --
route('GET', '/api/geoip', ({ url }) => net.geoip(url.searchParams.get('q')));
route('GET', '/api/tempmail', () => ({ boxes: net.tmBoxes() }));
route('POST', '/api/tempmail', () => net.tmCreate());
route('GET', '/api/tempmail/messages', ({ url }) => net.tmMessages(url.searchParams.get('address')).then((messages) => ({ messages })));
route('GET', '/api/tempmail/message', ({ url }) => net.tmMessage(url.searchParams.get('address'), url.searchParams.get('id')));
route('DELETE', '/api/tempmail', async ({ body }) => { await net.tmDelete(body.address); return { ok: true }; });
route('GET', '/api/proxy/system', () => net.sysProxyGet());
route('POST', '/api/proxy/system', ({ body }) => net.sysProxySet(body));
route('GET', '/api/proxy/list', () => ({ proxies: net.proxies() }));
route('POST', '/api/proxy/list', ({ body }) => net.proxyAdd(body));
route('DELETE', '/api/proxy/list', ({ body }) => { net.proxyRemove(body.id); return { ok: true }; });
route('POST', '/api/proxy/test', async ({ body }) => { const p = net.proxies().find((x) => x.id === body.id); if (!p) throw new Error('Proxy não encontrado.'); return net.proxyTest(p); });

// -- IA e agentes --
route('GET', '/api/ai/settings', () => ai.publicSettings());
route('POST', '/api/ai/settings', ({ body }) => ai.saveSettings(body));
route('GET', '/api/ai/status', async () => ({ ollama: await ai.ollamaStatus(), settings: ai.publicSettings() }));
route('POST', '/api/ai/serve', () => { ai.ollamaServe(); return { ok: true }; });
route('POST', '/api/ai/pull', ({ body }) => ({ job: ai.ollamaPull(body.model).id }));

route('GET', '/api/agents', () => ({ agents: agents.listAgents(), sessions: agents.listSessions() }));
route('POST', '/api/agents/autonomy', ({ body }) => {
  if (body.mode === 'full' && !auth.verifyPin(body.pin)) throw Object.assign(new Error('PIN inválido. O modo "full" exige confirmação com o PIN.'), { status: 401 });
  agents.setAutonomy(body.agent, body.mode); return { ok: true };
});
route('POST', '/api/agents/sessions', ({ body }) => { const s = agents.newSession(body.agent); return { id: s.id }; });
route('GET', '/api/agents/sessions/:id', ({ params }) => { const s = agents.getSession(params.id); if (!s) throw Object.assign(new Error('Conversa não encontrada.'), { status: 404 }); return { id: s.id, agentId: s.agentId, title: s.title, status: s.status }; });
route('GET', '/api/agents/sessions/:id/stream', ({ params, res }) => { const s = agents.getSession(params.id); if (!s) throw Object.assign(new Error('Conversa não encontrada.'), { status: 404 }); agents.stream(s, res); });
route('POST', '/api/agents/sessions/:id/send', ({ params, body }) => { agents.send(params.id, body.text); return { ok: true }; });
route('POST', '/api/agents/sessions/:id/stop', ({ params }) => ({ ok: agents.stop(params.id) }));
route('DELETE', '/api/agents/sessions/:id', ({ params }) => { agents.removeSession(params.id); return { ok: true }; });
route('POST', '/api/agents/approve', ({ body }) => ({ ok: agents.decide(body.id, body.approve === true) }));

// -- remoto --
route('GET', '/api/remote', () => ({ config: remote.config(), interfaces: remote.interfaces(), port: PORT }));
route('POST', '/api/remote', async ({ body }) => { const c = remote.setConfig(body); await applyRemote(); return { config: c }; });

// -- lab --
route('GET', '/api/lab', () => labState());
route('POST', '/api/lab/start', () => ({ job: labStart().id }));
route('POST', '/api/lab/stop', () => ({ ok: labJob ? jobs.kill(labJob.id) : false }));

// ---------- despacho ----------
async function handle(req, res) {
  const ip = req.socket.remoteAddress || '';
  const u = new URL(req.url, 'http://x');

  // anti DNS-rebinding
  if (!allowedHosts().has((req.headers.host || '').toLowerCase())) { res.writeHead(421); return res.end('Host não permitido'); }

  // cabeçalhos de segurança
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");

  if (u.pathname.startsWith('/api/')) {
    const method = req.method;
    if (method !== 'GET') {
      if (req.headers['x-sentinel'] !== '1') return json(res, 403, { error: 'Cabeçalho de segurança ausente.' });
      const origin = req.headers.origin; if (origin && new URL(origin).host !== req.headers.host) return json(res, 403, { error: 'Origem inválida.' });
    }
    const r = routes.find((x) => x.method === method && x.re.test(u.pathname));
    if (!r) return json(res, 404, { error: 'Rota inexistente.' });
    const sid = cookieOf(req, COOKIE);
    if (!r.open && !auth.sessionFor(sid)) return json(res, 401, { error: 'Não autenticado.' });
    try {
      const params = u.pathname.match(r.re).groups || {};
      const body = method === 'GET' ? {} : await readBody(req);
      const out = await r.handler({ req, res, url: u, body, params, ip, sid });
      if (!res.headersSent && out !== undefined) json(res, 200, out);
    } catch (e) {
      if (!res.headersSent) json(res, e.status || 400, fail(e));
    }
    return;
  }

  // estaticos
  let p = decodeURIComponent(u.pathname); if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC, p));
  if (!file.startsWith(PUBLIC + path.sep) || p.includes('\0')) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('Não encontrado'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

// ---------- listeners ----------
const servers = new Map(); // host -> server
function listen(host) {
  return new Promise((resolve, reject) => {
    const s = http.createServer((req, res) => handle(req, res).catch((e) => { if (!res.headersSent) json(res, 500, fail(e)); }));
    s.requestTimeout = 0; s.headersTimeout = 20000;
    s.once('error', reject);
    s.listen(PORT, host, () => { servers.set(host, s); resolve(s); });
  });
}
async function applyRemote() {
  const r = remote.config();
  for (const [host, s] of [...servers]) {
    if (host === '127.0.0.1') continue;
    if (!r.enabled || r.bindIp !== host) { s.close(); s.closeAllConnections?.(); servers.delete(host); }
  }
  if (r.enabled && r.bindIp && !servers.has(r.bindIp)) await listen(r.bindIp).catch((e) => console.error('Remoto:', e.message));
}

async function main() {
  await listen('127.0.0.1').catch((e) => { console.error(`Não foi possível abrir 127.0.0.1:${PORT}: ${e.message}`); process.exit(1); });
  await applyRemote();
  applock.init();
  tools.refreshWsl().catch(() => {}); // detecção de WSL em segundo plano (pode ser lenta)
  store.audit('server.start', { port: PORT });
  console.log(`Sentinel rodando em http://127.0.0.1:${PORT}`);
  if (process.argv.includes('--open')) {
    const url = `http://127.0.0.1:${PORT}`;
    if (process.platform === 'win32') {
      const edge = ['C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', 'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe'].find((p) => fs.existsSync(p));
      if (edge) spawn(edge, [`--app=${url}`, '--window-size=1280,820'], { detached: true, stdio: 'ignore' }).unref();
      else spawn('cmd', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref();
    } else if (process.platform === 'darwin') {
      spawn('open', [url], { detached: true, stdio: 'ignore' }).unref();
    } else {
      spawn('xdg-open', [url], { detached: true, stdio: 'ignore' }).unref();
    }
  }
}

process.on('uncaughtException', (e) => { console.error('uncaught:', e); store.audit('server.error', { msg: String(e.message).slice(0, 200) }); });
process.on('unhandledRejection', (e) => { console.error('unhandled:', e); });

if (require.main === module) main();
module.exports = { handle };
