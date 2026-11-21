'use strict';
// Website Scan embutido (Quick / Standard / Deep) e port scan TCP.
// Tudo passa pelo escopo de alvos autorizados antes de enviar qualquer pacote.
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const scope = require('./scope');
const jobs = require('./jobs');
const store = require('./store');

const UA = 'Sentinel-Scan/1.0 (+authorized-security-assessment)';
const sevRank = { high: 0, medium: 1, low: 2, info: 3 };

async function http(url, opts = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeout || 10000);
  try {
    const res = await fetch(url, {
      method: opts.method || 'GET', redirect: 'manual', signal: ctrl.signal,
      headers: { 'User-Agent': UA, Accept: '*/*', ...(opts.headers || {}) },
    });
    let body = '';
    if (opts.body !== false) {
      const buf = Buffer.from(await res.arrayBuffer());
      body = buf.subarray(0, opts.max || 200000).toString('utf8');
    }
    const headers = {};
    res.headers.forEach((v, k) => { headers[k] = v; });
    const cookies = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
    return { status: res.status, headers, cookies, body, url };
  } finally { clearTimeout(timer); }
}

function normalizeUrl(input) {
  let t = String(input || '').trim();
  if (!t) throw new Error('Informe um alvo.');
  if (!/^https?:\/\//i.test(t)) t = 'https://' + t;
  const u = new URL(t);
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Somente http/https.');
  return u;
}

// ---------- verificacoes ----------
const SEC_HEADERS = [
  ['strict-transport-security', 'HSTS ausente', 'medium', 'Sem HSTS o navegador pode ser forçado a usar HTTP (downgrade/sslstrip).'],
  ['content-security-policy', 'CSP ausente', 'medium', 'Sem Content-Security-Policy, XSS tem impacto maior.'],
  ['x-content-type-options', 'X-Content-Type-Options ausente', 'low', 'Use "nosniff" para impedir MIME sniffing.'],
  ['referrer-policy', 'Referrer-Policy ausente', 'low', 'Controla quanto da URL vaza para terceiros.'],
  ['permissions-policy', 'Permissions-Policy ausente', 'info', 'Restringe APIs do navegador (câmera, microfone, geolocalização).'],
];

function analyzeHeaders(r, f) {
  const h = r.headers;
  for (const [key, title, sev, detail] of SEC_HEADERS) if (!h[key]) f.push({ sev, title, detail });
  if (!h['x-frame-options'] && !/frame-ancestors/i.test(h['content-security-policy'] || '')) {
    f.push({ sev: 'medium', title: 'Proteção contra clickjacking ausente', detail: 'Sem X-Frame-Options nem CSP frame-ancestors.' });
  }
  if (h.server && /\d/.test(h.server)) f.push({ sev: 'low', title: 'Versão do servidor exposta', detail: `Server: ${h.server}` });
  if (h['x-powered-by']) f.push({ sev: 'low', title: 'Tecnologia exposta em X-Powered-By', detail: h['x-powered-by'] });
  if (h['access-control-allow-origin'] === '*' && /true/i.test(h['access-control-allow-credentials'] || '')) {
    f.push({ sev: 'high', title: 'CORS permissivo com credenciais', detail: 'Access-Control-Allow-Origin: * combinado com Allow-Credentials.' });
  }
  for (const c of r.cookies) {
    const name = c.split('=')[0];
    const miss = [];
    if (!/;\s*secure/i.test(c)) miss.push('Secure');
    if (!/;\s*httponly/i.test(c)) miss.push('HttpOnly');
    if (!/;\s*samesite/i.test(c)) miss.push('SameSite');
    if (miss.length) f.push({ sev: /sess|auth|token|login/i.test(name) ? 'medium' : 'low', title: `Cookie "${name}" sem ${miss.join(', ')}`, detail: 'Atributos de segurança ausentes no Set-Cookie.' });
  }
}

function detectTech(r) {
  const t = new Set();
  const h = r.headers; const b = r.body || '';
  if (h.server) t.add(h.server);
  if (h['x-powered-by']) t.add(h['x-powered-by']);
  if (h['cf-ray'] || /cloudflare/i.test(h.server || '')) t.add('Cloudflare');
  if (h['x-vercel-id']) t.add('Vercel');
  if (h['x-amz-cf-id']) t.add('AWS CloudFront');
  if (h['x-github-request-id']) t.add('GitHub Pages');
  const ck = r.cookies.join(';');
  if (/PHPSESSID/.test(ck)) t.add('PHP (sessão)');
  if (/laravel_session/.test(ck)) t.add('Laravel');
  if (/JSESSIONID/.test(ck)) t.add('Java (servlet)');
  if (/ASP\.NET/.test(ck)) t.add('ASP.NET');
  const gen = b.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i);
  if (gen) t.add(gen[1]);
  if (/wp-content|wp-includes/.test(b)) t.add('WordPress');
  if (/\/_next\//.test(b)) t.add('Next.js');
  if (/data-reactroot|react(\.|-dom)/i.test(b)) t.add('React');
  if (/ng-version|angular/i.test(b)) t.add('Angular');
  if (/vue(\.|-)/i.test(b)) t.add('Vue');
  if (/jquery[.-]?(\d[\d.]*)?(\.min)?\.js/i.test(b)) t.add('jQuery');
  if (/bootstrap/i.test(b)) t.add('Bootstrap');
  return [...t];
}

function phpCheck(r, f) {
  const m = /PHP\/(\d+)\.(\d+)(?:\.(\d+))?/i.exec(r.headers['x-powered-by'] || r.headers.server || '');
  if (!m) return null;
  const v = `${m[1]}.${m[2]}${m[3] ? '.' + m[3] : ''}`;
  const major = +m[1], minor = +m[2];
  if (major < 8 || (major === 8 && minor < 2)) {
    f.push({ sev: 'high', title: `PHP ${v} fora de suporte (EOL)`, detail: 'Versoes anteriores ao PHP 8.2 não recebem mais correções de segurança. Atualize.' });
  } else f.push({ sev: 'info', title: `PHP ${v} detectado`, detail: 'Verifique se há atualização de segurança disponível.' });
  return v;
}

function tlsInfo(host, port = 443) {
  return new Promise((resolve) => {
    const sock = tls.connect({ host: net.isIP(host) ? undefined : host, servername: net.isIP(host) ? undefined : host, port, rejectUnauthorized: false, timeout: 8000 }, () => {
      const c = sock.getPeerCertificate();
      const out = {
        protocol: sock.getProtocol(), cipher: sock.getCipher()?.name, authorized: sock.authorized, authError: sock.authorizationError || null,
        subject: c?.subject?.CN || null, issuer: c?.issuer?.O || c?.issuer?.CN || null,
        validFrom: c?.valid_from || null, validTo: c?.valid_to || null,
        daysLeft: c?.valid_to ? Math.floor((new Date(c.valid_to) - Date.now()) / 86400000) : null,
        san: c?.subjectaltname || null,
      };
      sock.end(); resolve(out);
    });
    sock.on('timeout', () => { sock.destroy(); resolve({ error: 'timeout' }); });
    sock.on('error', (e) => resolve({ error: e.message }));
  });
}

function tlsFindings(info, f) {
  if (!info || info.error) { f.push({ sev: 'info', title: 'TLS não avaliado', detail: info?.error || 'sem resposta na porta 443' }); return; }
  if (!info.authorized) f.push({ sev: 'high', title: 'Certificado não confiável', detail: info.authError });
  if (info.daysLeft !== null && info.daysLeft < 0) f.push({ sev: 'high', title: 'Certificado expirado', detail: `Expirou em ${info.validTo}` });
  else if (info.daysLeft !== null && info.daysLeft < 15) f.push({ sev: 'medium', title: `Certificado expira em ${info.daysLeft} dias`, detail: info.validTo });
  if (/TLSv1(\.0|\.1)?$/.test(info.protocol || '')) f.push({ sev: 'high', title: `Protocolo antigo negociado: ${info.protocol}`, detail: 'Desative TLS 1.0/1.1.' });
}

const DEEP_PATHS = [
  '.git/HEAD', '.git/config', '.env', '.env.local', '.env.production', '.DS_Store', '.htaccess', '.htpasswd', 'config.php', 'config.php.bak', 'wp-config.php.bak',
  'backup.zip', 'backup.sql', 'db.sql', 'dump.sql', 'database.sql', 'site.zip', 'www.zip',
  'phpinfo.php', 'info.php', 'test.php', 'server-status', 'server-info', 'admin/', 'administrator/', 'login', 'wp-login.php', 'wp-admin/', 'xmlrpc.php',
  'phpmyadmin/', 'pma/', 'adminer.php', 'console', 'actuator', 'actuator/env', 'actuator/health', 'api/', 'api/v1/', 'swagger.json', 'swagger-ui/', 'openapi.json', 'graphql',
  'robots.txt', 'sitemap.xml', '.well-known/security.txt', 'crossdomain.xml', 'composer.json', 'package.json', 'Dockerfile', 'docker-compose.yml', 'web.config', 'WEB-INF/web.xml',
  'cgi-bin/', 'old/', 'bak/', 'tmp/', 'uploads/', 'logs/', 'error_log', 'debug.log',
];

async function discovery(base, log, f) {
  const rnd = crypto.randomBytes(6).toString('hex');
  let baseline = null;
  try { baseline = await http(new URL(`/${rnd}`, base).href, { timeout: 8000, max: 4000 }); } catch { /* ignore */ }
  const found = [];
  let idx = 0;
  const worker = async () => {
    while (idx < DEEP_PATHS.length) {
      const p = DEEP_PATHS[idx++];
      try {
        const r = await http(new URL('/' + p, base).href, { timeout: 8000, max: 4000 });
        const soft = baseline && r.status === baseline.status && Math.abs((r.body || '').length - (baseline.body || '').length) < 40;
        if (soft) continue;
        if (r.status === 200 || r.status === 401 || r.status === 403) {
          const body = r.body || '';
          const html = /text\/html/i.test(r.headers['content-type'] || '');
          let sev = null; let title = null;
          if (p.startsWith('.git/') && r.status === 200 && /^ref:|\[core\]/.test(body)) { sev = 'high'; title = `Repositorio Git exposto (/${p})`; }
          else if (/^\.env/.test(p) && r.status === 200 && !html && /=/.test(body)) { sev = 'high'; title = `Arquivo de ambiente exposto (/${p})`; }
          else if (/\.(sql|zip|bak)$/.test(p) && r.status === 200 && !html) { sev = 'high'; title = `Arquivo de backup acessível (/${p})`; }
          else if (/phpinfo|info\.php/.test(p) && r.status === 200 && /PHP Version/i.test(body)) { sev = 'medium'; title = `phpinfo() exposto (/${p})`; }
          else if (/actuator\/env|server-status|server-info/.test(p) && r.status === 200) { sev = 'medium'; title = `Endpoint de diagnóstico exposto (/${p})`; }
          else if (/phpmyadmin|adminer|pma\//.test(p) && r.status !== 404) { sev = 'medium'; title = `Painel de banco acessível (/${p})`; }
          else if (/admin|login|console/.test(p) && r.status !== 404) { sev = 'info'; title = `Área administrativa encontrada (/${p}) [${r.status}]`; }
          else if (r.status === 200) { sev = 'info'; title = `Recurso encontrado (/${p})`; }
          if (title) { found.push(p); f.push({ sev, title, detail: `HTTP ${r.status}` }); log(`  [${r.status}] /${p}`); }
        }
      } catch { /* ignore */ }
    }
  };
  await Promise.all([worker(), worker(), worker(), worker()]);
  return found;
}

async function methodsCheck(base, f) {
  try {
    const r = await http(base, { method: 'OPTIONS', body: false, timeout: 8000 });
    const allow = r.headers.allow || '';
    if (/\b(TRACE|PUT|DELETE)\b/i.test(allow)) f.push({ sev: 'medium', title: 'Métodos HTTP arriscados habilitados', detail: `Allow: ${allow}` });
    return allow || null;
  } catch { return null; }
}

// ---------- orquestracao ----------
async function runWebScan(job, targetInput, level) {
  const log = (m) => jobs.emit(job, m);
  const findings = []; const result = { target: null, level, startedAt: Date.now() };
  try {
    const u = normalizeUrl(targetInput);
    scope.assertAllowed(u.href);
    result.target = u.href;
    log(`Alvo: ${u.href}  |  Nível: ${level}`);
    log('Escopo autorizado: ok');

    log('Requisição inicial...');
    let first;
    try { first = await http(u.href); } catch (e) { throw new Error(`Sem resposta do alvo: ${e.cause?.code || e.message}`); }
    result.status = first.status; result.headers = first.headers;
    log(`HTTP ${first.status}  (${first.headers.server || 'servidor não informado'})`);

    let r = first; let hops = 0;
    while ([301, 302, 303, 307, 308].includes(r.status) && r.headers.location && hops < 4) {
      const next = new URL(r.headers.location, r.url).href;
      log(`  redireciona -> ${next}`);
      scope.assertAllowed(next);
      r = await http(next); hops++;
    }
    result.finalUrl = r.url; result.finalStatus = r.status;

    analyzeHeaders(r, findings);
    result.php = phpCheck(r, findings);
    result.tech = detectTech(r);
    if (result.tech.length) log(`Tecnologias: ${result.tech.join(', ')}`);

    if (r.status === 403 || r.status === 401) {
      findings.push({ sev: 'info', title: `Resposta com acesso controlado (HTTP ${r.status})`, detail: 'Avaliação limitada: o alvo bloqueou ou exige autenticação. Resultados de cabeçalhos podem refletir um WAF/CDN, não a aplicação.' });
      result.limited = true;
    }

    if (level !== 'quick') {
      log('Avaliando TLS...');
      const host = new URL(r.url).hostname;
      if (new URL(r.url).protocol === 'https:' || u.protocol === 'https:') {
        result.tls = await tlsInfo(host);
        tlsFindings(result.tls, findings);
        if (result.tls && !result.tls.error) log(`TLS ${result.tls.protocol}  cert até ${result.tls.validTo} (${result.tls.daysLeft}d)`);
      } else findings.push({ sev: 'high', title: 'Site servido sem HTTPS', detail: 'O alvo responde apenas em HTTP.' });
      if (u.protocol === 'https:') {
        try {
          const plain = await http(`http://${u.host}/`, { body: false, timeout: 6000 });
          const toHttps = [301, 302, 307, 308].includes(plain.status) && /^https:/i.test(plain.headers.location || '');
          if (!toHttps) findings.push({ sev: 'medium', title: 'HTTP não redireciona para HTTPS', detail: `GET http://${u.host}/ -> ${plain.status}` });
        } catch { /* porta 80 fechada: ok */ }
      }
      log('Coletando robots.txt / security.txt...');
      for (const p of ['robots.txt', '.well-known/security.txt']) {
        try {
          const x = await http(new URL('/' + p, r.url).href, { timeout: 6000, max: 20000 });
          if (x.status === 200 && !/text\/html/i.test(x.headers['content-type'] || '')) {
            result[p] = true; log(`  encontrado: /${p}`);
            if (p === 'robots.txt') {
              const dis = [...x.body.matchAll(/^\s*Disallow:\s*(\S+)/gim)].map((m) => m[1]).filter((d) => /admin|backup|private|secret|config|\.bak|old|tmp/i.test(d));
              if (dis.length) findings.push({ sev: 'info', title: 'robots.txt revela caminhos sensíveis', detail: dis.slice(0, 8).join(', ') });
            }
          } else if (p.includes('security.txt')) findings.push({ sev: 'info', title: 'security.txt ausente', detail: 'Publique um canal de contato para reporte de vulnerabilidades.' });
        } catch { /* ignore */ }
      }
    }

    if (level === 'deep') {
      log('Descoberta ativa de caminhos comuns (rate limitado)...');
      result.allow = await methodsCheck(r.url, findings);
      result.discovered = await discovery(r.url, log, findings);
      log(`Descoberta concluída: ${result.discovered.length} caminho(s)`);
    }
  } catch (e) {
    findings.push({ sev: 'info', title: 'Scan interrompido', detail: e.message });
    log(`Erro: ${e.message}`, 'err');
    result.error = e.message;
  }

  findings.sort((a, b) => sevRank[a.sev] - sevRank[b.sev]);
  result.findings = findings;
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((x) => counts[x.sev]++);
  result.counts = counts;
  result.verdict = result.error ? 'Falhou' : result.limited ? 'Avaliação limitada' : counts.high ? 'Risco alto' : counts.medium ? 'Risco médio' : counts.low ? 'Risco baixo' : 'Sem achados relevantes';
  result.endedAt = Date.now();
  log(`Veredito: ${result.verdict}  (alto ${counts.high} / médio ${counts.medium} / baixo ${counts.low} / info ${counts.info})`);
  job.meta.result = result;
  const entry = { id: job.id, ...result, headers: undefined };
  store.update('scanHistory', (h) => [entry, ...h].slice(0, 100), []);
  store.audit('scan.web', { target: result.target, level, verdict: result.verdict });
  jobs.finish(job, result.error ? 'failed' : 'done', result.error ? 1 : 0);
}

function startWebScan(target, level) {
  if (!['quick', 'standard', 'deep'].includes(level)) throw new Error('Nível inválido.');
  const u = normalizeUrl(target);
  scope.assertAllowed(u.href); // falha rápido, antes de criar o job
  const job = jobs.create('webscan', `Website scan (${level}): ${u.hostname}`, { target: u.href, level });
  runWebScan(job, target, level);
  return job;
}

// ---------- port scan TCP embutido ----------
const TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631, 993, 995, 1433, 1521, 1723, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900, 5985, 6379, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 11434, 27017];
const SERVICE = { 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios', 143: 'imap', 443: 'https', 445: 'smb', 465: 'smtps', 587: 'submission', 631: 'ipp', 993: 'imaps', 995: 'pop3s', 1433: 'mssql', 1521: 'oracle', 1723: 'pptp', 2049: 'nfs', 2375: 'docker', 3000: 'dev-http', 3306: 'mysql', 3389: 'rdp', 5000: 'dev-http', 5432: 'postgres', 5900: 'vnc', 5985: 'winrm', 6379: 'redis', 8000: 'http-alt', 8008: 'http-alt', 8080: 'http-proxy', 8081: 'http-alt', 8443: 'https-alt', 8888: 'http-alt', 9000: 'http-alt', 9200: 'elasticsearch', 11434: 'ollama', 27017: 'mongodb' };

function probe(host, port, timeout = 1200) {
  return new Promise((resolve) => {
    const s = new net.Socket(); let banner = ''; let done = false; let connected = false;
    const end = (open) => { if (done) return; done = true; s.destroy(); resolve({ port, open, banner: banner.trim().slice(0, 100) }); };
    s.setTimeout(timeout);
    // Conectou = aberta. Se não mandar banner em 500 ms (ex.: HTTP), ainda conta como aberta.
    s.once('connect', () => { connected = true; s.setTimeout(500); });
    s.on('data', (d) => { banner += d.toString('latin1').replace(/[^\x20-\x7e\n]/g, ''); end(true); });
    s.on('timeout', () => end(connected));
    s.once('error', () => end(false));
    s.connect(port, host);
  });
}

function parsePorts(spec) {
  if (!spec || spec === 'top') return TOP_PORTS;
  const out = new Set();
  for (const part of String(spec).split(',')) {
    const m = part.trim().match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!m) throw new Error(`Porta inválida: ${part}`);
    const a = +m[1], b = m[2] ? +m[2] : a;
    if (a < 1 || b > 65535 || a > b) throw new Error(`Faixa inválida: ${part}`);
    if (b - a > 2000) throw new Error('Faixa grande demais (max 2000 portas por faixa).');
    for (let p = a; p <= b; p++) out.add(p);
  }
  if (out.size > 5000) throw new Error('Máximo de 5000 portas.');
  return [...out];
}

function startPortScan(target, portSpec) {
  const host = scope.assertAllowed(target);
  const ports = parsePorts(portSpec);
  const job = jobs.create('portscan', `Port scan TCP: ${host}`, { target: host });
  (async () => {
    jobs.emit(job, `Port scan TCP connect em ${host} (${ports.length} portas)`);
    const open = []; let i = 0;
    const worker = async () => {
      while (i < ports.length && job.status === 'running') {
        const r = await probe(host, ports[i++]);
        if (r.open) { open.push(r); jobs.emit(job, `${String(r.port).padEnd(6)} aberta   ${(SERVICE[r.port] || '?').padEnd(14)} ${r.banner}`); }
      }
    };
    await Promise.all(Array.from({ length: 150 }, worker));
    open.sort((a, b) => a.port - b.port);
    job.meta.result = { host, open };
    jobs.emit(job, `Concluído: ${open.length} porta(s) aberta(s).`, 'sys');
    store.audit('scan.ports', { host, open: open.length });
    jobs.finish(job, 'done', 0);
  })();
  return job;
}

function history() { return store.get('scanHistory', []); }
function clearHistory() { store.set('scanHistory', []); }
function deleteHistory(id) { store.update('scanHistory', (h) => h.filter((x) => x.id !== id), []); }

module.exports = { startWebScan, startPortScan, history, clearHistory, deleteHistory, probe };
