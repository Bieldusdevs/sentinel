'use strict';
// Utilitários de rede: geo-IP, temp mail (mail.tm), gerenciador de proxy do Windows e teste de proxies.
const net = require('net');
const dns = require('dns').promises;
const crypto = require('crypto');
const { execFile } = require('child_process');
const store = require('./store');

async function jfetch(url, opts = {}) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), opts.timeout || 12000);
  try {
    const r = await fetch(url, { ...opts, signal: ctrl.signal, headers: { 'User-Agent': 'Sentinel/1.0', Accept: 'application/json', ...(opts.headers || {}) } });
    const text = await r.text();
    let data = null; try { data = text ? JSON.parse(text) : null; } catch { /* não-JSON */ }
    return { ok: r.ok, status: r.status, data, text };
  } finally { clearTimeout(t); }
}

// ---------- Geo-IP ----------
async function geoip(query) {
  let q = String(query || '').trim();
  let resolved = null;
  if (q && !net.isIP(q)) {
    if (!/^[a-z0-9.-]{1,253}$/i.test(q.replace(/^https?:\/\//i, '').split('/')[0])) throw new Error('Informe um IP ou domínio válido.');
    q = q.replace(/^https?:\/\//i, '').split('/')[0];
    try { resolved = (await dns.lookup(q)).address; } catch { throw new Error('Domínio não resolveu.'); }
  }
  const target = resolved || q;
  const r = await jfetch(`https://ipwho.is/${encodeURIComponent(target)}`);
  if (!r.data || r.data.success === false) throw new Error(r.data?.message || 'Consulta falhou.');
  const d = r.data;
  let rdns = null; try { rdns = (await dns.reverse(d.ip))[0] || null; } catch { /* sem PTR */ }
  return {
    query: q || 'meu IP', ip: d.ip, type: d.type, resolvedFrom: resolved ? q : null, rdns,
    continent: d.continent, country: d.country, countryCode: d.country_code, region: d.region, city: d.city, postal: d.postal,
    lat: d.latitude, lon: d.longitude, timezone: d.timezone?.id, utc: d.timezone?.utc,
    asn: d.connection?.asn, org: d.connection?.org, isp: d.connection?.isp, domain: d.connection?.domain,
    map: d.latitude != null ? `https://www.openstreetmap.org/?mlat=${d.latitude}&mlon=${d.longitude}#map=10/${d.latitude}/${d.longitude}` : null,
  };
}

// ---------- Temp mail ----------
// mail.tm e mail.gw usam a MESMA API (API Platform). Dependendo do header Accept, /domains e /messages
// vem como array puro OU embrulhado em { "hydra:member": [...] }. O helper abaixo aceita os dois,
// e o serviço tem um provedor reserva caso o principal esteja fora do ar.
const TM_BASES = ['https://api.mail.tm', 'https://api.mail.gw'];
const members = (data) => (Array.isArray(data) ? data : (data?.['hydra:member'] || data?.member || []));

async function tmCreate() {
  let lastErr = 'Serviço de e-mail temporário indisponível.';
  for (const base of TM_BASES) {
    try {
      const dom = await jfetch(`${base}/domains?page=1`);
      const domain = (members(dom.data).find((d) => d.isActive !== false) || members(dom.data)[0])?.domain;
      if (!domain) { lastErr = 'Nenhum domínio disponível no provedor.'; continue; }
      const address = `${crypto.randomBytes(5).toString('hex')}@${domain}`;
      const password = crypto.randomBytes(18).toString('base64url');
      const acc = await jfetch(`${base}/accounts`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address, password }) });
      if (!acc.ok || !acc.data?.id) { lastErr = acc.data?.message || `Falha ao criar a caixa (${acc.status}).`; continue; }
      const tok = await jfetch(`${base}/token`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address, password }) });
      if (!tok.data?.token) { lastErr = 'Falha ao autenticar a caixa.'; continue; }
      const box = { address, password, token: tok.data.token, id: acc.data.id, base, createdAt: Date.now() };
      store.update('tempmail', (l) => [box, ...l].slice(0, 10), []);
      store.audit('tempmail.create', { address, base });
      return { address, createdAt: box.createdAt };
    } catch (e) { lastErr = e.message; }
  }
  throw new Error(lastErr);
}

function tmBoxes() { return store.get('tempmail', []).map((b) => ({ address: b.address, createdAt: b.createdAt })); }
function tmFind(address) { const b = store.get('tempmail', []).find((x) => x.address === address); if (!b) throw new Error('Caixa não encontrada.'); return b; }
const tmBase = (b) => b.base || TM_BASES[0];

async function tmMessages(address) {
  const b = tmFind(address);
  const r = await jfetch(`${tmBase(b)}/messages?page=1`, { headers: { Authorization: `Bearer ${b.token}` } });
  if (!r.ok) throw new Error('Falha ao listar mensagens.');
  return members(r.data).map((m) => ({ id: m.id, from: m.from?.address, name: m.from?.name, subject: m.subject, intro: m.intro, at: m.createdAt, seen: m.seen }));
}

async function tmMessage(address, id) {
  const b = tmFind(address);
  if (!/^[a-f0-9]{24}$/i.test(id)) throw new Error('Id inválido.');
  const r = await jfetch(`${tmBase(b)}/messages/${id}`, { headers: { Authorization: `Bearer ${b.token}` } });
  if (!r.ok) throw new Error('Mensagem não encontrada.');
  const m = r.data;
  return { id: m.id, from: m.from?.address, subject: m.subject, at: m.createdAt, text: m.text || '', html: Array.isArray(m.html) ? m.html.join('\n') : (m.html || ''), attachments: (m.attachments || []).length };
}

async function tmDelete(address) {
  const b = tmFind(address);
  await jfetch(`${tmBase(b)}/accounts/${b.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${b.token}` } }).catch(() => {});
  store.update('tempmail', (l) => l.filter((x) => x.address !== address), []);
}

// ---------- Proxy do Windows ----------
const REG_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
function reg(args) {
  return new Promise((resolve, reject) => execFile('reg', args, { windowsHide: true, timeout: 8000, encoding: 'utf8' }, (e, o, se) => (e ? reject(new Error(se || e.message)) : resolve(o))));
}
async function sysProxyGet() {
  if (process.platform !== 'win32') return { supported: false };
  const o = await reg(['query', REG_KEY]);
  const val = (n) => o.match(new RegExp(`^\\s+${n}\\s+REG_\\w+\\s+(.*)$`, 'm'))?.[1]?.trim() || '';
  return { supported: true, enabled: parseInt(val('ProxyEnable'), 16) === 1, server: val('ProxyServer'), bypass: val('ProxyOverride'), pac: val('AutoConfigURL') };
}
async function sysProxySet({ enabled, server, bypass }) {
  if (enabled) {
    if (!/^([a-z0-9.-]+|\[[0-9a-f:]+\]):\d{1,5}$/i.test(String(server || ''))) throw new Error('Use host:porta (ex.: 127.0.0.1:8080).');
    await reg(['add', REG_KEY, '/v', 'ProxyServer', '/t', 'REG_SZ', '/d', server, '/f']);
    if (bypass) {
      if (!/^[\w.*;<>\-:]+$/.test(bypass)) throw new Error('Lista de exceções inválida.');
      await reg(['add', REG_KEY, '/v', 'ProxyOverride', '/t', 'REG_SZ', '/d', bypass, '/f']);
    }
  }
  await reg(['add', REG_KEY, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', enabled ? '1' : '0', '/f']);
  store.audit('proxy.system', { enabled: !!enabled, server: enabled ? server : null });
  return sysProxyGet();
}

// ---------- Lista de proxies salvos + teste ----------
function proxies() { return store.get('proxies', []); }
function proxyAdd({ name, type, host, port }) {
  if (!['http', 'socks5'].includes(type)) throw new Error('Tipo deve ser http ou socks5.');
  if (!/^[a-z0-9.-]{1,253}$/i.test(host || '')) throw new Error('Host inválido.');
  port = +port; if (!(port > 0 && port < 65536)) throw new Error('Porta inválida.');
  const p = { id: crypto.randomBytes(4).toString('hex'), name: String(name || host).slice(0, 40), type, host, port };
  store.update('proxies', (l) => [...l, p], []); return p;
}
function proxyRemove(id) { store.update('proxies', (l) => l.filter((p) => p.id !== id), []); }

function proxyTest(p) {
  return new Promise((resolve) => {
    const t0 = Date.now(); const s = new net.Socket(); let phase = 0;
    const done = (r) => { s.destroy(); resolve({ ...r, ms: Date.now() - t0 }); };
    s.setTimeout(6000, () => done({ ok: false, error: 'timeout' }));
    s.once('error', (e) => done({ ok: false, error: e.code || e.message }));
    s.connect(p.port, p.host, () => {
      if (p.type === 'socks5') s.write(Buffer.from([5, 1, 0]));
      else s.write('CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n');
    });
    s.on('data', (d) => {
      if (p.type === 'socks5') return done(d[0] === 5 ? { ok: true, detail: d[1] === 0 ? 'SOCKS5 sem autenticação' : d[1] === 2 ? 'SOCKS5 com usuário/senha' : 'SOCKS5' } : { ok: false, error: 'não e SOCKS5' });
      const line = d.toString('latin1').split('\r\n')[0];
      done(/^HTTP\/1\.[01] (200|407)/.test(line) ? { ok: true, detail: line } : { ok: false, error: line.slice(0, 60) || 'sem resposta' });
    });
    phase++;
  });
}

module.exports = { geoip, tmCreate, tmBoxes, tmMessages, tmMessage, tmDelete, sysProxyGet, sysProxySet, proxies, proxyAdd, proxyRemove, proxyTest };
