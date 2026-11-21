'use strict';
// Mapas: satélite, aviação, clima e ameaças reais. Tudo passa pelo servidor (proxy de tiles),
// então o CSP do app continua restrito a 'self' e o seu IP não vai direto para os provedores externos.
// Fontes gratuitas, sem chave: Esri World Imagery (satélite), OpenStreetMap (base), OpenSky Network
// (aviação, anônimo), RainViewer (radar de chuva), blocklist.de (IPs reportados atacando, sem chave).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const store = require('./store');
const jobs = require('./jobs');

const UA = 'Sentinel/1.0 (app local; uso pessoal)';
const TILE_DIR = path.join(store.DATA_DIR, 'tilecache');
fs.mkdirSync(TILE_DIR, { recursive: true });

async function jfetch(url, opts = {}) {
  const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), opts.timeout || 15000);
  try { return await fetch(url, { ...opts, signal: ctrl.signal, headers: { 'User-Agent': UA, ...(opts.headers || {}) } }); }
  finally { clearTimeout(t); }
}

// ---------- proxy de tiles (satélite e mapa-base OSM), com cache em disco ----------
const PROVIDERS = {
  'sat': (z, x, y) => `https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/${z}/${y}/${x}`,
  'sat-ref': (z, x, y) => `https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/${z}/${y}/${x}`,
  'osm': (z, x, y, sub) => `https://${sub}.tile.openstreetmap.org/${z}/${x}/${y}.png`,
};
const SUBS = ['a', 'b', 'c'];

function tileCachePath(provider, z, x, y) {
  const h = crypto.createHash('sha1').update(`${provider}/${z}/${x}/${y}`).digest('hex');
  return path.join(TILE_DIR, h.slice(0, 2), h + (provider === 'osm' || provider.startsWith('sat') ? '.png' : '.bin'));
}

async function tile(provider, z, x, y) {
  z = +z; x = +x; y = +y;
  if (!PROVIDERS[provider] || !Number.isInteger(z) || !Number.isInteger(x) || !Number.isInteger(y) || z < 0 || z > 19) throw Object.assign(new Error('Tile inválido.'), { status: 400 });
  const cp = tileCachePath(provider, z, x, y);
  try { return { buf: fs.readFileSync(cp), type: 'image/png' }; } catch { /* sem cache ainda */ }
  const url = PROVIDERS[provider](z, x, y, SUBS[(x + y) % SUBS.length]);
  const r = await jfetch(url, { timeout: 10000 });
  if (!r.ok) throw Object.assign(new Error(`Provedor de mapa respondeu ${r.status}.`), { status: 502 });
  const buf = Buffer.from(await r.arrayBuffer());
  try { fs.mkdirSync(path.dirname(cp), { recursive: true }); fs.writeFileSync(cp, buf); } catch { /* cache best-effort */ }
  return { buf, type: r.headers.get('content-type') || 'image/png' };
}

// ---------- clima: RainViewer (radar de precipitação) ----------
let rvMeta = null; let rvMetaAt = 0;
async function rainviewerFrames() {
  if (rvMeta && Date.now() - rvMetaAt < 5 * 60 * 1000) return rvMeta;
  const r = await jfetch('https://api.rainviewer.com/public/weather-maps.json');
  if (!r.ok) throw new Error('RainViewer indisponível.');
  const j = await r.json();
  const frames = [...(j.radar?.past || []), ...(j.radar?.nowcast || [])].map((f) => ({ time: f.time, path: f.path }));
  rvMeta = { host: j.host, frames }; rvMetaAt = Date.now();
  return rvMeta;
}

async function weatherTile(frameIndex, z, x, y) {
  z = +z; x = +x; y = +y; frameIndex = +frameIndex;
  const meta = await rainviewerFrames();
  const f = meta.frames[frameIndex];
  if (!f) throw Object.assign(new Error('Quadro de radar inválido.'), { status: 400 });
  const url = `${meta.host}${f.path}/256/${z}/${x}/${y}/2/1_1.png`;
  const r = await jfetch(url, { timeout: 10000 });
  if (!r.ok) throw Object.assign(new Error('Radar indisponível.'), { status: 502 });
  return { buf: Buffer.from(await r.arrayBuffer()), type: 'image/png' };
}

// ---------- aviação: OpenSky Network (posições públicas, anônimo) ----------
let lastAviationAt = 0;
async function aviation(bbox) {
  // uso anônimo do OpenSky: respeite o intervalo (evita bloqueio por excesso de chamadas)
  if (Date.now() - lastAviationAt < 4000) throw Object.assign(new Error('Aguarde alguns segundos entre atualizações.'), { status: 429 });
  lastAviationAt = Date.now();
  const [lamin, lomin, lamax, lomax] = bbox;
  for (const v of [lamin, lomin, lamax, lomax]) if (!Number.isFinite(v)) throw new Error('Área inválida.');
  const url = `https://opensky-network.org/api/states/all?lamin=${lamin}&lomin=${lomin}&lamax=${lamax}&lomax=${lomax}`;
  const r = await jfetch(url, { timeout: 12000 });
  if (!r.ok) throw Object.assign(new Error(`OpenSky respondeu ${r.status}.`), { status: 502 });
  const j = await r.json();
  const planes = (j.states || []).filter((s) => s[5] != null && s[6] != null && !s[8]).map((s) => ({
    icao: s[0], callsign: (s[1] || '').trim(), country: s[2], lon: s[5], lat: s[6],
    altitude: s[7], velocity: s[9], heading: s[10], vrate: s[11], onGround: !!s[8],
  }));
  return { planes, at: j.time };
}

// ---------- ameaças reais: IPs reportados atacando (blocklist.de) + geolocalização ----------
const BL_LISTS = { ssh: 'SSH (força bruta)', mail: 'E-mail (spam/invasão)', apache: 'Web (Apache)', bots: 'Bots maliciosos', bruteforcelogin: 'Força bruta de login', strongips: 'Mais reportados (48h)' };

async function fetchList(name) {
  const r = await jfetch(`https://lists.blocklist.de/lists/${name}.txt`, { timeout: 15000 });
  if (!r.ok) return [];
  return (await r.text()).split('\n').map((l) => l.trim()).filter((l) => /^\d{1,3}(\.\d{1,3}){3}$/.test(l));
}

function geoCache() { return store.get('geoCache', {}); }
function geoCacheSet(ip, val) {
  store.update('geoCache', (c) => {
    c[ip] = { ...val, at: Date.now() };
    const keys = Object.keys(c);
    if (keys.length > 600) for (const k of keys.sort((a, b) => c[a].at - c[b].at).slice(0, keys.length - 600)) delete c[k];
    return c;
  }, {});
}

async function geoLookup(ip) {
  const cached = geoCache()[ip];
  if (cached && Date.now() - cached.at < 7 * 24 * 3600 * 1000) return cached;
  try {
    const r = await jfetch(`https://ipwho.is/${ip}`, { timeout: 6000 });
    const j = await r.json();
    if (!j.success) return null;
    const val = { lat: j.latitude, lon: j.longitude, city: j.city, country: j.country, countryCode: j.country_code, org: j.connection?.isp || j.connection?.org || null };
    geoCacheSet(ip, val);
    return { ...val, at: Date.now() };
  } catch { return null; }
}

async function pool(items, limit, fn) {
  const out = []; let i = 0;
  await Promise.all(Array.from({ length: limit }, async () => { while (i < items.length) { const idx = i++; out[idx] = await fn(items[idx], idx); } }));
  return out;
}

// alvos de scan são colisões frequentes com os IPs de ataque de teste do proprio CyberLab etc.: ignora loopback
const skipIp = (ip) => /^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip);

function startThreatRefresh(capIps = 120) {
  const job = jobs.create('threats', 'Atualizando mapa de ameaças (blocklist.de)');
  (async () => {
    try {
      jobs.emit(job, 'Baixando listas de IPs reportados (blocklist.de)...', 'sys');
      const names = Object.keys(BL_LISTS);
      const lists = {}; for (const n of names) lists[n] = new Set((await fetchList(n)).filter((ip) => !skipIp(ip)));
      jobs.emit(job, names.map((n) => `${n}: ${lists[n].size}`).join('  |  '));

      // prioriza quem aparece em mais listas (mais reportado), depois a lista "strongips"
      const scores = new Map();
      for (const n of names) for (const ip of lists[n]) scores.set(ip, (scores.get(ip) || 0) + (n === 'strongips' ? 3 : 1));
      const ranked = [...scores.entries()].sort((a, b) => b[1] - a[1]).slice(0, capIps).map(([ip]) => ip);

      jobs.emit(job, `Geolocalizando ${ranked.length} IP(s) (com cache de 7 dias)...`);
      let done = 0;
      const points = await pool(ranked, 6, async (ip) => {
        const g = await geoLookup(ip); done++;
        if (done % 20 === 0) jobs.emit(job, `  ${done}/${ranked.length}...`);
        if (!g || g.lat == null) return null;
        const categories = names.filter((n) => lists[n].has(ip));
        return { ip, lat: g.lat, lon: g.lon, city: g.city, country: g.country, countryCode: g.countryCode, org: g.org, categories, score: scores.get(ip) };
      });
      const result = { points: points.filter(Boolean), total: { ssh: lists.ssh.size, mail: lists.mail.size, apache: lists.apache.size, bots: lists.bots.size }, generatedAt: Date.now() };
      store.set('threatMap', result);
      jobs.emit(job, `Pronto: ${result.points.length} ponto(s) no mapa.`, 'sys');
      jobs.finish(job, 'done', 0);
    } catch (e) { jobs.emit(job, `Erro: ${e.message}`, 'err'); jobs.finish(job, 'failed', 1); }
  })();
  return job;
}

function threatState() { return store.get('threatMap', null); }

module.exports = { tile, weatherTile, rainviewerFrames, aviation, startThreatRefresh, threatState, BL_LISTS };
