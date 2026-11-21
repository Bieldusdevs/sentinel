'use strict';
// Nucleo do front: helpers, API, modais, streams, markdown seguro, roteador.
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const icon = (n, s = 16, cls = '') => `<svg class="ic ${cls}" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n] || ''}</svg>`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const fmtBytes = (n) => { if (n == null) return ''; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return `${n.toFixed(i ? 1 : 0)} ${u[i]}`; };
const fmtTime = (t) => new Date(t).toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });
const fmtUp = (s) => { const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return `${d ? d + 'd ' : ''}${h}h ${m}m`; };

// ---------- API ----------
class ApiError extends Error { constructor(m, status) { super(m); this.status = status; } }
async function api(method, path, body) {
  const r = await fetch(path, { method, headers: { 'Content-Type': 'application/json', 'X-Sentinel': '1' }, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' });
  let j = null; try { j = await r.json(); } catch { /* sem corpo */ }
  if (r.status === 401 && !path.startsWith('/api/auth/')) { App.showAuth(); throw new ApiError('Sessão expirada.', 401); }
  if (!r.ok) throw new ApiError(j?.error || `Erro ${r.status}`, r.status);
  return j;
}
const get = (p) => api('GET', p); const post = (p, b = {}) => api('POST', p, b); const del = (p, b = {}) => api('DELETE', p, b);

// executa e mostra erro como toast
async function safe(fn, btn) {
  if (btn) { btn.disabled = true; btn.dataset.t = btn.innerHTML; }
  try { return await fn(); } catch (e) { if (e.status !== 401) toast(e.message, 'bad'); return undefined; } finally { if (btn) { btn.disabled = false; } }
}

// ---------- UI ----------
function toast(msg, kind = '') {
  const el = document.createElement('div'); el.className = `toast ${kind}`; el.textContent = msg; $('#toasts').append(el);
  setTimeout(() => el.remove(), kind === 'bad' ? 7000 : 3500);
}

function modal({ title, body, actions = [{ label: 'Fechar', value: null }], onMount }) {
  return new Promise((resolve) => {
    const scrim = document.createElement('div'); scrim.className = 'scrim';
    scrim.innerHTML = `<div class="modal" role="dialog" aria-modal="true" aria-label="${esc(title)}"><div class="modal-head"><h2>${esc(title)}</h2><button class="btn icon ghost" data-x aria-label="Fechar">${icon('x')}</button></div><div class="modal-body">${body}</div><div class="modal-foot">${actions.map((a, i) => `<button class="btn ${a.kind || ''}" data-i="${i}">${esc(a.label)}</button>`).join('')}</div></div>`;
    const close = (v) => { scrim.remove(); document.removeEventListener('keydown', onKey); resolve(v); };
    const collect = () => Object.fromEntries($$('[name]', scrim).map((f) => [f.name, f.type === 'checkbox' ? f.checked : f.value]));
    const onKey = (e) => { if (e.key === 'Escape') close(null); };
    document.addEventListener('keydown', onKey);
    scrim.addEventListener('mousedown', (e) => { if (e.target === scrim) close(null); });
    $('[data-x]', scrim).onclick = () => close(null);
    $$('[data-i]', scrim).forEach((b) => { b.onclick = () => { const a = actions[+b.dataset.i]; close(a.value === 'form' ? { ok: true, ...collect() } : a.value); }; });
    document.body.append(scrim); onMount?.(scrim); $('input,select,textarea', scrim)?.focus();
  });
}
const confirmBox = (text, { title = 'Confirmar', ok = 'Confirmar', danger = false } = {}) =>
  modal({ title, body: `<p class="muted">${text}</p>`, actions: [{ label: 'Cancelar', value: false }, { label: ok, value: true, kind: danger ? 'danger' : 'primary' }] });
async function askPin(text = 'Confirme com seu PIN.') {
  const r = await modal({ title: 'Confirmação', body: `<p class="muted">${esc(text)}</p><div class="field"><span class="label">PIN</span><input class="input" name="pin" type="password" autocomplete="current-password"></div>`, actions: [{ label: 'Cancelar', value: null }, { label: 'Confirmar', value: 'form', kind: 'primary' }] });
  return r?.pin || null;
}

// Stream SSE; devolve função de fechar
function sse(url, onEvent) {
  const es = new EventSource(url);
  es.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch { /* ignora */ } };
  es.onerror = () => { /* o servidor encerra ao fim do job */ };
  return () => es.close();
}
function appendLine(box, l) {
  const d = document.createElement('div'); if (l.s === 'err') d.className = 'err'; else if (l.s === 'sys') d.className = 'sys';
  d.textContent = l.x; const stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 30; box.append(d); if (stick) box.scrollTop = box.scrollHeight;
}
// liga um job a um elemento console; resolve com o status final
function watchJob(jobId, box, { clear = true } = {}) {
  if (clear) box.textContent = '';
  return new Promise((resolve) => { const stop = sse(`/api/jobs/${jobId}/stream`, (l) => { if (l.s === 'end') { stop(); resolve(l); } else appendLine(box, l); }); App.leave(stop); });
}

// ---------- markdown mínimo e seguro (sempre escapa antes) ----------
function md(src) {
  src = String(src || '').replace(/```tool[\s\S]*?(```|$)/gi, '').trim();
  const blocks = []; let t = esc(src).replace(/```(\w*)\n?([\s\S]*?)(```|$)/g, (_, lang, code) => { blocks.push(`<pre class="code"><code>${code.replace(/\n$/, '')}</code></pre>`); return `\u0000${blocks.length - 1}\u0000`; });
  t = t.replace(/`([^`\n]+)`/g, '<code>$1</code>').replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>');
  const out = []; let list = null;
  for (const line of t.split('\n')) {
    const li = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
    if (li) { const tag = /^\s*\d/.test(line) ? 'ol' : 'ul'; if (list !== tag) { if (list) out.push(`</${list}>`); out.push(`<${tag}>`); list = tag; } out.push(`<li>${li[1]}</li>`); continue; }
    if (list) { out.push(`</${list}>`); list = null; }
    if (/^\u0000\d+\u0000$/.test(line.trim())) out.push(line.trim()); else if (line.trim() === '') out.push('<br>'); else out.push(`<p>${line}</p>`);
  }
  if (list) out.push(`</${list}>`);
  return out.join('').replace(/(<br>)+/g, '').replace(/\u0000(\d+)\u0000/g, (_, i) => blocks[+i]);
}

function copyText(text) { navigator.clipboard?.writeText(text).then(() => toast('Copiado', 'ok'), () => toast('Não foi possível copiar', 'bad')); }

// ---------- App: shell, roteador, autenticação ----------
const App = {
  pages: [], current: null, cleanups: [], timers: [],
  register(p) { this.pages.push(p); },
  leave(fn) { this.cleanups.push(fn); },
  every(fn, ms) { const id = setInterval(fn, ms); this.cleanups.push(() => clearInterval(id)); return id; },
  runCleanups() { for (const f of this.cleanups.splice(0)) { try { f(); } catch { /* */ } } },

  async route() {
    const id = (location.hash.replace(/^#\/?/, '') || 'dashboard').split('/')[0];
    const page = this.pages.find((p) => p.id === id) || this.pages[0];
    this.runCleanups(); this.current = page;
    document.body.classList.remove('nav-open');
    $$('.nav a').forEach((a) => a.classList.toggle('on', a.dataset.id === page.id));
    // Cada navegação ganha o PROPRIO container. Se uma página lenta terminar de renderizar depois
    // que o usuário já foi para outra, ela escreve num container descartado (não sobrescreve a atual).
    const root = document.createElement('div'); $('#page').replaceChildren(root);
    document.title = `${page.title} - Sentinel`; $('#top-title') && ($('#top-title').textContent = page.title);
    $('.main').scrollTop = 0;
    try { await page.render(root, location.hash.split('/').slice(2)); } catch (e) { if (e.status !== 401 && root.isConnected) root.innerHTML = `<div class="notice bad">${icon('triangle-alert')}<div>Erro ao carregar: ${esc(e.message)}</div></div>`; }
  },

  head(eyebrow, title, lede, right = '') {
    return `<div class="page-head"><div><div class="eyebrow">${esc(eyebrow)}</div><h1>${esc(title)}</h1>${lede ? `<p class="lede">${esc(lede)}</p>` : ''}</div>${right ? `<div class="row wrap">${right}</div>` : ''}</div>`;
  },

  groups: [
    ['Visão geral', ['dashboard']],
    ['Inteligência', ['agents', 'models']],
    ['Segurança', ['scan', 'tools', 'scope', 'lab']],
    ['Proteção', ['vault', 'panic']],
    ['Utilitários', ['notes', 'net', 'qr', 'maps']],
    ['Conhecimento', ['learn']],
    ['Sistema', ['remote', 'security']],
  ],

  showApp() {
    $('#root').innerHTML = `
    <div id="app">
      <aside class="side" aria-label="Navegação">
        <div class="brand"><div class="brand-mark">${icon('shield', 16)}</div><div><b>Sentinel</b><small>root@sentinel:~</small></div></div>
        <nav class="nav">${this.groups.map(([g, ids]) => `<div class="nav-label">${g}</div>${ids.map((id) => { const p = this.pages.find((x) => x.id === id); return `<a href="#/${id}" data-id="${id}">${icon(p.icon)}<span>${p.title}</span>${p.pill ? `<span class="pill" id="pill-${id}"></span>` : ''}</a>`; }).join('')}`).join('')}</nav>
        <div class="side-foot">
          <div class="status-line"><i class="dot" id="st-ai"></i><span id="st-ai-t">IA</span></div>
          <div class="status-line"><i class="dot" id="st-remote"></i><span id="st-remote-t">Remoto</span></div>
          <button class="btn sm" id="btn-logout">${icon('lock')} Bloquear sessão</button>
        </div>
      </aside>
      <div class="main">
        <div class="topbar"><button class="btn icon" id="btn-menu" aria-label="Menu">${icon('sliders-horizontal')}</button><b id="top-title"></b></div>
        <div class="page" id="page"></div>
      </div>
    </div>`;
    $('#btn-menu').onclick = () => document.body.classList.toggle('nav-open');
    document.addEventListener('click', (e) => { if (document.body.classList.contains('nav-open') && !e.target.closest('.side') && !e.target.closest('#btn-menu')) document.body.classList.remove('nav-open'); });
    $('#btn-logout').onclick = async () => { await post('/api/auth/logout').catch(() => {}); this.showAuth(); };
    window.onhashchange = () => this.route();
    this.route(); this.refreshStatus(); this.statusTimer = setInterval(() => this.refreshStatus(), 20000);
  },

  async refreshStatus() {
    try {
      const [ai, rm] = await Promise.all([get('/api/ai/status'), get('/api/remote')]);
      const o = ai.ollama; const m = ai.settings.ollamaModel; const has = o.models.some((x) => x.name === m);
      const el = $('#st-ai'); if (!el) return;
      el.className = 'dot ' + (o.running ? (has ? 'ok' : 'warn') : 'bad'); // verde: rodando e com o modelo; amarelo: falta baixar o modelo
      $('#st-ai-t').textContent = !o.running ? 'Ollama parado' : has ? `Ollama - ${m}` : `Baixe o ${m}`;
      $('#st-remote').className = 'dot ' + (rm.config.enabled ? 'ok' : '');
      $('#st-remote-t').textContent = rm.config.enabled ? `Remoto ${rm.config.bindIp}` : 'Remoto desligado';
    } catch { /* ignora */ }
  },

  // ----- autenticação -----
  showAuth() {
    clearInterval(this.statusTimer); this.runCleanups();
    get('/api/auth/state').then((s) => { if (!s.setup) this.authSetup(); else if (s.authed) this.showApp(); else this.authLogin(s.needs2fa); });
  },
  authShell(inner) {
    $('#root').innerHTML = `<div class="auth"><div class="auth-art"><div class="row"><div class="brand-mark" style="width:30px;height:30px">${icon('shield', 18)}</div><b style="font-size:16px">Sentinel</b></div><h1>Seu PC, sob <em>seu</em> controle.</h1><div class="label">Workbench local de cibersegurança &middot; agentes de IA &middot; acesso remoto privado</div></div><div class="auth-form">${inner}</div></div>`;
  },
  authSetup() {
    this.authShell(`<form id="f" class="stack"><div><div class="eyebrow">Primeiro acesso</div><h2 style="font-size:22px">Proteja o Sentinel</h2><p class="muted" style="margin-top:6px">Crie um PIN ou senha (mínimo 6 caracteres). Ele protege o app, os agentes e o acesso remoto.</p></div>
      <div class="field"><span class="label">Criar PIN</span><input class="input" type="password" name="a" autocomplete="new-password" required minlength="6"></div>
      <div class="field"><span class="label">Confirmar PIN</span><input class="input" type="password" name="b" autocomplete="new-password" required></div>
      <button class="btn primary" type="submit">${icon('check')} Criar e entrar</button><div class="hint" id="err" style="color:var(--hi)"></div></form>`);
    $('#f').onsubmit = async (e) => {
      e.preventDefault(); const f = new FormData(e.target);
      if (f.get('a') !== f.get('b')) return ($('#err').textContent = 'Os PINs não conferem.');
      try { const r = await post('/api/auth/setup', { pin: f.get('a') }); this.showRecovery(r.recovery); } catch (x) { $('#err').textContent = x.message; }
    };
  },
  showRecovery(code, then = () => this.showApp()) {
    this.authShell(`<div class="stack"><div><div class="eyebrow">Número de recuperação</div><h2 style="font-size:22px">Guarde este número</h2><p class="muted" style="margin-top:6px">Sem o PIN, ele é a única forma de redefinir o acesso. Anote em local seguro, fora deste PC. Ele não será mostrado de novo.</p></div>
      <div class="recovery">${esc(code)}</div><label class="check"><input type="checkbox" id="saved"> Guardei meu número em local seguro.</label>
      <div class="row"><button class="btn" id="cp">${icon('copy')} Copiar</button><button class="btn primary grow" id="go" disabled>Continuar</button></div></div>`);
    $('#saved').onchange = (e) => { $('#go').disabled = !e.target.checked; }; $('#cp').onclick = () => copyText(code); $('#go').onclick = then;
  },
  authLogin(needs2fa) {
    this.authShell(`<form id="f" class="stack"><div><div class="eyebrow">Acesso</div><h2 style="font-size:22px">Entrar</h2></div>
      <div class="field"><span class="label">PIN</span><input class="input" type="password" name="pin" autocomplete="current-password" required autofocus></div>
      ${needs2fa ? `<div class="field"><span class="label">Código 2FA</span><input class="input mono" name="totp" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="000000"></div>` : ''}
      <button class="btn primary" type="submit">${icon('lock-open')} Desbloquear</button><div class="hint" id="err" style="color:var(--hi)"></div>
      <a href="#" id="forgot" class="hint">Esqueci o PIN</a></form>`);
    $('#f').onsubmit = async (e) => { e.preventDefault(); const f = Object.fromEntries(new FormData(e.target)); try { await post('/api/auth/login', f); this.showApp(); } catch (x) { $('#err').textContent = x.message; } };
    $('#forgot').onclick = (e) => { e.preventDefault(); this.authRecover(); };
  },
  authRecover() {
    this.authShell(`<form id="f" class="stack"><div><div class="eyebrow">Recuperação</div><h2 style="font-size:22px">Redefinir PIN</h2><p class="muted" style="margin-top:6px">Informe o número de recuperação guardado e um novo PIN. O 2FA será desativado.</p></div>
      <div class="field"><span class="label">Número de recuperação</span><input class="input mono" name="recovery" placeholder="0000-0000-0000-0000-0000-0000" required></div>
      <div class="field"><span class="label">Novo PIN</span><input class="input" type="password" name="newPin" minlength="6" required></div>
      <button class="btn primary" type="submit">Redefinir</button><div class="hint" id="err" style="color:var(--hi)"></div><a href="#" id="back" class="hint">Voltar</a></form>`);
    $('#back').onclick = (e) => { e.preventDefault(); this.showAuth(); };
    $('#f').onsubmit = async (e) => { e.preventDefault(); const f = Object.fromEntries(new FormData(e.target)); try { const r = await post('/api/auth/recover', f); this.showRecovery(r.recovery, () => this.showAuth()); } catch (x) { $('#err').textContent = x.message; } };
  },
};
