'use strict';
// Cofre: gerador de senhas, criptografia de arquivos/pastas, bloqueio de apps.

// Seletor de arquivos do servidor (o navegador não expoe caminhos reais).
function createFB(el, { onPick, filter, hint = 'Clique para selecionar. Duplo clique abre a pasta.' }) {
  let cwd = null; let selected = null;
  async function load(p) {
    const d = await safe(() => (p ? get(`/api/fs?path=${encodeURIComponent(p)}`) : get('/api/fs')));
    if (!d) return; cwd = d.path; selected = null;
    const dr = await get('/api/fs/drives').catch(() => ({ drives: [] }));
    el.innerHTML = `<div class="row wrap" style="margin-bottom:8px">${dr.drives.map((x) => `<button class="chip" data-d="${esc(x)}" style="padding:4px 10px">${esc(x)}</button>`).join('')}<button class="chip" data-home style="padding:4px 10px">${icon('folder-open', 13)} Pessoal</button></div><div class="row" style="margin-bottom:8px">${d.parent ? `<button class="btn sm icon" data-up aria-label="Subir">${icon('chevron-right', 14)}</button>` : ''}<code class="grow mono" style="word-break:break-all;background:none">${esc(d.path)}</code><button class="btn sm" data-pickdir>Usar esta pasta</button></div><div class="fb">${d.items.filter((i) => i.dir || !filter || filter.test(i.name)).map((i) => `<div class="fb-item" data-n="${esc(i.name)}" data-dir="${i.dir ? 1 : 0}">${icon(i.dir ? 'folder-open' : 'file-text', 15)}<span class="grow">${esc(i.name)}</span><span class="hint mono">${i.dir ? '' : fmtBytes(i.size)}</span></div>`).join('') || '<div class="empty">Vazio</div>'}</div><div class="hint" style="margin-top:6px">${esc(hint)}</div>`;
    const join = (n) => d.path.replace(/[\\/]+$/, '') + '\\' + n;
    $$('[data-d]', el).forEach((b) => b.onclick = () => load(b.dataset.d)); $('[data-home]', el).onclick = () => load(null);
    $('[data-up]', el)?.addEventListener('click', () => load(d.parent)); $('[data-pickdir]', el).onclick = () => onPick(d.path, true);
    $$('.fb-item', el).forEach((it) => { it.onclick = () => { $$('.fb-item', el).forEach((x) => x.classList.remove('sel')); it.classList.add('sel'); selected = join(it.dataset.n); onPick(selected, it.dataset.dir === '1'); }; it.ondblclick = () => { if (it.dataset.dir === '1') load(join(it.dataset.n)); }; });
  }
  load(null); return { load };
}

App.register({
  id: 'vault', title: 'Cofre', icon: 'folder-lock',
  async render(root) {
    let tab = localStorage.getItem('vtab') || 'pw';
    root.innerHTML = App.head('Proteção', 'Cofre', 'Senhas fortes, arquivos criptografados e bloqueio de aplicativos.') + `<div class="tabs" id="vt"><button data-t="pw">${icon('key-round', 15)} Senhas</button><button data-t="files">${icon('file-lock', 15)} Arquivos</button><button data-t="apps">${icon('lock', 15)} Bloqueio de apps</button></div><div id="vb"></div>`;
    const show = (t) => { tab = t; localStorage.setItem('vtab', t); $$('#vt button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); App.runCleanups(); ({ pw: tabPw, files: tabFiles, apps: tabApps })[t]($('#vb')); };
    $$('#vt button').forEach((b) => b.onclick = () => show(b.dataset.t)); show(tab);
  },
});

function tabPw(box) {
  box.innerHTML = `<div class="grid g2" style="grid-template-columns:.9fr 1.1fr;align-items:start"><div class="card card-pad stack">
    <div class="field"><div class="row between"><span class="label">Tamanho</span><b class="mono" id="pw-lv">256</b></div><input type="range" id="pw-len" min="8" max="1024" value="256" style="accent-color:var(--ac)"><div class="chips">${[16, 32, 64, 128, 256, 512].map((n) => `<button class="chip" data-n="${n}" style="padding:3px 10px">${n}</button>`).join('')}</div></div>
    <div class="grid g2" style="gap:10px"><label class="check"><input type="checkbox" id="o-lower" checked> minusculas</label><label class="check"><input type="checkbox" id="o-upper" checked> MAIUSCULAS</label><label class="check"><input type="checkbox" id="o-digits" checked> números</label><label class="check"><input type="checkbox" id="o-symbols" checked> simbolos</label><label class="check"><input type="checkbox" id="o-amb"> evitar ambíguos (O 0 l 1)</label></div>
    <div class="field"><span class="label">Quantidade</span><input class="input" id="pw-count" type="number" min="1" max="20" value="1" style="width:100px"></div>
    <button class="btn primary" id="pw-go">${icon('shuffle', 15)} Gerar</button><div class="hint">Gerado com o CSPRNG do sistema (crypto.randomInt). Nada sai deste PC.</div>
    <hr style="border:0;border-top:1px solid var(--line)"><div class="row between"><h3>Frase-senha pronunciável</h3><button class="btn sm" id="pp-go">Gerar</button></div><div class="pw-out hide" id="pp-out"></div></div>
    <div class="card card-pad stack"><div class="row between"><h2>Resultado</h2><span class="badge ac mono hide" id="pw-ent"></span></div><div class="pw-out" id="pw-out" style="min-height:120px;color:var(--tx-3)">Clique em Gerar.</div><div class="row"><button class="btn sm" id="pw-cp" disabled>${icon('copy', 14)} Copiar</button><span class="hint">Use gerenciador de senhas para guardar. Para algo que exige um tamanho máximo, reduza o tamanho.</span></div></div></div>`;
  const len = $('#pw-len'); const sync = () => { $('#pw-lv').textContent = len.value; $$('[data-n]').forEach((c) => c.classList.toggle('on', c.dataset.n === len.value)); }; len.oninput = sync; sync();
  $$('[data-n]').forEach((c) => c.onclick = () => { len.value = c.dataset.n; sync(); });
  $('#pw-go').onclick = async () => {
    const r = await safe(() => post('/api/vault/password', { length: +len.value, lower: $('#o-lower').checked, upper: $('#o-upper').checked, digits: $('#o-digits').checked, symbols: $('#o-symbols').checked, avoidAmbiguous: $('#o-amb').checked, count: +$('#pw-count').value })); if (!r) return;
    const out = $('#pw-out'); out.style.color = ''; out.textContent = r.passwords.join('\n\n'); $('#pw-cp').disabled = false; $('#pw-cp').onclick = () => copyText(r.passwords.join('\n')); const e = $('#pw-ent'); e.textContent = `${r.entropyBits} bits de entropia`; e.classList.remove('hide');
  };
  $('#pp-go').onclick = async () => { const r = await safe(() => post('/api/vault/passphrase', { words: 6 })); if (r) { const o = $('#pp-out'); o.classList.remove('hide'); o.textContent = r.passphrase; o.title = `${r.entropyBits} bits`; } };
}

function tabFiles(box) {
  let picked = null; let isDir = false;
  box.innerHTML = `<div class="grid g2" style="grid-template-columns:1.1fr .9fr;align-items:start"><div class="card card-pad"><h2 style="margin-bottom:12px">Escolher arquivo ou pasta</h2><div id="fb"></div></div>
    <div class="card card-pad stack"><h2>Criptografar / descriptografar</h2><div class="field"><span class="label">Selecionado</span><div class="code mono" id="f-sel" style="word-break:break-all;padding:10px;display:block">nenhum</div></div>
      <div class="field"><span class="label">Senha</span><input class="input" type="password" id="f-pw" autocomplete="off"></div>
      <label class="check" id="f-rmw"><input type="checkbox" id="f-rm"> Apagar o original depois de criptografar</label>
      <div class="row"><button class="btn primary grow" id="f-enc">${icon('lock', 14)} Criptografar</button><button class="btn grow" id="f-dec">${icon('lock-open', 14)} Descriptografar</button></div>
      <div class="notice warn">${icon('triangle-alert')}<div><b>Sem recuperação.</b> Se esquecer a senha, os dados são irrecuperáveis. AES-256-GCM com chave derivada por scrypt (N=2^17); qualquer alteração no arquivo e detectada. Arquivos viram <code>nome.sntl</code>; pastas viram <code>pasta.tar.sntl</code>.</div></div></div></div>`;
  createFB($('#fb'), { onPick: (p, d) => { picked = p; isDir = d; $('#f-sel').textContent = p; } });
  $('#f-enc').onclick = async (e) => {
    if (!picked) return toast('Selecione um arquivo ou pasta.', 'bad'); if (/\.sntl$/i.test(picked)) return toast('Já está criptografado.', 'bad');
    const rm = $('#f-rm').checked; if (rm && !(await confirmBox('O original será <b>apagado</b> depois de criptografar. Confirme que lembra a senha.', { danger: true, ok: 'Criptografar e apagar' }))) return;
    toast('Criptografando... (a derivação da chave leva alguns segundos)'); const r = await safe(() => post('/api/vault/encrypt', { path: picked, password: $('#f-pw').value, removeOriginal: rm }), e.currentTarget); if (r) { toast(`Criado: ${r.output}`, 'ok'); $('#f-pw').value = ''; }
  };
  $('#f-dec').onclick = async (e) => {
    if (!picked || !/\.sntl$/i.test(picked)) return toast('Selecione um arquivo .sntl.', 'bad');
    const r = await safe(() => post('/api/vault/decrypt', { path: picked, password: $('#f-pw').value }), e.currentTarget); if (r) { toast(`Restaurado: ${r.output}`, 'ok'); $('#f-pw').value = ''; }
  };
}

async function tabApps(box) {
  let pick = null;
  const draw = async () => {
    const s = await get('/api/applock');
    const isWin = s.platform === 'win32';
    box.innerHTML = `<div class="grid g2" style="align-items:start"><div class="card"><div class="card-head"><h2>Aplicativos</h2><span class="label">${s.apps.length} selecionado(s)</span></div>
      <div class="list">${s.apps.map((a) => `<div class="row">${icon('monitor-smartphone', 16)}<div class="grow"><b style="font-weight:500">${esc(a.name)}</b><div class="hint mono" style="word-break:break-all">${esc(a.path || 'por nome do processo')}</div></div><button class="btn sm icon danger" data-rm="${esc(a.name)}" aria-label="Remover">${icon('x', 14)}</button></div>`).join('') || `<div class="empty">${icon('lock', 24)}<div>Nenhum app protegido.</div></div>`}</div>
      <div class="card-pad stack" style="border-top:1px solid var(--line)"><div class="row"><input class="input mono grow" id="ap-in" placeholder="${isWin ? 'chrome.exe ou C:\\\\caminho\\\\app.exe' : 'discord, steam ou /usr/bin/app'}"><button class="btn primary" id="ap-add">${icon('plus', 14)}</button></div>${isWin ? `<details><summary class="hint" style="cursor:pointer">Escolher .exe no disco</summary><div id="ap-fb" style="margin-top:10px"></div></details>` : `<div class="hint">No Linux, informe o nome do processo (ex.: <span class="mono">discord</span>, veja em <span class="mono">ps -e</span>).</div>`}</div></div>
      <div class="stack"><div class="card card-pad stack"><div class="row between"><div class="row"><div class="brand-mark" style="background:${s.locked ? 'var(--ac)' : 'var(--ok)'}">${icon(s.locked ? 'lock' : 'lock-open', 15)}</div><div><h2>${s.locked ? 'Travado' : 'Destravado'}</h2><div class="hint">${s.locked ? 'Apps da lista não abrem sem o PIN' : 'Trava sozinho após inatividade'}</div></div></div><div>${s.locked ? `<button class="btn primary" id="ap-un">${icon('lock-open', 14)} Destravar</button>` : `<button class="btn" id="ap-lk">${icon('lock', 14)} Travar agora</button>`}</div></div>
        <div><div class="row" style="margin-bottom:8px">${icon('clock', 15)}<b style="font-weight:500">Travar após inatividade</b></div><div class="chips">${[1, 5, 15, 30, 60].map((m) => `<button class="chip ${s.idleMin === m ? 'on' : ''}" data-m="${m}">${m} <span class="dim">min</span></button>`).join('')}</div></div></div>
        <div class="notice">${icon('info')}<div><b>Como funciona:</b> enquanto estiver travado, qualquer processo dos apps listados que for <b>aberto depois</b> do bloqueio e encerrado. Apps que já estavam abertos não são fechados (evita perder trabalho). Funciona enquanto o Sentinel estiver rodando; não é um serviço do ${isWin ? 'Windows' : 'Linux'}.</div></div>
        ${s.killed.length ? `<div class="card"><div class="card-head"><h2>Bloqueios recentes</h2></div><div class="list">${s.killed.slice().reverse().map((k) => `<div class="row between"><span class="mono">${esc(k.name)}</span><span class="hint mono">${new Date(k.t).toLocaleTimeString('pt-BR')}</span></div>`).join('')}</div></div>` : ''}</div></div>`;
    const add = async (v) => { if (await safe(() => post('/api/applock/add', { exe: v }))) draw(); };
    $('#ap-add').onclick = () => add($('#ap-in').value.trim());
    if (isWin) createFB($('#ap-fb'), { filter: /\.exe$/i, hint: 'Selecione um .exe e clique em Adicionar acima.', onPick: (p, d) => { if (!d && /\.exe$/i.test(p)) { $('#ap-in').value = p; } } });
    $$('[data-rm]').forEach((b) => b.onclick = async () => { await safe(() => post('/api/applock/remove', { name: b.dataset.rm })); draw(); });
    $$('[data-m]').forEach((b) => b.onclick = async () => { await safe(() => post('/api/applock/idle', { min: +b.dataset.m })); draw(); });
    $('#ap-lk')?.addEventListener('click', async () => { await safe(() => post('/api/applock/lock')); draw(); });
    $('#ap-un')?.addEventListener('click', async () => { const pin = await askPin('Digite o PIN para destravar os apps.'); if (pin && await safe(() => post('/api/applock/unlock', { pin }))) draw(); });
  };
  await draw();
}
