'use strict';
// Website Scan, Ferramentas, Escopo, Laboratório (CyberLab + VMs).

// Se o alvo estiver fora do escopo, oferece adicionar (com atestado de autorização) e tenta de novo.
async function withScope(target, fn) {
  try { return await fn(); } catch (e) {
    if (e.status !== 403 || !/autorizados/.test(e.message)) { if (e.status !== 401) toast(e.message, 'bad'); return undefined; }
    const host = (() => { try { return new URL(/^https?:/.test(target) ? target : 'https://' + target).hostname; } catch { return target; } })();
    const r = await modal({ title: 'Alvo fora do escopo', body: `<p class="muted"><b class="mono">${esc(host)}</b> não está na lista de alvos autorizados. Scans e ferramentas ofensivas só rodam contra sistemas que você <b>possui</b> ou tem <b>permissão por escrito</b> para testar. Testar sistemas de terceiros sem autorização é crime.</p><label class="check"><input type="checkbox" name="ok"> Declaro que sou dono de <b class="mono">${esc(host)}</b> ou tenho autorização para testá-lo.</label><div class="field"><span class="label">Anotação (opcional)</span><input class="input" name="note" placeholder="ex.: meu servidor, contrato #123"></div>`, actions: [{ label: 'Cancelar', value: null }, { label: 'Adicionar ao escopo e continuar', value: 'form', kind: 'primary' }] });
    if (!r || !r.ok) return undefined;
    // r.ok e o estado do checkbox de atestado (mesmo nome "ok"); só chega aqui se foi marcado.
    if (!(await safe(() => post('/api/scope', { value: host, note: r.note, attested: true })))) return undefined;
    return safe(fn);
  }
}

const SEV = { high: 'Alto', medium: 'Médio', low: 'Baixo', info: 'Info' };
function reportHtml(r) {
  const c = r.counts || {};
  return `<div class="stack">
    <div class="row between wrap"><div><div class="label">Veredito</div><h2 style="font-size:20px;margin-top:4px">${esc(r.verdict)}</h2></div><div class="row">${['high', 'medium', 'low', 'info'].map((k) => `<span class="badge ${k}">${SEV[k]} ${c[k] || 0}</span>`).join('')}</div></div>
    <dl class="kv"><dt>alvo</dt><dd class="mono">${esc(r.target)}</dd><dt>status HTTP</dt><dd>${esc(r.status)}${r.finalUrl && r.finalUrl !== r.target ? ` &rarr; ${esc(r.finalStatus)} em <span class="mono">${esc(r.finalUrl)}</span>` : ''}</dd>
    ${r.tech?.length ? `<dt>tecnologias</dt><dd>${r.tech.map((t) => `<span class="badge">${esc(t)}</span>`).join(' ')}</dd>` : ''}${r.php ? `<dt>PHP</dt><dd class="mono">${esc(r.php)}</dd>` : ''}
    ${r.tls && !r.tls.error ? `<dt>TLS</dt><dd class="mono">${esc(r.tls.protocol)} &middot; ${esc(r.tls.cipher)}<br>${esc(r.tls.subject)} &middot; ${esc(r.tls.issuer)} &middot; expira em ${esc(r.tls.daysLeft)} dias</dd>` : ''}
    ${r.allow ? `<dt>métodos</dt><dd class="mono">${esc(r.allow)}</dd>` : ''}</dl>
    <div class="card" style="background:var(--bg)"><div class="card-head"><h2>Achados (${(r.findings || []).length})</h2></div>${(r.findings || []).map((f) => `<div class="finding"><span class="badge ${f.sev}" style="align-self:start;justify-self:start">${SEV[f.sev]}</span><div><b>${esc(f.title)}</b><small>${esc(f.detail)}</small></div></div>`).join('') || '<div class="empty">Nada encontrado.</div>'}</div></div>`;
}

App.register({
  id: 'scan', title: 'Website Scan', icon: 'scan-search',
  async render(root) {
    let level = localStorage.getItem('scanLevel') || 'standard'; let filter = ''; let status = '';
    root.innerHTML = App.head('Segurança', 'Website Scan', 'Inspecione um site: cabeçalhos, TLS, tecnologias e exposições. Só roda contra alvos autorizados.', `<span class="badge ok" id="sc-ready">pronto</span>`) + `
      <div class="levels" id="levels">${[['quick', 'Quick', 'Cabeçalhos + checagem passiva de versão PHP'], ['standard', 'Standard', 'TLS, avisos de PHP + tecnologias', 'Recomendado'], ['deep', 'Deep', 'Perfil completo + descoberta ativa']].map(([id, t, d, tag]) => `<button class="level ${id === level ? 'on' : ''}" data-l="${id}"><i class="radio"></i><div><b>${t}</b>${tag ? `<div><span class="badge ac" style="margin:4px 0 2px">${tag}</span></div>` : ''}<div class="hint">${d}</div></div></button>`).join('')}</div>
      <div class="row" style="margin:14px 0 22px"><input class="input mono grow" id="sc-t" placeholder="example.com ou https://example.com" spellcheck="false" autocomplete="off"><button class="btn primary" id="sc-go">${icon('radar')} <span>Iniciar scan ${level}</span></button></div>
      <div class="card hide" id="sc-live" style="margin-bottom:22px"><div class="card-head"><h2 id="sc-live-t">Scan em andamento</h2><button class="btn sm danger hide" id="sc-kill">${icon('square', 14)} Parar</button></div><div class="console" id="sc-log" style="border:0;border-radius:0;height:200px"></div><div id="sc-rep" class="card-pad hide" style="border-top:1px solid var(--line)"></div></div>
      <div class="card"><div class="card-head"><div class="row"><div class="ic-box" style="width:34px;height:34px;border:1px solid var(--line-2);display:grid;place-items:center;border-radius:4px">${icon('history', 17)}</div><div><h2>Histórico de scans</h2><div class="hint" id="sc-n"></div></div></div><button class="btn sm danger" id="sc-clear">${icon('trash-2', 14)} Limpar</button></div>
        <div class="card-pad row" style="border-bottom:1px solid var(--line)"><input class="input grow" id="sc-q" placeholder="Buscar alvo ou veredito"><select class="select" id="sc-f" style="width:190px"><option value="">Todos os status</option><option value="high">Risco alto</option><option value="medium">Risco médio</option><option value="limit">Avaliação limitada</option><option value="fail">Falhou</option></select></div>
        <div id="sc-hist"></div></div>`;
    $$('[data-l]').forEach((b) => b.onclick = () => { level = b.dataset.l; localStorage.setItem('scanLevel', level); $$('[data-l]').forEach((x) => x.classList.toggle('on', x === b)); $('#sc-go span').textContent = `Iniciar scan ${level}`; });

    async function history() {
      const { history: h } = await get('/api/scan/history'); const q = filter.toLowerCase();
      const list = h.filter((x) => (!q || `${x.target} ${x.verdict}`.toLowerCase().includes(q)) && (!status || (status === 'high' && x.counts?.high) || (status === 'medium' && x.counts?.medium && !x.counts?.high) || (status === 'limit' && x.limited) || (status === 'fail' && x.error)));
      $('#sc-n').textContent = `${h.length} relatorio(s) salvo(s)`;
      $('#sc-hist').innerHTML = list.length ? `<div class="list">${list.map((x) => `<div class="row wrap"><span class="badge ${x.error ? 'high' : x.limited ? 'info' : x.counts?.high ? 'high' : x.counts?.medium ? 'medium' : 'ok'}">${x.error ? 'falhou' : x.limited ? 'limitado' : x.counts?.high ? 'alto' : x.counts?.medium ? 'médio' : 'ok'}</span><div class="grow"><b class="mono" style="font-weight:500;word-break:break-all">${esc(x.target)}</b><div class="hint">${fmtTime(x.startedAt)} &middot; ${esc(x.level)} &middot; HTTP ${esc(x.status ?? '-')} &middot; ${esc(x.verdict)}</div></div><button class="btn sm" data-view="${x.id}">Ver</button><button class="btn sm icon" data-rm="${x.id}" aria-label="Apagar">${icon('trash-2', 14)}</button></div>`).join('')}</div>` : `<div class="empty">${icon('history', 24)}<div>Nenhum relatório${h.length ? ' com esse filtro' : ' ainda'}.</div></div>`;
      $$('[data-view]').forEach((b) => b.onclick = () => modal({ title: 'Relatório', body: reportHtml(h.find((x) => x.id === b.dataset.view)) }));
      $$('[data-rm]').forEach((b) => b.onclick = async () => { await safe(() => del('/api/scan/history', { id: b.dataset.rm })); history(); });
    }
    $('#sc-q').oninput = (e) => { filter = e.target.value; history(); }; $('#sc-f').onchange = (e) => { status = e.target.value; history(); };
    $('#sc-clear').onclick = async () => { if (await confirmBox('Apagar todo o histórico de scans?', { danger: true, ok: 'Apagar' })) { await safe(() => del('/api/scan/history')); history(); } };

    async function go() {
      const target = $('#sc-t').value.trim(); if (!target) return toast('Informe um alvo.', 'bad');
      const r = await withScope(target, () => post('/api/scan/web', { target, level })); if (!r) return;
      $('#sc-live').classList.remove('hide'); $('#sc-rep').classList.add('hide'); $('#sc-live-t').textContent = `Scan ${level}: ${target}`;
      $('#sc-go').disabled = true; $('#sc-ready').textContent = 'escaneando'; $('#sc-ready').className = 'badge ac'; const kill = $('#sc-kill'); kill.classList.remove('hide'); kill.onclick = () => post(`/api/jobs/${r.job}/kill`);
      await watchJob(r.job, $('#sc-log')); kill.classList.add('hide'); $('#sc-go').disabled = false; $('#sc-ready').textContent = 'pronto'; $('#sc-ready').className = 'badge ok';
      const j = await get(`/api/jobs/${r.job}`); if (j.result) { $('#sc-rep').innerHTML = reportHtml(j.result); $('#sc-rep').classList.remove('hide'); } history();
    }
    $('#sc-go').onclick = go; $('#sc-t').onkeydown = (e) => { if (e.key === 'Enter') go(); };
    history();
  },
});

// ---------- Ferramentas ----------
const TOOL_FORMS = {
  nmap: (presets) => `<div class="field"><span class="label">Alvo</span><input class="input mono" name="target" placeholder="127.0.0.1"></div><div class="grid g2"><div class="field"><span class="label">Perfil</span><select class="select" name="preset">${presets.map((p) => `<option>${p}</option>`).join('')}</select></div><div class="field"><span class="label">Portas (opcional)</span><input class="input mono" name="ports" placeholder="80,443,8000-8100"></div></div>`,
  nikto: () => `<div class="field"><span class="label">Alvo</span><input class="input mono" name="target" placeholder="127.0.0.1"></div><div class="grid g2"><div class="field"><span class="label">Porta</span><input class="input mono" name="port" placeholder="80"></div><label class="check" style="align-self:end"><input type="checkbox" name="ssl"> SSL</label></div>`,
  msfconsole: () => `<div class="field"><span class="label">Modulo</span><input class="input mono" name="module" value="auxiliary/scanner/portscan/tcp"></div><div class="field"><span class="label">Alvo (RHOSTS)</span><input class="input mono" name="target" placeholder="127.0.0.1"></div><div class="field"><span class="label">Opções extras (CHAVE=valor por linha)</span><textarea class="input" name="opts" rows="3" placeholder="PORTS=1-1024"></textarea></div>`,
  sqlmap: () => `<div class="field"><span class="label">URL com parametro</span><input class="input mono" name="target" placeholder="http://127.0.0.1:8080/search?q=a"></div><div class="field"><span class="label">Nível (1-3)</span><input class="input mono" name="level" value="1"></div>`,
  whatweb: () => `<div class="field"><span class="label">Alvo</span><input class="input mono" name="target" placeholder="127.0.0.1"></div>`,
  gobuster: () => `<div class="field"><span class="label">URL</span><input class="input mono" name="target" placeholder="http://127.0.0.1:8080"></div><div class="field"><span class="label">Wordlist</span><input class="input mono" name="wordlist" placeholder="common.txt"></div>`,
};

App.register({
  id: 'tools', title: 'Ferramentas', icon: 'terminal',
  async render(root) {
    const { tools, presets } = await get('/api/tools'); let sel = localStorage.getItem('tool') || 'builtin';
    root.innerHTML = App.head('Segurança', 'Ferramentas', 'nmap, Nikto, Metasploit e mais, com escopo obrigatório. Sem instalar nada, o scanner TCP embutido já funciona.') + `
    <div class="grid" style="grid-template-columns:300px 1fr;align-items:start" id="tl"><div class="card" id="tl-list"></div><div class="stack" id="tl-main"></div></div>`;
    const list = $('#tl-list');
    list.innerHTML = `<div class="list"><div class="row" data-t="builtin" style="cursor:pointer"><div class="grow"><b style="font-weight:500">Port scan TCP</b><div class="hint">Embutido - sempre disponível</div></div><span class="badge ok">pronto</span></div>${tools.map((t) => `<div class="row" data-t="${t.id}" style="cursor:pointer"><div class="grow"><b style="font-weight:500">${esc(t.label)}</b><div class="hint">${t.installed ? (t.mode === 'wsl' ? 'via WSL' : 'instalado') : 'não instalado'}</div></div><span class="badge ${t.installed ? 'ok' : ''}">${t.installed ? 'pronto' : 'ausente'}</span></div>`).join('')}</div>`;
    const main = $('#tl-main');
    function show(id) {
      sel = id; localStorage.setItem('tool', id); $$('[data-t]', list).forEach((r) => r.style.background = r.dataset.t === id ? 'var(--bg-2)' : '');
      if (id === 'builtin') {
        main.innerHTML = `<div class="card card-pad stack"><h2>Port scan TCP (embutido)</h2><p class="muted">Conecta nas portas e le banners. Rápido, sem dependências.</p><div class="grid g2"><div class="field"><span class="label">Alvo</span><input class="input mono" id="b-t" value="127.0.0.1"></div><div class="field"><span class="label">Portas</span><input class="input mono" id="b-p" value="top" placeholder="top ou 1-1024"></div></div><div class="row"><button class="btn primary" id="b-go">${icon('play', 14)} Escanear</button><button class="btn danger hide" id="b-kill">${icon('square', 14)} Parar</button></div></div><div class="console" id="t-log"></div>`;
        $('#b-go').onclick = async () => { const t = $('#b-t').value.trim(); const r = await withScope(t, () => post('/api/scan/ports', { target: t, ports: $('#b-p').value.trim() || 'top' })); if (!r) return; $('#b-kill').classList.remove('hide'); $('#b-kill').onclick = () => post(`/api/jobs/${r.job}/kill`); await watchJob(r.job, $('#t-log')); $('#b-kill').classList.add('hide'); };
        return;
      }
      const t = tools.find((x) => x.id === id);
      main.innerHTML = `<div class="card card-pad stack"><div class="row between wrap"><div><h2>${esc(t.label)}</h2><p class="muted">${esc(t.desc)}</p></div><span class="badge ${t.installed ? 'ok' : ''}">${t.installed ? (t.mode === 'wsl' ? 'via WSL' : 'instalado') : 'não instalado'}</span></div>
        ${t.installed ? `<div id="t-form" class="stack">${TOOL_FORMS[id](presets)}</div><div class="row"><button class="btn primary" id="t-go">${icon('play', 14)} Executar</button><button class="btn danger hide" id="t-kill">${icon('square', 14)} Parar</button></div>` : `<div class="notice warn">${icon('triangle-alert')}<div>Não encontrado neste PC.<br><code style="word-break:break-all">${esc(t.installHint)}</code></div></div>${t.canInstall ? `<div><button class="btn primary" id="t-inst">${icon('download', 14)} Instalar com winget</button></div>` : ''}`}</div><div class="console" id="t-log"></div>`;
      $('#t-inst')?.addEventListener('click', async () => {
        if (!(await confirmBox(`Instalar <b>${esc(t.label)}</b> via winget (baixa e instala software). O Windows pode pedir confirmação de administrador.`, { ok: 'Instalar' }))) return;
        const r = await safe(() => post('/api/tools/install', { tool: id })); if (!r) return; await watchJob(r.job, $('#t-log')); toast('Reabra a página para atualizar o status.'); });
      $('#t-go')?.addEventListener('click', async () => {
        const f = Object.fromEntries($$('[name]', $('#t-form')).map((x) => [x.name, x.type === 'checkbox' ? x.checked : x.value.trim()]));
        const params = { ...f }; if (id === 'msfconsole') { params.options = Object.fromEntries((f.opts || '').split('\n').map((l) => l.trim()).filter(Boolean).map((l) => l.split(/=(.*)/s).slice(0, 2))); delete params.opts; }
        const r = await withScope(f.target, () => post('/api/tools/run', { tool: id, params })); if (!r) return;
        $('#t-kill').classList.remove('hide'); $('#t-kill').onclick = () => post(`/api/jobs/${r.job}/kill`); await watchJob(r.job, $('#t-log')); $('#t-kill').classList.add('hide'); });
    }
    $$('[data-t]', list).forEach((r) => r.onclick = () => show(r.dataset.t)); show(sel);
  },
});

// ---------- Escopo ----------
App.register({
  id: 'scope', title: 'Escopo', icon: 'route',
  async render(root) {
    const draw = async () => {
      const { scope } = await get('/api/scope');
      root.innerHTML = App.head('Segurança', 'Escopo autorizado', 'A lista do que você pode testar. Scans, nmap, Nikto, Metasploit e os agentes recusam qualquer alvo fora daqui.') + `
      <div class="grid g2" style="grid-template-columns:1.2fr .8fr;align-items:start">
        <div class="card"><div class="card-head"><h2>Alvos (${scope.length})</h2></div><div class="list">${scope.map((e) => `<div class="row"><div class="grow"><b class="mono" style="font-weight:500">${esc(e.value)}</b><div class="hint">${esc(e.note || '')}${e.addedAt ? ' &middot; adicionado ' + fmtTime(e.addedAt) : ''}</div></div>${e.builtin ? '<span class="badge">padrão</span>' : `<button class="btn sm danger" data-rm="${esc(e.value)}">${icon('trash-2', 14)}</button>`}</div>`).join('')}</div></div>
        <div class="card card-pad stack"><h2>Adicionar alvo</h2><div class="field"><span class="label">Domínio, IP, *.dominio ou CIDR</span><input class="input mono" id="sc-v" placeholder="meuservidor.com  |  192.168.56.0/24"></div><div class="field"><span class="label">Anotação</span><input class="input" id="sc-n" placeholder="ex.: VM Kali, meu site"></div>
          <label class="check"><input type="checkbox" id="sc-a"> Declaro que sou dono deste alvo ou tenho autorização escrita para testá-lo.</label><button class="btn primary" id="sc-add">${icon('plus', 14)} Adicionar</button>
          <div class="hint">Testar sistemas sem autorização é crime. O CyberLab (127.0.0.1) e suas VMs são os alvos ideais para treinar.</div></div></div>`;
      $('#sc-add').onclick = async () => { if (await safe(() => post('/api/scope', { value: $('#sc-v').value, note: $('#sc-n').value, attested: $('#sc-a').checked }))) { toast('Adicionado.', 'ok'); draw(); } };
      $$('[data-rm]').forEach((b) => b.onclick = async () => { await safe(() => del('/api/scope', { value: b.dataset.rm })); draw(); });
    };
    await draw();
  },
});

// ---------- Laboratório: CyberLab + VMs ----------
App.register({
  id: 'lab', title: 'Laboratório', icon: 'flask-conical',
  async render(root) {
    const draw = async () => {
      const [lab, prov, vms] = await Promise.all([get('/api/lab'), get('/api/vm/providers'), get('/api/vm/list')]);
      const real = vms.vms.filter((v) => !v.error);
      root.innerHTML = App.head('Segurança', 'Laboratório', 'Alvos de treino: o CyberLab (site vulnerável de proposito) e máquinas virtuais isoladas.') + `
      <div class="card" style="margin-bottom:20px"><div class="card-head"><div class="row"><i class="dot ${lab.running ? 'ok' : ''}"></i><h2>CyberLab</h2><span class="hint">8 falhas do OWASP Top 10 - só em 127.0.0.1:8080</span></div><div class="row">${lab.exists ? (lab.running ? `<a class="btn sm" href="${lab.url}" target="_blank" rel="noopener">${icon('external-link', 14)} Abrir</a><button class="btn sm danger" id="lb-stop">${icon('square', 14)} Parar</button>` : `<button class="btn sm primary" id="lb-start">${icon('play', 14)} Iniciar</button>`) : ''}</div></div>
        ${lab.exists ? `<div class="card-pad stack"><p class="muted">Inicie, escaneie com o <a href="#/scan">Website Scan</a> ou o <a href="#/agents">agente Pentest</a> e tente achar as flags. Spoilers e dicas estão no README da pasta <code>${esc(lab.dir)}</code>.</p><div class="console ${lab.running ? '' : 'hide'}" id="lb-log" style="height:140px"></div></div>` : `<div class="empty">CyberLab não encontrado em ${esc(lab.dir)}.</div>`}</div>
      <div class="card"><div class="card-head"><div><h2>Máquinas virtuais</h2><div class="hint">VirtualBox ${prov.virtualbox ? '<span class="badge ok">ok</span>' : '<span class="badge">ausente</span>'} Hyper-V ${prov.hyperv ? '<span class="badge ok">ok</span>' : '<span class="badge" title="Requer PowerShell como administrador">indisponível</span>'}</div></div><div class="row"><button class="btn sm" id="vm-ref">${icon('refresh-cw', 14)}</button><button class="btn sm primary" id="vm-new" ${prov.virtualbox ? '' : 'disabled'}>${icon('plus', 14)} Nova VM</button></div></div>
        <div class="list">${real.map((v) => `<div class="row wrap"><i class="dot ${v.state === 'running' ? 'ok' : ''}"></i><div class="grow"><b style="font-weight:500">${esc(v.name)}</b><div class="hint">${esc(v.provider)} &middot; ${v.state === 'running' ? 'ligada' : 'desligada'}</div></div>${v.state === 'running' ? `<button class="btn sm" data-a="stop" data-p="${v.provider}" data-n="${esc(v.name)}">Desligar</button><button class="btn sm danger" data-a="poweroff" data-p="${v.provider}" data-n="${esc(v.name)}">Forçar</button>` : `<button class="btn sm primary" data-a="start" data-p="${v.provider}" data-n="${esc(v.name)}">${icon('play', 14)} Iniciar</button>`}<button class="btn sm" data-a="snapshot" data-p="${v.provider}" data-n="${esc(v.name)}">Snapshot</button><button class="btn sm icon danger" data-a="delete" data-p="${v.provider}" data-n="${esc(v.name)}" aria-label="Excluir">${icon('trash-2', 14)}</button></div>`).join('') || `<div class="empty">${icon('container', 26)}<div>Nenhuma VM encontrada.</div></div>`}${vms.vms.filter((v) => v.error).map((v) => `<div class="notice warn">${icon('triangle-alert')}<div>${esc(v.provider)}: ${esc(v.error)}</div></div>`).join('')}</div></div>
      <div class="notice" style="margin-top:16px">${icon('info')}<div>Para treinar com segurança, deixe as VMs em rede <b>NAT</b> ou <b>Host-Only</b> e adicione a faixa delas ao <a href="#/scope">Escopo</a> (ex.: <code>192.168.56.0/24</code>). Seu disco tem pouco espaço: dimensione os discos virtuais com cuidado.</div></div>`;
      $('#lb-start')?.addEventListener('click', async () => { const r = await safe(() => post('/api/lab/start')); await sleep(800); await draw(); const box = $('#lb-log'); if (box && r) { box.classList.remove('hide'); watchJob(r.job, box); } });
      $('#lb-stop')?.addEventListener('click', async () => { await safe(() => post('/api/lab/stop')); await sleep(600); draw(); });
      if (lab.running && lab.jobId) watchJob(lab.jobId, $('#lb-log'));
      $('#vm-ref').onclick = draw;
      $$('[data-a]').forEach((b) => b.onclick = async () => {
        const a = b.dataset.a; const danger = ['delete', 'poweroff'].includes(a);
        if (danger && !(await confirmBox(a === 'delete' ? `Excluir a VM <b>${esc(b.dataset.n)}</b> e <b>todos os discos dela</b>? Não tem como desfazer.` : `Cortar a energia de <b>${esc(b.dataset.n)}</b> imediatamente? Pode corromper o disco virtual.`, { danger: true, ok: a === 'delete' ? 'Excluir' : 'Forçar' }))) return;
        b.disabled = true; if (await safe(() => post('/api/vm/action', { provider: b.dataset.p, name: b.dataset.n, action: a }))) toast('Feito.', 'ok'); await sleep(1200); draw();
      });
      $('#vm-new').onclick = async () => {
        const r = await modal({ title: 'Nova VM (VirtualBox)', body: `<div class="field"><span class="label">Nome</span><input class="input" name="name" placeholder="lab-ubuntu"></div><div class="field"><span class="label">Sistema</span><select class="select" name="os"><option value="Linux_64">Linux 64-bit</option><option value="Debian_64">Debian 64-bit</option><option value="Ubuntu_64">Ubuntu 64-bit</option><option value="Windows10_64">Windows 10 64-bit</option></select></div><div class="grid g3"><div class="field"><span class="label">CPUs</span><input class="input" name="cpus" value="2"></div><div class="field"><span class="label">RAM (MB)</span><input class="input" name="memMB" value="2048"></div><div class="field"><span class="label">Disco (GB)</span><input class="input" name="diskGB" value="20"></div></div><div class="field"><span class="label">Caminho da ISO (opcional)</span><input class="input mono" name="iso" placeholder="C:\\\\Users\\\\voce\\\\Downloads\\\\ubuntu.iso"></div>`, actions: [{ label: 'Cancelar', value: null }, { label: 'Criar', value: 'form', kind: 'primary' }] });
        if (r) { const { ok, ...p } = r; if (!p.iso) delete p.iso; if (await safe(() => post('/api/vm/create', p))) { toast('VM criada.', 'ok'); draw(); } }
      };
    };
    await draw();
  },
});
