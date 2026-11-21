'use strict';
// Agentes de IA (chat com ferramentas e aprovações) e Modelos.

const MODES = {
  ask: ['Perguntar', 'Só leitura roda sozinha. Todo o resto pede seu OK.'],
  safe: ['Seguro', 'Leitura e scans do escopo rodam sozinhos. Escrita, shell e VMs pedem OK.'],
  full: ['Total', 'Nada pede OK. Continuam valendo o escopo de alvos e os bloqueios catastróficos.'],
};
const RISK = { read: ['ok', 'leitura'], active: ['medium', 'ativa'], write: ['high', 'escrita'], exec: ['high', 'execução'] };

App.register({
  id: 'agents', title: 'Agentes', icon: 'bot',
  async render(root) {
    let data = await get('/api/agents'); let agentId = localStorage.getItem('agent') || data.agents[0].id;
    if (!data.agents.some((a) => a.id === agentId)) agentId = data.agents[0].id;
    let sid = null; let closeStream = null; let live = null; let status = 'idle';

    root.innerHTML = App.head('Inteligência', 'Agentes', 'Cada agente tem ferramentas proprias e você decide quanta autonomia ele tem.') + `
      <div class="chat"><div class="chat-side" id="ag-side"></div>
      <div class="chat-main"><div class="chat-top" id="ag-top"></div><div class="msgs" id="msgs"></div>
      <div class="composer"><textarea class="input" id="ag-in" rows="1" placeholder="Peca algo ao agente..." title="Enter envia, Shift+Enter quebra a linha"></textarea><button class="btn primary" id="ag-send">${icon('send')}</button><button class="btn danger hide" id="ag-stop">${icon('square')} Parar</button></div></div></div>`;
    const msgs = $('#msgs'); const input = $('#ag-in');
    const agent = () => data.agents.find((a) => a.id === agentId);
    const scroll = () => { msgs.scrollTop = msgs.scrollHeight; };

    function renderSide() {
      const sessions = data.sessions.filter((s) => s.agentId === agentId);
      $('#ag-side').innerHTML = data.agents.map((a) => `<div class="agent-item ${a.id === agentId ? 'on' : ''}" data-a="${a.id}"><div class="ic-box">${icon(a.icon, 17)}</div><div class="grow"><b>${esc(a.name)}</b><small>${esc(a.blurb)}</small><div style="margin-top:6px"><span class="badge ${a.autonomy === 'full' ? 'high' : a.autonomy === 'safe' ? 'medium' : 'ok'}">${MODES[a.autonomy][0]}</span></div></div></div>`).join('') +
        `<div class="label" style="padding:14px 16px 6px">Conversas</div>` + (sessions.map((s) => `<div class="agent-item ${s.id === sid ? 'on' : ''}" data-s="${s.id}" style="padding:9px 16px"><div class="grow"><small style="color:var(--tx)">${esc(s.title)}</small></div><button class="btn icon ghost sm" data-del="${s.id}" aria-label="Apagar">${icon('trash-2', 14)}</button></div>`).join('') || '<div class="hint" style="padding:0 16px 14px">Nenhuma ainda.</div>');
      $$('[data-a]').forEach((el) => el.onclick = () => { agentId = el.dataset.a; localStorage.setItem('agent', agentId); sid = null; openLatest(); });
      $$('[data-s]').forEach((el) => el.onclick = (e) => { if (e.target.closest('[data-del]')) return; openSession(el.dataset.s); });
      $$('[data-del]').forEach((b) => b.onclick = async () => { await safe(() => del(`/api/agents/sessions/${b.dataset.del}`)); if (sid === b.dataset.del) sid = null; await reload(); openLatest(); });
    }
    function renderTop() {
      const a = agent();
      $('#ag-top').innerHTML = `<div class="row"><div class="ic-box" style="width:28px;height:28px;border:1px solid var(--line-2);display:grid;place-items:center;border-radius:4px;color:var(--ac)">${icon(a.icon, 15)}</div><div><b>${esc(a.name)}</b><div class="hint">${a.tools.length ? 'Ferramentas: ' + a.tools.join(', ') : 'Sem ferramentas (somente conversa)'}</div></div></div>
        <div class="row wrap">${a.tools.length ? `<div class="seg" title="Autonomia">${Object.entries(MODES).map(([k, [l, d]]) => `<button data-m="${k}" class="${a.autonomy === k ? 'on' : ''}" title="${esc(d)}">${l}</button>`).join('')}</div>` : ''}<button class="btn sm" id="ag-new">${icon('plus')} Nova</button></div>`;
      $$('[data-m]').forEach((b) => b.onclick = async () => {
        const m = b.dataset.m; if (m === agent().autonomy) return; let pin;
        if (m === 'full') {
          if (!(await confirmBox(`No modo <b>Total</b>, o agente <b>${esc(agent().name)}</b> executa comandos, escreve arquivos e controla VMs <b>sem pedir aprovação</b>. Um erro do modelo ou uma instrução maliciosa escondida numa página/arquivo pode causar dano real. Os bloqueios catastróficos (formatar disco, apagar o sistema) e o escopo de alvos continuam valendo.`, { title: 'Ligar autonomia total?', ok: 'Entendo o risco', danger: true }))) return;
          pin = await askPin('Digite o PIN para confirmar.'); if (!pin) return;
        }
        if (await safe(() => post('/api/agents/autonomy', { agent: agentId, mode: m, pin }))) { await reload(); renderTop(); renderSide(); toast(`Autonomia: ${MODES[m][0]}`, 'ok'); }
      });
      $('#ag-new').onclick = () => newSession();
    }
    async function reload() { data = await get('/api/agents'); }
    async function newSession() { const r = await post('/api/agents/sessions', { agent: agentId }); await reload(); openSession(r.id); }
    async function openLatest() { const s = data.sessions.find((x) => x.agentId === agentId); if (s) openSession(s.id); else { renderTop(); renderSide(); msgs.innerHTML = emptyState(); setStatus('idle'); closeStream?.(); } }
    function emptyState() { const a = agent(); return `<div class="empty" style="margin:auto">${icon(a.icon, 30)}<div><b style="color:var(--tx)">${esc(a.name)}</b><br>${esc(a.blurb)}</div><div class="hint">Escreva abaixo para comecar.</div></div>`; }

    function setStatus(s) {
      status = s; const run = s !== 'idle';
      $('#ag-send').classList.toggle('hide', run); $('#ag-stop').classList.toggle('hide', !run); input.disabled = run;
      msgs.querySelector('.typing-row')?.remove();
      if (s === 'running') { const d = document.createElement('div'); d.className = 'typing-row hint mono'; d.innerHTML = '<span class="typing">pensando</span>'; msgs.append(d); scroll(); }
      if (s === 'waiting') { const d = document.createElement('div'); d.className = 'typing-row hint mono'; d.textContent = 'aguardando sua aprovação...'; msgs.append(d); scroll(); }
    }

    function openSession(id) {
      closeStream?.(); sid = id; msgs.innerHTML = ''; live = null; renderTop(); renderSide();
      closeStream = sse(`/api/agents/sessions/${id}/stream`, onEvent); App.leave(() => closeStream?.());
    }
    function bubble(role, html) { const d = document.createElement('div'); d.className = `msg ${role}`; d.innerHTML = `<div class="who">${role === 'user' ? 'Você' : esc(agent().name)}</div><div class="body">${html}</div>`; msgs.append(d); return d; }
    function onEvent(e) {
      msgs.querySelector('.typing-row')?.remove();
      if (e.k === 'status') { setStatus(e.v); return; }
      if (e.k === 'tok') { if (!live) { live = { el: bubble('assistant', ''), text: '' }; } live.text += e.text; live.el.querySelector('.body').innerHTML = md(live.text) || '<span class="typing"></span>'; scroll(); return; }
      if (e.k === 'msg') {
        if (e.role === 'user') bubble('user', esc(e.text));
        else { if (live) { live.el.querySelector('.body').innerHTML = md(e.text); if (!md(e.text)) live.el.remove(); live = null; } else if (md(e.text)) bubble('assistant', md(e.text)); }
      } else if (e.k === 'tool') {
        const [cls, lab] = RISK[e.risk] || ['info', e.risk];
        const d = document.createElement('div'); d.className = 'toolcall'; d.innerHTML = `<div class="th">${icon('terminal', 14)}<span>${esc(e.name)}</span><span class="badge ${cls}" style="margin-left:auto">${lab}</span></div><pre>${esc(e.text)}</pre>`; msgs.append(d);
      } else if (e.k === 'approval') {
        const d = document.createElement('div'); d.className = 'approval'; d.dataset.id = e.id;
        d.innerHTML = `<div class="row">${icon('triangle-alert', 16)}<b>O agente quer executar:</b><span class="badge ${(RISK[e.risk] || [])[0] || ''}" style="margin-left:auto">${esc(e.tool)}</span></div><pre>${esc(e.text)}</pre><div class="row"><button class="btn primary sm" data-ok>${icon('check', 14)} Aprovar</button><button class="btn danger sm" data-no>${icon('x', 14)} Negar</button></div>`;
        d.querySelector('[data-ok]').onclick = () => post('/api/agents/approve', { id: e.id, approve: true });
        d.querySelector('[data-no]').onclick = () => post('/api/agents/approve', { id: e.id, approve: false });
        msgs.append(d);
      } else if (e.k === 'approved') {
        const d = msgs.querySelector(`.approval[data-id="${e.id}"]`);
        if (d) { d.style.borderColor = e.ok ? 'var(--ok)' : 'var(--hi)'; d.style.background = 'var(--bg)'; d.querySelector('.row:last-child').outerHTML = `<div class="hint mono">${e.ok ? 'aprovado' : 'negado'}</div>`; }
      } else if (e.k === 'result') {
        const d = document.createElement('div'); d.className = 'toolcall'; d.innerHTML = `<div class="th">${icon('check', 14)}<span>resultado - ${esc(e.name)}</span></div><pre>${esc(e.text)}</pre>`; msgs.append(d);
      } else if (e.k === 'error') {
        const d = document.createElement('div'); d.className = 'notice bad'; d.innerHTML = `${icon('circle-alert')}<div>${esc(e.text)}</div>`; msgs.append(d);
      }
      scroll();
    }
    async function send() {
      const text = input.value.trim(); if (!text || status !== 'idle') return;
      if (!sid) { const r = await safe(() => post('/api/agents/sessions', { agent: agentId })); if (!r) return; await reload(); await new Promise((res) => { openSession(r.id); setTimeout(res, 250); }); }
      input.value = ''; input.style.height = ''; await safe(() => post(`/api/agents/sessions/${sid}/send`, { text }));
      reload().then(renderSide);
    }
    $('#ag-send').onclick = send; $('#ag-stop').onclick = () => post(`/api/agents/sessions/${sid}/stop`);
    input.onkeydown = (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } };
    input.oninput = () => { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 160) + 'px'; };
    App.leave(() => closeStream?.());
    renderSide(); renderTop(); openLatest();
  },
});

App.register({
  id: 'models', title: 'Modelos de IA', icon: 'brain-circuit',
  async render(root) {
    const draw = async () => {
      const [st, sys] = await Promise.all([get('/api/ai/status'), get('/api/system')]); const o = st.ollama; const s = st.settings; const installed = new Set(o.models.map((m) => m.name));
      root.innerHTML = App.head('Inteligência', 'Modelos de IA', 'IA 100% local e gratuita, rodando no seu PC com Ollama: privada, offline e sem limite de uso.') + `
      <div class="notice" style="margin-bottom:20px">${icon('info')}<div>Seu PC tem <b>${sys.cores} threads</b> e <b>${fmtBytes(sys.memTotal)}</b> de RAM, com GPU de ~6 GB de VRAM. Modelos de <b>7B/8B</b> cabem inteiros na GPU (rápidos). Os de <b>14B</b> são bem mais capazes, mas o Ollama divide entre GPU e processador e eles ficam mais lentos. Acima disso não cabe com folga.</div></div>
      <div class="grid g2" style="align-items:start">
        <div class="stack">
          <div class="card"><div class="card-head"><div class="row"><i class="dot ${o.running ? 'ok' : 'bad'}"></i><h2>Ollama ${o.running ? 'v' + esc(o.version) : 'parado'}</h2></div>${o.running ? '' : `<button class="btn sm primary" id="o-start">${icon('play', 14)} Iniciar</button>`}</div>
            <div class="list">${o.running ? (o.models.map((m) => `<label class="row" style="cursor:pointer"><input type="radio" name="om" value="${esc(m.name)}" ${s.ollamaModel === m.name ? 'checked' : ''} style="accent-color:var(--ac)"><div class="grow"><b class="mono" style="font-weight:500">${esc(m.name)}</b><div class="hint">${fmtBytes(m.size)}</div></div>${s.ollamaModel === m.name ? '<span class="badge ac">ativo</span>' : ''}</label>`).join('') || `<div class="empty">Nenhum modelo instalado. Baixe um abaixo.</div>`) : `<div class="empty">${icon('power', 24)}<div>Inicie o Ollama para listar modelos.<br><span class="hint">Não instalado? <code>winget install -e --id Ollama.Ollama</code></span></div></div>`}</div></div>
          <div class="card"><div class="card-head"><h2>Recomendados para sua GPU</h2></div><div class="list">${o.recommended.map((m) => `<div class="row"><div class="grow"><b class="mono" style="font-weight:500">${esc(m.id)}</b> <span class="hint">${esc(m.size)}</span><div class="hint">${esc(m.note)}</div></div>${installed.has(m.id) ? '<span class="badge ok">instalado</span>' : `<button class="btn sm" data-pull="${esc(m.id)}" ${o.running ? '' : 'disabled'}>${icon('download', 14)} Baixar</button>`}</div>`).join('')}</div></div>
          <div class="console hide" id="pull-log" style="height:140px"></div>
        </div>
        <div class="stack">
          <div class="card card-pad stack"><h2>Qual escolher</h2>
            <dl class="kv" style="grid-template-columns:110px 1fr"><dt>dia a dia</dt><dd><b>qwen2.5-coder:7b</b>: rápido e muito bom em código. É o padrão.</dd><dt>mais capaz</dt><dd><b>qwen2.5-coder:14b</b>: respostas e código melhores; espere poucas palavras por segundo.</dd><dt>raciocínio</dt><dd><b>qwen3:8b</b> ou <b>qwen3:14b</b>: "pensam" antes de responder; ótimos para analisar e planejar.</dd></dl>
            <div class="hint">Para os agentes, que seguem um protocolo de ferramentas, modelos maiores erram menos. Se um 7B se perder, troque para um 14B.</div></div>
          <div class="card card-pad stack"><h2>Parâmetros</h2>
            <div class="field"><span class="label">Contexto (tokens) - ${s.numCtx}</span><input type="range" id="ctx" min="2048" max="16384" step="1024" value="${s.numCtx}" style="accent-color:var(--ac)"><span class="hint">Mais contexto usa mais memória. Em 6 GB de VRAM, 8192 é um bom limite; com modelos 14B, prefira 4096.</span></div>
            <div class="field"><span class="label">Temperatura - <span id="tv">${s.temperature}</span></span><input type="range" id="tmp" min="0" max="1" step="0.1" value="${s.temperature}" style="accent-color:var(--ac)"></div>
            <button class="btn" id="par-save">Salvar parâmetros</button></div>
        </div>
      </div>`;
      $('#o-start')?.addEventListener('click', async () => { await safe(() => post('/api/ai/serve')); toast('Iniciando Ollama...'); await sleep(2500); draw(); App.refreshStatus(); });
      $$('input[name=om]').forEach((r) => r.onchange = async () => { await safe(() => post('/api/ai/settings', { ollamaModel: r.value })); draw(); App.refreshStatus(); });
      $$('[data-pull]').forEach((b) => b.onclick = async () => {
        if (!(await confirmBox(`Baixar <b class="mono">${esc(b.dataset.pull)}</b> do repositório do Ollama. Ocupa vários GB de disco (você tem pouco espaço livre) e pode demorar.`, { ok: 'Baixar' }))) return;
        const r = await safe(() => post('/api/ai/pull', { model: b.dataset.pull })); if (!r) return;
        const box = $('#pull-log'); box.classList.remove('hide'); await watchJob(r.job, box); draw(); App.refreshStatus();
      });
      $('#tmp').oninput = (e) => { $('#tv').textContent = e.target.value; };
      $('#par-save').onclick = async () => { if (await safe(() => post('/api/ai/settings', { numCtx: +$('#ctx').value, temperature: +$('#tmp').value }))) toast('Salvo.', 'ok'); };
    };
    await draw();
  },
});
