'use strict';
// Painel, Acesso remoto e Segurança.

function qrSvg(text, cell = 4) {
  const q = qrcode(0, 'M'); q.addData(text); q.make();
  return q.createSvgTag({ cellSize: cell, margin: 0, scalable: true });
}

App.register({
  id: 'dashboard', title: 'Painel', icon: 'layout-dashboard',
  async render(root) {
    const [sys, ai, rm, lock, vms, audit, agents] = await Promise.all([
      get('/api/system'), get('/api/ai/status'), get('/api/remote'), get('/api/applock'),
      get('/api/vm/list').catch(() => ({ vms: [] })), get('/api/audit'), get('/api/agents'),
    ]);
    const memUsed = sys.memTotal - sys.memFree; const memPct = Math.round(memUsed / sys.memTotal * 100);
    const o = ai.ollama;
    const modules = [
      ['agents', 'bot', 'Agentes de IA', `${agents.agents.length} perfis, ${agents.agents.filter((a) => a.autonomy === 'full').length} em modo total`, 'ok'],
      ['models', 'brain-circuit', 'IA local (Ollama)', !o.running ? 'Parado - inicie em Modelos de IA' : o.models.some((x) => x.name === ai.settings.ollamaModel) ? `Modelo ativo: ${ai.settings.ollamaModel}` : `Falta baixar ${ai.settings.ollamaModel}`, o.running && o.models.some((x) => x.name === ai.settings.ollamaModel) ? 'ok' : 'warn'],
      ['scope', 'route', 'Escopo autorizado', `${sys.counts.scope} alvo(s)`, 'ok'],
      ['vault', 'folder-lock', 'Bloqueio de apps', `${lock.apps.length} app(s) - ${lock.locked ? 'travado' : 'destravado'}`, lock.apps.length ? 'ok' : 'warn'],
      ['lab', 'container', 'Máquinas virtuais', `${vms.vms.filter((v) => !v.error).length} VM(s) detectada(s)`, 'ok'],
      ['remote', 'monitor-smartphone', 'Acesso remoto', rm.config.enabled ? `Ativo em ${rm.config.bindIp}:${rm.port}` : 'Desligado (somente este PC)', rm.config.enabled ? 'ok' : 'warn'],
    ];
    root.innerHTML = App.head('Visão geral', 'Painel', `${sys.host} - ${sys.platform}`, `<a class="btn" href="#/scan">${icon('scan-search')} Novo scan</a><a class="btn primary" href="#/agents">${icon('bot')} Falar com um agente</a>`) + `
    <div class="cells c4" style="grid-template-columns:repeat(4,1fr);margin-bottom:20px">
      <div class="cell"><div class="label">CPU</div><div class="num" id="d-cpu">${sys.cpuUsage}<small>%</small></div><div class="bar"><i id="d-cpub" style="width:${sys.cpuUsage}%"></i></div><div class="hint" style="margin-top:8px">${esc(sys.cpu)} (${sys.cores} threads)</div></div>
      <div class="cell"><div class="label">Memória</div><div class="num" id="d-mem">${memPct}<small>%</small></div><div class="bar"><i id="d-memb" style="width:${memPct}%"></i></div><div class="hint" style="margin-top:8px">${fmtBytes(memUsed)} de ${fmtBytes(sys.memTotal)}</div></div>
      <div class="cell"><div class="label">Ligado há</div><div class="num">${fmtUp(sys.uptime)}</div><div class="hint">Node ${esc(sys.node)}</div></div>
      <div class="cell"><div class="label">Tarefas ativas</div><div class="num" id="d-jobs">${sys.counts.jobs}</div><div class="hint">${sys.counts.scans} scan(s) no histórico</div></div>
    </div>
    <div class="grid g2" style="grid-template-columns:1.1fr .9fr;align-items:start">
      <div class="card"><div class="card-head"><h2>Modulos</h2><span class="label">estado</span></div>
        <div class="list">${modules.map(([id, ic, t, d, st]) => `<a href="#/${id}" class="row" style="color:inherit;text-decoration:none">${icon(ic, 18)}<div class="grow"><b style="font-weight:500">${esc(t)}</b><div class="hint">${esc(d)}</div></div><i class="dot ${st}"></i></a>`).join('')}</div></div>
      <div class="card"><div class="card-head"><h2>Atividade recente</h2><a href="#/security" class="hint">ver tudo</a></div>
        <div class="list">${audit.events.slice(0, 9).map((e) => `<div><div class="row between"><span class="mono" style="font-size:12.5px">${esc(e.type)}</span><span class="hint mono">${new Date(e.t).toLocaleTimeString('pt-BR')}</span></div></div>`).join('') || '<div class="empty">Sem atividade ainda.</div>'}</div></div>
    </div>`;
    App.every(async () => {
      const s = await get('/api/system').catch(() => null); if (!s || !$('#d-cpu')) return;
      $('#d-cpu').firstChild.textContent = s.cpuUsage; $('#d-cpub').style.width = s.cpuUsage + '%';
      const p = Math.round((s.memTotal - s.memFree) / s.memTotal * 100); $('#d-mem').firstChild.textContent = p; $('#d-memb').style.width = p + '%'; $('#d-jobs').textContent = s.counts.jobs;
    }, 3000);
  },
});

App.register({
  id: 'remote', title: 'Acesso remoto', icon: 'monitor-smartphone',
  async render(root) {
    const draw = async () => {
      const r = await get('/api/remote'); const cur = r.config;
      const urls = cur.enabled ? [`http://${cur.bindIp}:${r.port}`] : [];
      root.innerHTML = App.head('Sistema', 'Acesso remoto', 'Use o Sentinel e os agentes de qualquer lugar, sem abrir portas no roteador: pela sua VPN privada.') + `
      <div class="notice warn" style="margin-bottom:20px">${icon('triangle-alert')}<div><b>Como funciona e por que e assim.</b> O Sentinel nunca escuta em IP público. Você instala o <b>Tailscale</b> (gratis) neste PC e no celular/notebook; ele cria uma rede privada criptografada. De fora de casa, você abre o endereço <code>100.x.x.x</code> deste PC. Abrir porta no roteador com acesso total ao PC seria invadido em horas.</div></div>
      <div class="grid g2" style="grid-template-columns:1.2fr .8fr;align-items:start">
        <div class="stack">
          <div class="card"><div class="card-head"><h2>Interfaces de rede privada</h2><label class="row"><span class="hint">${cur.enabled ? 'ligado' : 'desligado'}</span><span class="switch"><input type="checkbox" id="rm-on" ${cur.enabled ? 'checked' : ''} ${r.interfaces.length ? '' : 'disabled'}><i></i></span></label></div>
            <div class="list">${r.interfaces.length ? r.interfaces.map((i) => `<label class="row" style="cursor:pointer"><input type="radio" name="rm-if" value="${esc(i.ip)}" ${cur.bindIp === i.ip || (!cur.bindIp && i.kind === 'tailscale') ? 'checked' : ''} style="accent-color:var(--ac)"><div class="grow"><b class="mono" style="font-weight:500">${esc(i.ip)}</b><div class="hint">${esc(i.name)}</div></div><span class="badge ${i.kind === 'tailscale' ? 'ok' : 'medium'}">${i.kind === 'tailscale' ? 'Tailscale (recomendado)' : 'Rede local'}</span></label>`).join('') : `<div class="empty">${icon('wifi', 24)}<div>Nenhuma interface privada detectada.</div></div>`}</div></div>
          <div class="card card-pad stack"><h2>Passo a passo</h2>
            <ol class="muted" style="padding-left:1.2em;display:grid;gap:8px"><li>Neste PC, instale o Tailscale: <code>winget install -e --id Tailscale.Tailscale</code> e faça login.</li><li>No celular, instale o app Tailscale e entre na <b>mesma conta</b>.</li><li>Volte aqui: a interface <b>Tailscale</b> aparece acima. Selecione-a e ligue o acesso.</li><li>No celular, abra o endereço mostrado ao lado e entre com seu PIN (e 2FA).</li><li>Ative o <b>2FA</b> em <a href="#/security">Segurança</a> antes de usar fora de casa.</li></ol>
            <div class="hint">Com a opção "Rede local" só quem está no seu Wi-Fi acessa. Mantenha o PC ligado e sem suspensão para acesso remoto.</div></div>
        </div>
        <div class="card card-pad stack">${cur.enabled ? `<h2>Conectar de outro aparelho</h2><div class="qr-box">${qrSvg(urls[0])}</div><div class="row"><code class="grow mono">${esc(urls[0])}</code><button class="btn sm" id="cp-url">${icon('copy')}</button></div><div class="hint">Escaneie com a câmera do celular (conectado ao Tailscale).</div>` : `<div class="empty">${icon('monitor-smartphone', 28)}<div>Acesso remoto desligado.<br>Somente este PC acessa o Sentinel.</div></div>`}</div>
      </div>`;
      $('#rm-on')?.addEventListener('change', async (e) => {
        const ip = $('input[name=rm-if]:checked')?.value;
        if (e.target.checked && !ip) { e.target.checked = false; return toast('Selecione uma interface.', 'bad'); }
        if (e.target.checked && !(await confirmBox('Ligar o acesso remoto expõe o login do Sentinel nessa rede privada. Ative o 2FA e use um PIN forte.', { ok: 'Ligar' }))) { e.target.checked = false; return; }
        await safe(() => post('/api/remote', { enabled: e.target.checked, bindIp: ip })); draw(); App.refreshStatus();
      });
      $$('input[name=rm-if]').forEach((i) => i.addEventListener('change', async () => { if (cur.enabled) { await safe(() => post('/api/remote', { enabled: true, bindIp: i.value })); draw(); App.refreshStatus(); } }));
      $('#cp-url')?.addEventListener('click', () => copyText(urls[0]));
    };
    await draw();
  },
});

App.register({
  id: 'security', title: 'Segurança', icon: 'fingerprint',
  async render(root) {
    const st = await get('/api/auth/state'); const audit = await get('/api/audit');
    root.innerHTML = App.head('Sistema', 'Segurança', 'PIN, autenticação em dois fatores e o registro de tudo que os agentes e você fizeram.') + `
    <div class="grid g2" style="align-items:start;margin-bottom:20px">
      <div class="card card-pad stack"><h2>Alterar PIN</h2>
        <div class="field"><span class="label">PIN atual</span><input class="input" type="password" id="pin-a"></div><div class="field"><span class="label">Novo PIN</span><input class="input" type="password" id="pin-b"></div>
        <button class="btn" id="pin-go">${icon('key-round')} Alterar PIN</button></div>
      <div class="card card-pad stack"><div class="row between"><h2>Autenticação em dois fatores</h2><span class="badge ${st.needs2fa ? 'ok' : 'medium'}">${st.needs2fa ? 'ativo' : 'inativo'}</span></div>
        <p class="muted">Use um app autenticador (Google Authenticator, Aegis, 1Password). Recomendado antes de ligar o acesso remoto.</p>
        <div id="tf">${st.needs2fa ? `<button class="btn danger" id="tf-off">Desativar 2FA</button>` : `<button class="btn primary" id="tf-on">${icon('shield-check')} Ativar 2FA</button>`}</div></div>
    </div>
    <div class="card"><div class="card-head"><h2>Registro de auditoria</h2><span class="label">últimos ${audit.events.length}</span></div>
      <div style="overflow-x:auto"><table><thead><tr><th>Quando</th><th>Evento</th><th>Detalhe</th></tr></thead><tbody>${audit.events.map((e) => { const { t, type, actor, ...rest } = e; return `<tr><td class="mono dim" style="white-space:nowrap">${fmtTime(t)}</td><td class="mono">${esc(type)}</td><td class="muted mono" style="font-size:12px;word-break:break-all">${esc(JSON.stringify(rest) === '{}' ? '' : JSON.stringify(rest))}</td></tr>`; }).join('')}</tbody></table></div></div>`;
    $('#pin-go').onclick = (e) => safe(async () => { await post('/api/auth/pin', { pin: $('#pin-a').value, newPin: $('#pin-b').value }); toast('PIN alterado.', 'ok'); $('#pin-a').value = $('#pin-b').value = ''; }, e.currentTarget);
    $('#tf-on')?.addEventListener('click', async () => {
      const r = await safe(() => post('/api/auth/2fa/begin')); if (!r) return;
      const res = await modal({ title: 'Ativar 2FA', body: `<p class="muted">Escaneie no app autenticador, ou digite a chave manualmente.</p><div class="qr-box" style="margin:auto">${qrSvg(r.uri)}</div><div class="code mono" style="text-align:center;user-select:all;word-break:break-all">${esc(r.secret)}</div><div class="field"><span class="label">Código de 6 dígitos</span><input class="input mono" name="code" inputmode="numeric" maxlength="6"></div>`, actions: [{ label: 'Cancelar', value: null }, { label: 'Confirmar', value: 'form', kind: 'primary' }] });
      if (res) { await safe(() => post('/api/auth/2fa/confirm', { code: res.code })); App.route(); }
    });
    $('#tf-off')?.addEventListener('click', async () => { const pin = await askPin('Digite o PIN para desativar o 2FA.'); if (pin) { await safe(() => post('/api/auth/2fa/disable', { pin })); App.route(); } });
  },
});
