'use strict';
// Rede (Geo-IP, Temp Mail, Proxy) e gerador de QR Code.

App.register({
  id: 'net', title: 'Rede', icon: 'globe',
  async render(root) {
    let tab = localStorage.getItem('ntab') || 'geo';
    root.innerHTML = App.head('Utilitários', 'Rede', 'Geolocalização de IP, e-mail temporário e gerenciador de proxy.') + `<div class="tabs" id="nt"><button data-t="geo">${icon('map-pin', 15)} Geo-IP</button><button data-t="mail">${icon('mail', 15)} Temp Mail</button><button data-t="proxy">${icon('network', 15)} Proxy</button></div><div id="nb"></div>`;
    const show = (t) => { tab = t; localStorage.setItem('ntab', t); $$('#nt button').forEach((b) => b.classList.toggle('on', b.dataset.t === t)); App.runCleanups(); ({ geo: tabGeo, mail: tabMail, proxy: tabProxy })[t]($('#nb')); };
    $$('#nt button').forEach((b) => b.onclick = () => show(b.dataset.t)); show(tab);
  },
});

function tabGeo(box) {
  box.innerHTML = `<div class="row" style="margin-bottom:20px"><input class="input mono grow" id="g-q" placeholder="IP ou domínio (vazio = seu IP público)" spellcheck="false"><button class="btn primary" id="g-go">${icon('search', 14)} Consultar</button><button class="btn" id="g-me">Meu IP</button></div><div id="g-out"></div><div class="hint" style="margin-top:12px">Consulta feita pelo servidor local ao serviço ipwho.is. O IP consultado e enviado a esse serviço.</div>`;
  const go = async (q) => {
    const out = $('#g-out'); out.innerHTML = `<div class="empty">${icon('refresh-cw', 22, 'spin')}</div>`;
    const r = await safe(() => get(`/api/geoip?q=${encodeURIComponent(q || '')}`)); if (!r) { out.innerHTML = ''; return; }
    const rows = [['IP', r.ip + (r.type ? ` (${r.type})` : '')], r.resolvedFrom && ['Resolvido de', r.resolvedFrom], r.rdns && ['DNS reverso', r.rdns], ['País', `${r.country || '-'} ${r.countryCode ? '(' + r.countryCode + ')' : ''}`], ['Região / cidade', `${r.region || '-'} / ${r.city || '-'}`], r.postal && ['CEP', r.postal], ['Coordenadas', r.lat != null ? `${r.lat}, ${r.lon}` : '-'], ['Fuso', `${r.timezone || '-'} ${r.utc ? '(UTC' + r.utc + ')' : ''}`], ['Provedor (ISP)', r.isp || '-'], ['Organização', r.org || '-'], ['ASN', r.asn ? 'AS' + r.asn : '-'], r.domain && ['Domínio do provedor', r.domain]].filter(Boolean);
    out.innerHTML = `<div class="card card-pad"><div class="row between" style="margin-bottom:14px"><h2 class="mono">${esc(r.ip)}</h2>${r.map ? `<a class="btn sm" href="${esc(r.map)}" target="_blank" rel="noopener noreferrer">${icon('external-link', 14)} Ver no mapa</a>` : ''}</div><dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl></div>`;
  };
  $('#g-go').onclick = () => go($('#g-q').value.trim()); $('#g-me').onclick = () => { $('#g-q').value = ''; go(''); }; $('#g-q').onkeydown = (e) => { if (e.key === 'Enter') go(e.target.value.trim()); };
}

async function tabMail(box) {
  let boxes = (await get('/api/tempmail')).boxes; let cur = boxes[0]?.address || null; let timer;
  const draw = () => {
    box.innerHTML = `<div class="grid g2" style="grid-template-columns:300px 1fr;align-items:start"><div class="card"><div class="card-head"><h2>Caixas</h2><button class="btn sm primary" id="m-new">${icon('plus', 14)} Nova</button></div><div class="list">${boxes.map((b) => `<div class="row" data-b="${esc(b.address)}" style="cursor:pointer;${b.address === cur ? 'background:var(--bg-2)' : ''}"><div class="grow"><b class="mono" style="font-weight:500;font-size:12.5px;word-break:break-all">${esc(b.address)}</b><div class="hint">${fmtTime(b.createdAt)}</div></div></div>`).join('') || `<div class="empty">${icon('mail', 24)}<div>Crie um endereço descartável.</div></div>`}</div></div>
      <div class="card" id="m-main"><div class="empty">${cur ? '' : 'Selecione ou crie uma caixa.'}</div></div></div><div class="hint" style="margin-top:12px">Serviço mail.tm. Use só para cadastros sem importância: qualquer pessoa que souber o endereço pode tentar receber nele. Mensagens são exibidas em sandbox, sem scripts nem imagens externas.</div>`;
    $('#m-new').onclick = async (e) => { const r = await safe(() => post('/api/tempmail'), e.currentTarget); if (r) { boxes = (await get('/api/tempmail')).boxes; cur = r.address; draw(); } };
    $$('[data-b]').forEach((b) => b.onclick = () => { cur = b.dataset.b; draw(); });
    if (cur) inbox();
  };
  async function inbox() {
    clearInterval(timer); const main = $('#m-main'); if (!main) return;
    const load = async () => {
      const r = await get(`/api/tempmail/messages?address=${encodeURIComponent(cur)}`).catch(() => null); if (!r || !$('#m-list')) return;
      $('#m-list').innerHTML = r.messages.map((m) => `<div class="row" data-id="${esc(m.id)}" style="cursor:pointer;align-items:flex-start"><div class="grow"><b style="font-weight:${m.seen ? 400 : 600}">${esc(m.subject || '(sem assunto)')}</b><div class="hint">${esc(m.from)} &middot; ${fmtTime(m.at)}</div><div class="hint">${esc(m.intro || '')}</div></div></div>`).join('') || `<div class="empty">${icon('mail', 24)}<div>Caixa vazia. Atualiza sozinha a cada 8 s.</div></div>`;
      $$('[data-id]', main).forEach((el) => el.onclick = () => open(el.dataset.id));
    };
    main.innerHTML = `<div class="card-head"><div class="row"><code class="mono" style="font-size:13px">${esc(cur)}</code><button class="btn sm icon" id="m-cp">${icon('copy', 14)}</button></div><button class="btn sm danger" id="m-del">${icon('trash-2', 14)} Excluir caixa</button></div><div id="m-view"></div><div class="list" id="m-list"></div>`;
    $('#m-cp').onclick = () => copyText(cur);
    $('#m-del').onclick = async () => { if (await confirmBox('Excluir esta caixa e todas as mensagens?', { danger: true, ok: 'Excluir' })) { await safe(() => del('/api/tempmail', { address: cur })); boxes = (await get('/api/tempmail')).boxes; cur = boxes[0]?.address || null; draw(); } };
    await load(); timer = setInterval(load, 8000); App.leave(() => clearInterval(timer));
    async function open(id) {
      const m = await safe(() => get(`/api/tempmail/message?address=${encodeURIComponent(cur)}&id=${encodeURIComponent(id)}`)); if (!m) return;
      const v = $('#m-view'); v.className = 'card-pad stack'; v.style.borderBottom = '1px solid var(--line)';
      v.innerHTML = `<div class="row between wrap"><div><h2>${esc(m.subject || '(sem assunto)')}</h2><div class="hint">${esc(m.from)} &middot; ${fmtTime(m.at)}${m.attachments ? ` &middot; ${m.attachments} anexo(s) (não exibidos)` : ''}</div></div><div class="seg"><button data-v="t" class="on">Texto</button>${m.html ? '<button data-v="h">HTML</button>' : ''}</div></div><div id="m-body"></div>`;
      const showT = () => { $('#m-body').innerHTML = `<pre class="code" style="white-space:pre-wrap;word-break:break-word">${esc(m.text || '(sem texto)')}</pre>`; };
      const showH = () => { const f = document.createElement('iframe'); f.className = 'email-frame'; f.setAttribute('sandbox', ''); f.setAttribute('referrerpolicy', 'no-referrer'); f.srcdoc = m.html; $('#m-body').replaceChildren(f); };
      showT(); $$('[data-v]', v).forEach((b) => b.onclick = () => { $$('[data-v]', v).forEach((x) => x.classList.toggle('on', x === b)); b.dataset.v === 'h' ? showH() : showT(); });
    }
  }
  draw();
}

async function tabProxy(box) {
  const draw = async () => {
    const [sys, l] = await Promise.all([get('/api/proxy/system'), get('/api/proxy/list')]);
    box.innerHTML = `<div class="grid g2" style="align-items:start"><div class="stack">
      <div class="card card-pad stack"><div class="row between"><h2>Proxy do Windows</h2><span class="badge ${sys.enabled ? 'ok' : ''}">${sys.supported === false ? 'indisponível' : sys.enabled ? 'ligado' : 'desligado'}</span></div>
        <dl class="kv"><dt>servidor</dt><dd class="mono">${esc(sys.server || '-')}</dd><dt>exceções</dt><dd class="mono" style="word-break:break-all">${esc(sys.bypass || '-')}</dd>${sys.pac ? `<dt>PAC</dt><dd class="mono">${esc(sys.pac)}</dd>` : ''}</dl>
        <div class="field"><span class="label">Definir host:porta</span><input class="input mono" id="sp-s" placeholder="127.0.0.1:8080" value="${esc(sys.server || '')}"></div>
        <div class="row"><button class="btn primary" id="sp-on">Ligar proxy</button><button class="btn" id="sp-off" ${sys.enabled ? '' : 'disabled'}>Desligar</button></div><div class="hint">Altera o proxy do usuário atual (Configurações > Rede > Proxy). Vale para navegadores e apps que usam a configuração do sistema.</div></div>
      <div class="card card-pad stack"><h2>Credencial longa para seu proxy</h2><p class="muted">Gera uma senha de 256 caracteres para você configurar no <b>seu</b> servidor de proxy (Squid, 3proxy, SSH tunnel...). Copie e guarde no gerenciador de senhas.</p><button class="btn" id="sp-pw">${icon('key-round', 14)} Gerar e copiar senha de 256</button></div></div>
      <div class="stack"><div class="card"><div class="card-head"><h2>Proxies salvos</h2></div><div class="list">${l.proxies.map((p) => `<div class="row wrap"><div class="grow"><b style="font-weight:500">${esc(p.name)}</b><div class="hint mono">${esc(p.type)}://${esc(p.host)}:${esc(p.port)}</div></div><span class="hint mono" id="pr-${p.id}"></span><button class="btn sm" data-test="${p.id}">Testar</button><button class="btn sm" data-use="${p.id}">Usar no sistema</button><button class="btn sm icon danger" data-rm="${p.id}">${icon('trash-2', 14)}</button></div>`).join('') || `<div class="empty">${icon('network', 24)}<div>Nenhum proxy salvo.</div></div>`}</div></div>
      <div class="card card-pad stack"><h2>Adicionar proxy</h2><div class="grid g2"><div class="field"><span class="label">Nome</span><input class="input" id="pa-n"></div><div class="field"><span class="label">Tipo</span><select class="select" id="pa-t"><option value="http">HTTP</option><option value="socks5">SOCKS5</option></select></div><div class="field"><span class="label">Host</span><input class="input mono" id="pa-h" placeholder="127.0.0.1"></div><div class="field"><span class="label">Porta</span><input class="input mono" id="pa-p" placeholder="8080"></div></div><button class="btn primary" id="pa-add">${icon('plus', 14)} Adicionar</button></div></div></div>`;
    $('#sp-on').onclick = async () => { if (await safe(() => post('/api/proxy/system', { enabled: true, server: $('#sp-s').value.trim() }))) { toast('Proxy ligado.', 'ok'); draw(); } };
    $('#sp-off').onclick = async () => { if (await safe(() => post('/api/proxy/system', { enabled: false }))) { toast('Proxy desligado.', 'ok'); draw(); } };
    $('#sp-pw').onclick = async () => { const r = await safe(() => post('/api/vault/password', { length: 256 })); if (r) copyText(r.passwords[0]); };
    $('#pa-add').onclick = async () => { if (await safe(() => post('/api/proxy/list', { name: $('#pa-n').value, type: $('#pa-t').value, host: $('#pa-h').value.trim(), port: $('#pa-p').value }))) draw(); };
    $$('[data-rm]').forEach((b) => b.onclick = async () => { await safe(() => del('/api/proxy/list', { id: b.dataset.rm })); draw(); });
    $$('[data-test]').forEach((b) => b.onclick = async () => { const el = $(`#pr-${b.dataset.test}`); el.textContent = '...'; const r = await safe(() => post('/api/proxy/test', { id: b.dataset.test })); if (r) { el.style.color = r.ok ? 'var(--ok)' : 'var(--hi)'; el.textContent = r.ok ? `ok ${r.ms}ms` : `${r.error}`; el.title = r.detail || ''; } });
    $$('[data-use]').forEach((b) => b.onclick = async () => { const p = l.proxies.find((x) => x.id === b.dataset.use); if (p.type === 'socks5') return toast('O Windows não aplica SOCKS5 pela configuração de sistema; use HTTP.', 'bad'); if (await confirmBox(`Definir <b class="mono">${esc(p.host)}:${esc(p.port)}</b> como proxy do sistema? Todo o tráfego HTTP(S) dos apps passara por ele.`, { ok: 'Aplicar' })) { await safe(() => post('/api/proxy/system', { enabled: true, server: `${p.host}:${p.port}` })); draw(); } });
  };
  await draw();
}

// ---------- QR Code ----------
App.register({
  id: 'qr', title: 'QR Code', icon: 'qr-code',
  async render(root) {
    let type = 'text';
    const wifiEsc = (s) => String(s).replace(/([\\;,:"])/g, '\\$1');
    const TYPES = {
      text: { label: 'Texto / URL', icon: 'link', fields: '<div class="field"><span class="label">Conteúdo</span><textarea class="input" id="q-text" rows="4" placeholder="https://exemplo.com"></textarea></div>', value: () => $('#q-text').value },
      wifi: { label: 'Wi-Fi', icon: 'wifi', fields: '<div class="field"><span class="label">Nome da rede (SSID)</span><input class="input" id="q-ssid"></div><div class="field"><span class="label">Senha</span><input class="input" id="q-pass"></div><div class="field"><span class="label">Segurança</span><select class="select" id="q-sec"><option value="WPA">WPA/WPA2/WPA3</option><option value="WEP">WEP</option><option value="nopass">Aberta</option></select></div>', value: () => $('#q-ssid').value ? `WIFI:T:${$('#q-sec').value};S:${wifiEsc($('#q-ssid').value)};${$('#q-sec').value === 'nopass' ? '' : `P:${wifiEsc($('#q-pass').value)};`};` : '' },
      mail: { label: 'E-mail', icon: 'mail', fields: '<div class="field"><span class="label">Para</span><input class="input" id="q-to" placeholder="nome@exemplo.com"></div><div class="field"><span class="label">Assunto</span><input class="input" id="q-sub"></div><div class="field"><span class="label">Mensagem</span><textarea class="input" id="q-body" rows="3"></textarea></div>', value: () => $('#q-to').value ? `mailto:${$('#q-to').value}?subject=${encodeURIComponent($('#q-sub').value)}&body=${encodeURIComponent($('#q-body').value)}` : '' },
      tel: { label: 'Telefone', icon: 'send', fields: '<div class="field"><span class="label">Número</span><input class="input" id="q-tel" placeholder="+5511999999999"></div>', value: () => $('#q-tel').value ? `tel:${$('#q-tel').value.replace(/[^\d+]/g, '')}` : '' },
    };
    root.innerHTML = App.head('Utilitários', 'QR Code', 'Gere QR codes de texto, Wi-Fi, e-mail e telefone. Tudo local: nada e enviado para fora.') + `<div class="grid g2" style="grid-template-columns:1fr .8fr;align-items:start"><div class="card card-pad stack"><div class="seg" id="q-types" style="flex-wrap:wrap">${Object.entries(TYPES).map(([k, t]) => `<button data-k="${k}">${t.label}</button>`).join('')}</div><div id="q-fields" class="stack"></div><div class="field"><span class="label">Correção de erros</span><select class="select" id="q-ec"><option value="L">Baixa (L)</option><option value="M" selected>Media (M)</option><option value="Q">Alta (Q)</option><option value="H">Maxima (H)</option></select></div></div>
      <div class="card card-pad stack" style="justify-items:center"><div class="qr-box" id="q-out"><div style="width:220px;height:220px;display:grid;place-items:center;color:#999;font-size:13px">Preencha ao lado</div></div><div class="row"><button class="btn" id="q-svg" disabled>${icon('download', 14)} SVG</button><button class="btn" id="q-png" disabled>${icon('download', 14)} PNG</button></div></div></div>`;
    let svg = '';
    const render = () => {
      const v = TYPES[type].value(); const out = $('#q-out');
      if (!v) { svg = ''; out.innerHTML = '<div style="width:220px;height:220px;display:grid;place-items:center;color:#999;font-size:13px">Preencha ao lado</div>'; $('#q-svg').disabled = $('#q-png').disabled = true; return; }
      try { const q = qrcode(0, $('#q-ec').value); q.addData(v); q.make(); svg = q.createSvgTag({ cellSize: 8, margin: 2, scalable: true }); out.innerHTML = svg; $('#q-svg').disabled = $('#q-png').disabled = false; } catch { out.innerHTML = '<div style="width:220px;color:#c00;font-size:13px">Conteúdo grande demais para um QR code.</div>'; $('#q-svg').disabled = $('#q-png').disabled = true; }
    };
    const setType = (k) => { type = k; $$('#q-types button').forEach((b) => b.classList.toggle('on', b.dataset.k === k)); $('#q-fields').innerHTML = TYPES[k].fields; $$('#q-fields input,#q-fields textarea,#q-fields select').forEach((el) => el.addEventListener('input', render)); render(); };
    $$('#q-types button').forEach((b) => b.onclick = () => setType(b.dataset.k)); $('#q-ec').onchange = render; setType('text');
    const dl = (blob, name) => { const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
    $('#q-svg').onclick = () => dl(new Blob([svg.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"')], { type: 'image/svg+xml' }), 'qrcode.svg');
    $('#q-png').onclick = () => { const img = new Image(); img.onload = () => { const c = document.createElement('canvas'); c.width = c.height = 1024; const x = c.getContext('2d'); x.fillStyle = '#fff'; x.fillRect(0, 0, 1024, 1024); x.imageSmoothingEnabled = false; x.drawImage(img, 0, 0, 1024, 1024); c.toBlob((b) => dl(b, 'qrcode.png')); }; img.src = 'data:image/svg+xml;base64,' + btoa(svg.replace('<svg', '<svg xmlns="http://www.w3.org/2000/svg"').replace(/width="\d+px"/, 'width="1024"').replace(/height="\d+px"/, 'height="1024"')); };
  },
});
