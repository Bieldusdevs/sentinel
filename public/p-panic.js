'use strict';
// Apagar de emergência: apaga SOMENTE pastas/arquivos que o dono escolhe (cache, logs, histórico
// de apps). Nunca o sistema. Exige PIN + digitar "APAGAR". Pensado para proteger dados se o PC for
// roubado ou acessado sem autorização.

App.register({
  id: 'panic', title: 'Apagar de emergência', icon: 'triangle-alert',
  async render(root) {
    const draw = async () => {
      const [st, presets] = await Promise.all([get('/api/panic'), get('/api/panic/presets')]);
      const byGroup = {};
      for (const p of presets) (byGroup[p.group] ||= []).push(p);
      const already = new Set(st.targets.map((t) => t.path.toLowerCase()));

      root.innerHTML = App.head('Proteção', 'Apagar de emergência', 'Monte uma lista de pastas e arquivos (cache, logs, históricos de apps). Com o PIN, tudo nela é apagado de uma vez. Nunca apaga o Windows nem programas instalados.') + `
      <div class="notice warn" style="margin-bottom:20px">${icon('triangle-alert')}<div><b>Isso é definitivo.</b> Nada aqui vai para a lixeira. Monte a lista com calma e use a prévia antes de apagar. Pastas do sistema, do perfil inteiro e do próprio Sentinel não podem ser adicionadas.</div></div>

      <div class="grid g2" style="grid-template-columns:1.2fr .8fr;align-items:start">
        <div class="stack">
          <div class="card"><div class="card-head"><h2>Lista de apagar (${st.targets.length})</h2>${st.targets.length ? `<button class="btn sm" id="pv-go">${icon('search', 14)} Ver prévia</button>` : ''}</div>
            <div class="list" id="pv-list">${st.targets.map((t) => `<div class="row wrap"><span class="mono" style="word-break:break-all;flex:1">${esc(t.path)}</span>${!t.exists ? '<span class="badge medium">sumiu</span>' : t.kind === 'dir' ? '<span class="badge">pasta</span>' : '<span class="badge">arquivo</span>'}<button class="btn sm icon danger" data-rm="${esc(t.path)}" aria-label="Remover da lista">${icon('x', 14)}</button></div>`).join('') || `<div class="empty">${icon('folder-lock', 24)}<div>Lista vazia. Adicione pastas abaixo.</div></div>`}</div>
            <div id="pv-out"></div>
          </div>

          ${Object.entries(byGroup).map(([g, items]) => `<div class="card"><div class="card-head"><h3>${esc(g)}</h3></div><div class="list">${items.map((p) => `<div class="row"><div class="grow"><b style="font-weight:500">${esc(p.label)}</b><div class="hint mono" style="word-break:break-all">${esc(p.path)}</div></div>${already.has(p.path.toLowerCase()) ? '<span class="badge ok">na lista</span>' : `<button class="btn sm" data-add="${esc(p.path)}" data-note="${esc(p.label)}">${icon('plus', 14)} Adicionar</button>`}</div>`).join('')}</div></div>`).join('') || `<div class="notice">${icon('info')}<div>Nenhum rastro comum de app foi encontrado neste PC. Adicione caminhos manualmente ao lado.</div></div>`}
        </div>

        <div class="stack">
          <div class="card card-pad stack"><h2>Adicionar caminho manual</h2>
            <div id="pz-fb"></div>
            <div class="field"><span class="label">Selecionado</span><div class="code mono" id="pz-sel" style="word-break:break-all;padding:10px;display:block">nenhum</div></div>
            <div class="field"><span class="label">Anotação (opcional)</span><input class="input" id="pz-note" placeholder="ex.: logs do app X"></div>
            <button class="btn" id="pz-add">${icon('plus', 14)} Adicionar à lista</button>
          </div>

          <div class="card card-pad stack"><h2>Opções</h2>
            <label class="row" style="cursor:pointer"><span class="switch"><input type="checkbox" id="pz-ow" ${st.overwrite ? 'checked' : ''}><i></i></span><div class="grow"><b style="font-weight:500">Sobrescrever antes de apagar</b><div class="hint">Mais seguro contra recuperação forense, bem mais lento. Desligado: apagar normal do Windows (recuperável com ferramentas até ser sobrescrito pelo uso do disco).</div></div></label>
          </div>

          <div class="card card-pad stack" style="border-color:var(--line-2)">
            <h2>Apagar agora</h2>
            <label class="check"><input type="checkbox" id="pz-ok"> Entendo que isto é irreversível e já conferi a prévia.</label>
            <div class="field"><span class="label">Digite APAGAR para confirmar</span><input class="input mono" id="pz-word" placeholder="APAGAR" autocomplete="off"></div>
            <div class="field"><span class="label">PIN</span><input class="input" type="password" id="pz-pin" autocomplete="current-password"></div>
            <button class="btn danger" id="pz-go" ${st.targets.length ? '' : 'disabled'}>${icon('trash-2', 14)} Apagar tudo da lista</button>
          </div>
        </div>
      </div>

      <h2 style="margin:36px 0 4px">Backup e desinstalar o Sentinel</h2>
      <p class="muted" style="margin-bottom:16px">A alternativa honesta a esconder uma cópia escondida: você escolhe a pasta (pode ser uma sincronizada com OneDrive/Drive/Dropbox) e o app grava ali um backup cifrado. Desinstalar apaga o app inteiro, de si mesmo — um botão visível, nunca um gatilho oculto.</p>
      <div class="grid g2">
        <div class="card card-pad stack"><h3>${icon('download', 15)} Fazer backup agora</h3><p class="muted" style="font-size:12.5px">Grava um .sntl cifrado (AES-256-GCM) com seus dados (PIN, configurações, histórico) na pasta escolhida. Nada é enviado pela rede — a "nuvem" é a sincronização da sua própria pasta, se você escolher uma.</p>
          <div id="bk-fb"></div><div class="field"><span class="label">Pasta de destino</span><div class="code mono" id="bk-dest" style="word-break:break-all;padding:8px;display:block">nenhuma</div></div>
          <div class="field"><span class="label">Senha do backup</span><input class="input" type="password" id="bk-pw" autocomplete="new-password"></div>
          <button class="btn" id="bk-go">${icon('download', 14)} Fazer backup</button></div>
        <div class="card card-pad stack" style="border-color:var(--line-2)"><h3>${icon('triangle-alert', 15)} Desinstalar o Sentinel</h3><p class="muted" style="font-size:12.5px">Apaga a pasta inteira do app (código, dados, tudo). Definitivo. Faça backup antes se quiser restaurar depois.</p>
          <div class="field"><span class="label">Digite DESINSTALAR</span><input class="input mono" id="sd-word" placeholder="DESINSTALAR" autocomplete="off"></div>
          <div class="field"><span class="label">PIN</span><input class="input" type="password" id="sd-pin" autocomplete="current-password"></div>
          <button class="btn danger" id="sd-go">${icon('zap', 14)} Desinstalar tudo agora</button></div>
      </div>`;

      // seletor de arquivos/pastas (reaproveita o mesmo componente do Cofre)
      let picked = null;
      createFB($('#pz-fb'), { onPick: (p) => { picked = p; $('#pz-sel').textContent = p; } });
      $('#pz-add').onclick = async () => {
        if (!picked) return toast('Selecione um arquivo ou pasta.', 'bad');
        if (await safe(() => post('/api/panic/target', { path: picked, note: $('#pz-note').value }))) { toast('Adicionado à lista.', 'ok'); draw(); }
      };
      $$('[data-rm]').forEach((b) => b.onclick = async () => { await safe(() => del('/api/panic/target', { path: b.dataset.rm })); draw(); });
      $$('[data-add]').forEach((b) => b.onclick = async () => { if (await safe(() => post('/api/panic/target', { path: b.dataset.add, note: b.dataset.note }))) { toast('Adicionado.', 'ok'); draw(); } });
      $('#pz-ow').onchange = (e) => safe(() => post('/api/panic/overwrite', { on: e.target.checked }));

      let bkDest = null;
      createFB($('#bk-fb'), { onPick: (p, isDir) => { bkDest = isDir ? p : null; $('#bk-dest').textContent = bkDest || 'escolha uma pasta (não um arquivo)'; } });
      $('#bk-go').onclick = async (e) => {
        if (!bkDest) return toast('Escolha uma pasta de destino (use "Usar esta pasta").', 'bad');
        const pw = $('#bk-pw').value; if (pw.length < 8) return toast('Senha de backup muito curta.', 'bad');
        const r = await safe(() => post('/api/panic/backup', { dest: bkDest, password: pw }), e.currentTarget);
        if (r) { toast(`Backup criado: ${r.file}`, 'ok'); $('#bk-pw').value = ''; }
      };
      $('#sd-go').onclick = async (e) => {
        const word = $('#sd-word').value; const pin = $('#sd-pin').value;
        if (!word || !pin) return toast('Preencha a confirmação e o PIN.', 'bad');
        if (!(await confirmBox('Isto vai apagar o aplicativo Sentinel <b>inteiro</b> (código e dados), para sempre. Se você não fez backup, não tem como desfazer.', { title: 'Desinstalar o Sentinel?', ok: 'Desinstalar definitivamente', danger: true }))) return;
        const r = await safe(() => post('/api/panic/selfdestruct', { confirm: word, pin }), e.currentTarget);
        if (r) { document.body.innerHTML = '<div style="min-height:100vh;display:grid;place-items:center;background:#000;color:#fff;font:14px var(--mono)">Sentinel foi desinstalado. Esta janela pode ser fechada.</div>'; }
      };

      $('#pv-go')?.addEventListener('click', async () => {
        const out = $('#pv-out'); out.innerHTML = `<div class="empty">${icon('refresh-cw', 20, 'spin')}</div>`;
        const p = await safe(() => get('/api/panic/preview')); if (!p) { out.innerHTML = ''; return; }
        out.innerHTML = `<div class="card-pad" style="border-top:1px solid var(--line)"><div class="row between"><b>${p.totalFiles} arquivo(s)</b><b>${fmtBytes(p.totalBytes)}</b></div>${p.truncated ? '<div class="hint">Contagem parcial (lista muito grande, parei em 8s).</div>' : ''}${p.errors ? `<div class="hint">${p.errors} pasta(s) sem acesso de leitura.</div>` : ''}</div>`;
      });

      $('#pz-go').onclick = async (e) => {
        if (!$('#pz-ok').checked) return toast('Confirme que entende que é irreversível.', 'bad');
        const word = $('#pz-word').value; const pin = $('#pz-pin').value;
        if (!word || !pin) return toast('Preencha a confirmação e o PIN.', 'bad');
        const n = st.targets.length;
        if (!(await confirmBox(`Isto vai apagar <b>${n} item(ns)</b> da lista, para sempre. Não vai para a lixeira.`, { title: 'Última confirmação', ok: 'Apagar definitivamente', danger: true }))) return;
        const r = await safe(() => post('/api/panic/execute', { confirm: word, pin }), e.currentTarget);
        if (!r) return;
        $('#pz-word').value = ''; $('#pz-pin').value = '';
        const msg = `Apagado: ${r.files} arquivo(s), ${fmtBytes(r.bytes)}.` + (r.errors.length ? ` ${r.errors.length} erro(s).` : '');
        toast(msg, r.errors.length ? 'bad' : 'ok');
        if (r.errors.length) await modal({ title: 'Erros ao apagar', body: `<pre class="code" style="white-space:pre-wrap">${esc(r.errors.join('\n'))}</pre>` });
        draw();
      };
    };
    await draw();
  },
});
