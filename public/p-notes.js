'use strict';
// Notas: campo de anotações, salvo no servidor (lê de qualquer dispositivo com acesso remoto).

App.register({
  id: 'notes', title: 'Notas', icon: 'file-text',
  async render(root) {
    let list = (await get('/api/notes')).notes; let cur = list[0]?.id || null; let dirty = false; let saveTimer = null;

    root.innerHTML = App.head('Utilitários', 'Notas', 'Anotações rápidas, salvas automaticamente.') + `
      <div class="grid" style="grid-template-columns:260px 1fr;align-items:start">
        <div class="card"><div class="card-head"><h2>Notas</h2><button class="btn sm primary" id="n-new">${icon('plus', 14)} Nova</button></div>
          <div class="list" id="n-list"></div></div>
        <div class="card" id="n-main"></div>
      </div>`;

    function renderList() {
      $('#n-list').innerHTML = list.map((n) => `<div class="row" data-n="${n.id}" style="cursor:pointer;${n.id === cur ? 'background:var(--bg-2)' : ''}"><div class="grow" style="min-width:0"><b style="font-weight:500;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(n.title || '(sem título)')}</b><div class="hint">${fmtTime(n.updatedAt)}</div></div></div>`).join('') || `<div class="empty">${icon('file-text', 24)}<div>Nenhuma nota ainda.</div></div>`;
      $$('[data-n]').forEach((el) => el.onclick = () => { save(true); cur = el.dataset.n; renderMain(); renderList(); });
    }

    function renderMain() {
      const n = list.find((x) => x.id === cur);
      const main = $('#n-main');
      if (!n) { main.innerHTML = `<div class="empty" style="padding:60px 0">${icon('file-text', 28)}<div>Selecione ou crie uma nota.</div></div>`; return; }
      main.innerHTML = `<div class="card-head"><input class="input" id="n-title" value="${esc(n.title)}" placeholder="Título" style="border:0;background:none;font-weight:600;font-size:16px;padding:0"><button class="btn sm danger" id="n-del">${icon('trash-2', 14)} Excluir</button></div>
        <textarea class="input" id="n-body" style="border:0;border-radius:0;min-height:460px;font-family:var(--mono);font-size:13px" placeholder="Escreva aqui...">${esc(n.body)}</textarea>
        <div class="hint" id="n-status" style="padding:8px 18px">salvo</div>`;
      $('#n-title').oninput = () => queueSave(); $('#n-body').oninput = () => queueSave();
      $('#n-del').onclick = async () => { if (await confirmBox('Excluir esta nota?', { danger: true, ok: 'Excluir' })) { await safe(() => del('/api/notes', { id: n.id })); list = (await get('/api/notes')).notes; cur = list[0]?.id || null; renderList(); renderMain(); } };
    }

    function queueSave() { dirty = true; const s = $('#n-status'); if (s) s.textContent = 'editando...'; clearTimeout(saveTimer); saveTimer = setTimeout(() => save(), 900); }
    async function save(immediate) {
      if (!dirty || !cur) return; if (immediate) clearTimeout(saveTimer);
      const title = $('#n-title')?.value ?? ''; const body = $('#n-body')?.value ?? '';
      dirty = false;
      await post('/api/notes', { id: cur, title, body }).catch(() => {});
      const i = list.findIndex((x) => x.id === cur); if (i >= 0) { list[i] = { ...list[i], title, body, updatedAt: Date.now() }; }
      const s = $('#n-status'); if (s) s.textContent = 'salvo ' + new Date().toLocaleTimeString('pt-BR');
      renderList();
    }
    App.leave(() => save(true));

    $('#n-new').onclick = async () => { save(true); const r = await post('/api/notes', { title: 'Nova nota', body: '' }); list = (await get('/api/notes')).notes; cur = r.id; renderList(); renderMain(); };
    window.onbeforeunload = () => { if (dirty) save(true); };

    renderList(); renderMain();
  },
});
