'use strict';
// Aprender: trilhas, leitor de aulas e quizzes. Progresso salvo no navegador (localStorage).

const Progress = {
  get() { try { return JSON.parse(localStorage.getItem('lessonsDone') || '{}'); } catch { return {}; } },
  mark(id) { const p = this.get(); p[id] = Date.now(); try { localStorage.setItem('lessonsDone', JSON.stringify(p)); } catch { /* sem storage */ } },
};

// inline: escapa e converte `codigo` e **negrito**
const inl = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');

App.register({
  id: 'learn', title: 'Aprender', icon: 'graduation-cap',
  async render(root, args) {
    const id = args[0]; const done = Progress.get();
    if (!id) {
      const track = localStorage.getItem('ltrack') || 'all';
      const list = LESSONS.filter((l) => track === 'all' || l.track === track);
      const total = LESSONS.length; const n = LESSONS.filter((l) => done[l.id]).length;
      root.innerHTML = App.head('Conhecimento', 'Aprender', 'Linux e cibersegurança do básico ao avançado. Cada aula tem comandos para copiar e um quiz; pratique no seu laboratório.', `<span class="badge ac mono">${n}/${total} concluídas</span>`) + `
        <div class="bar" style="margin:-8px 0 22px"><i style="width:${Math.round(n / total * 100)}%"></i></div>
        <div class="seg" style="margin-bottom:20px" id="tr"><button data-t="all" class="${track === 'all' ? 'on' : ''}">Todas</button><button data-t="linux" class="${track === 'linux' ? 'on' : ''}">Linux</button><button data-t="cyber" class="${track === 'cyber' ? 'on' : ''}">Cibersegurança</button></div>
        <div class="lessons">${list.map((l) => `<a class="lesson-card ${done[l.id] ? 'done' : ''}" href="#/learn/${l.id}" style="color:inherit;text-decoration:none"><div class="idx"><span>${l.track === 'linux' ? 'LINUX' : 'CYBER'} &middot; ${String(LESSONS.indexOf(l) + 1).padStart(2, '0')}</span></div><h3>${esc(l.title)}</h3><p>${esc(l.blurb)}</p><div class="row" style="margin-top:auto"><span class="badge">${esc(l.level)}</span><span class="hint mono">${l.min} min</span></div></a>`).join('')}</div>`;
      $$('#tr button').forEach((b) => b.onclick = () => { localStorage.setItem('ltrack', b.dataset.t); App.route(); });
      return;
    }
    const l = LESSONS.find((x) => x.id === id); if (!l) { location.hash = '#/learn'; return; }
    const idx = LESSONS.indexOf(l); const next = LESSONS[idx + 1];
    root.innerHTML = `<div style="margin-bottom:18px"><a href="#/learn" class="hint">&larr; Todas as aulas</a></div>` + App.head(l.track === 'linux' ? 'Linux' : 'Cibersegurança', l.title, l.blurb, `<span class="badge">${esc(l.level)}</span><span class="badge mono">${l.min} min</span>`) + `<div class="reader">${l.sections.map((s) => {
      if (s.lab) return `<div class="notice ok" style="margin:22px 0">${icon('flask-conical')}<div><b>Pratique:</b> ${inl(s.lab)}</div></div>`;
      return `${s.h ? `<h2>${esc(s.h)}</h2>` : ''}${(s.p || []).map((p) => `<p>${inl(p)}</p>`).join('')}${s.ul ? `<ul>${s.ul.map((u) => `<li>${inl(u)}</li>`).join('')}</ul>` : ''}${s.code ? `<div style="position:relative;margin-bottom:12px"><pre class="code"><code>${esc(s.code)}</code></pre><button class="btn sm icon ghost" data-cp style="position:absolute;top:6px;right:6px" aria-label="Copiar">${icon('copy', 14)}</button></div>` : ''}${s.note ? `<div class="notice warn" style="margin:14px 0">${icon('triangle-alert')}<div>${inl(s.note)}</div></div>` : ''}`;
    }).join('')}
      <h2>Quiz</h2><div id="quiz">${l.quiz.map((q, i) => `<div class="quiz-q" data-q="${i}"><div style="font-weight:500">${i + 1}. ${inl(q.q)}</div>${q.o.map((o, j) => `<div class="quiz-opt" data-j="${j}"><span class="mono dim">${'ABCD'[j]}</span><span>${inl(o)}</span></div>`).join('')}<div class="hint hide" style="margin-top:8px"></div></div>`).join('')}</div>
      <div class="row between" style="margin-top:28px;padding-top:20px;border-top:1px solid var(--line)"><span class="hint" id="qz-r"></span>${next ? `<a class="btn primary" href="#/learn/${next.id}">Próxima: ${esc(next.title)} ${icon('chevron-right', 14)}</a>` : `<a class="btn" href="#/learn">Concluir trilha</a>`}</div></div>`;
    $$('[data-cp]').forEach((b) => b.onclick = () => copyText(b.parentElement.querySelector('code').textContent));
    let answered = 0; let right = 0;
    $$('.quiz-q').forEach((qEl) => {
      const q = l.quiz[+qEl.dataset.q]; let locked = false;
      $$('.quiz-opt', qEl).forEach((opt) => opt.onclick = () => {
        if (locked) return; locked = true; answered++; const j = +opt.dataset.j; const ok = j === q.a; if (ok) right++;
        opt.classList.add(ok ? 'right' : 'wrong'); if (!ok) $$('.quiz-opt', qEl)[q.a].classList.add('right');
        const h = $('.hint', qEl); h.classList.remove('hide'); h.innerHTML = `${ok ? 'Correto.' : 'Não foi dessa vez.'} ${inl(q.why)}`;
        if (answered === l.quiz.length) { $('#qz-r').textContent = `${right}/${l.quiz.length} corretas`; if (right >= Math.ceil(l.quiz.length * 0.66)) { Progress.mark(l.id); toast('Aula concluída.', 'ok'); } else toast('Releia a aula e tente de novo.'); }
      });
    });
  },
});
