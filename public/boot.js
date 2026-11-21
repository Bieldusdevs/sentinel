'use strict';
// Inicialização: decide entre configuração, login ou app. Mantém o bloqueio de apps ciente da atividade.
(() => {
  let last = 0;
  const ping = () => { const n = Date.now(); if (n - last > 60000 && $('#app')) { last = n; fetch('/api/applock/touch', { method: 'POST', headers: { 'X-Sentinel': '1', 'Content-Type': 'application/json' }, body: '{}' }).catch(() => {}); } };
  ['click', 'keydown', 'mousemove', 'touchstart'].forEach((e) => document.addEventListener(e, ping, { passive: true }));
  App.showAuth();
})();
