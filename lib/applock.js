'use strict';
// App Lock: bloqueia ABERTURA de apps escolhidos enquanto estiver travado.
// Limite honesto: só funciona enquanto o Sentinel estiver rodando (não é um serviço do Windows).
// Instâncias já abertas no momento do bloqueio não são encerradas (evita perda de dados);
// somente processos iniciados DEPOIS do bloqueio são finalizados.
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const auth = require('./auth');
const store = require('./store');

let locked = true; let lockedAt = Date.now(); let lastActivity = Date.now(); let timer = null;
const killedRecently = [];

function cfg() { return store.get('applock', { apps: [], idleMin: 15 }); }
function save(c) { store.set('applock', c); }

function state() {
  const c = cfg();
  return { locked, apps: c.apps, idleMin: c.idleMin, killed: killedRecently.slice(-20), platform: process.platform };
}

function normExe(p) {
  const s = String(p || '').trim();
  if (!s) throw new Error('Informe o executável.');
  if (process.platform !== 'win32') {
    const name = path.basename(s);
    if (!/^[\w.\-]{1,64}$/.test(name)) throw new Error('Informe um nome de processo válido (ex.: discord, steam).');
    return { name, path: /\//.test(s) ? s : null };
  }
  const name = path.win32.basename(s);
  if (!/^[\w .()\-]+\.exe$/i.test(name)) throw new Error('Informe um .exe válido.');
  return { name: name.toLowerCase(), path: /[\\/]/.test(s) ? s : null };
}

function addApp(p) {
  const e = normExe(p);
  const c = cfg();
  const blockedNames = process.platform === 'win32'
    ? /^(sentinel|node|explorer|winlogon|csrss|svchost|lsass|services|system|dwm|taskmgr)\.exe$/
    : /^(sentinel|node|systemd|init|Xorg|Xwayland)$/i;
  if (blockedNames.test(e.name)) throw new Error('Este processo não pode ser bloqueado (sistema/Sentinel).');
  if (c.apps.some((a) => a.name === e.name)) throw new Error('Já está na lista.');
  c.apps.push({ ...e, addedAt: Date.now() }); save(c); ensureTimer(); store.audit('applock.add', { app: e.name });
  return state();
}
function removeApp(name) { const c = cfg(); c.apps = c.apps.filter((a) => a.name !== name); save(c); store.audit('applock.remove', { app: name }); return state(); }
function setIdle(min) { if (![1, 5, 15, 30, 60].includes(+min)) throw new Error('Intervalo inválido.'); const c = cfg(); c.idleMin = +min; save(c); return state(); }

function lock() { locked = true; lockedAt = Date.now(); ensureTimer(); store.audit('applock.lock'); return state(); }
function unlock(pin) {
  if (!auth.verifyPin(pin)) throw Object.assign(new Error('PIN inválido.'), { status: 401 });
  locked = false; lastActivity = Date.now(); store.audit('applock.unlock'); return state();
}
function touch() { lastActivity = Date.now(); }

function psJson(script) {
  return new Promise((resolve) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { windowsHide: true, timeout: 8000 }, (err, out) => {
      if (err || !out.trim()) return resolve([]);
      try { const j = JSON.parse(out); resolve(Array.isArray(j) ? j : [j]); } catch { resolve([]); }
    });
  });
}

async function tickWin(names) {
  const list = names.map((n) => `'${n.replace(/'/g, "''")}'`).join(',');
  const procs = await psJson(`Get-Process -Name ${list} -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,@{n='Start';e={[DateTimeOffset]$_.StartTime | % ToUnixTimeMilliseconds}} | ConvertTo-Json -Compress`);
  for (const p of procs) {
    if (p.Start && p.Start > lockedAt) {
      execFile('taskkill', ['/PID', String(p.Id), '/T', '/F'], { windowsHide: true }, () => {});
      killedRecently.push({ t: Date.now(), name: p.ProcessName });
      store.audit('applock.blocked', { app: p.ProcessName });
    }
  }
}

// Linux: sem PowerShell/taskkill. Lê /proc diretamente - cada pasta /proc/<pid> tem o nome
// (comm) e um ctime que aproxima o instante em que o processo nasceu (truque comum, sem spawn).
function tickLinux(names) {
  const set = new Set(names);
  let pids = [];
  try { pids = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d)); } catch { return; }
  for (const pid of pids) {
    let comm;
    try { comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim(); } catch { continue; }
    if (!set.has(comm)) continue;
    let startMs;
    try { startMs = fs.statSync(`/proc/${pid}`).ctimeMs; } catch { continue; }
    if (startMs > lockedAt) {
      try { process.kill(+pid, 'SIGKILL'); } catch { /* já morreu */ }
      killedRecently.push({ t: Date.now(), name: comm });
      store.audit('applock.blocked', { app: comm });
    }
  }
}

async function tick() {
  const c = cfg();
  if (!locked && Date.now() - lastActivity > c.idleMin * 60000) { locked = true; lockedAt = Date.now(); store.audit('applock.autolock'); }
  if (!locked || !c.apps.length) return;
  if (process.platform === 'win32') {
    const names = c.apps.map((a) => a.name.replace(/\.exe$/i, '')).filter((n) => /^[\w .()\-]+$/.test(n));
    if (names.length) await tickWin(names);
    return;
  }
  if (process.platform === 'linux') {
    const names = c.apps.map((a) => a.name).filter((n) => /^[\w.\-]+$/.test(n));
    if (names.length) tickLinux(names);
  }
}

function ensureTimer() { if (!timer) { timer = setInterval(() => tick().catch(() => {}), 3000); timer.unref(); } }
function init() { if (cfg().apps.length) ensureTimer(); }

module.exports = { state, addApp, removeApp, setIdle, lock, unlock, touch, init };
