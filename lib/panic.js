'use strict';
// "Apagar de emergência": apaga uma lista de alvos (pastas/arquivos) que o DONO escolhe, com o PIN.
// Explícito, com prévia e log. NUNCA apaga o sistema, não desinstala programas, não mexe no log de
// eventos do Windows. Pensado para proteger dados sensíveis (ex.: se roubarem o PC).
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execFileSync, spawn } = require('child_process');
const auth = require('./auth');
const store = require('./store');
const vault = require('./vault');

const HOME = os.homedir();
const APP_DIR = path.resolve(__dirname, '..'); // raiz do projeto Sentinel (contem server.js, lib/, public/)
const WALK_FILE_CAP = 200000;   // limite de arquivos ao calcular/apagar (evita travar)

// ---------- caminhos proibidos (nunca apagáveis) ----------
function dangerousWin(r, low) {
  if (/^[a-z]:[\\/]?$/i.test(r.toLowerCase())) return 'Não é permitido apagar a raiz de um disco.';
  const win = (process.env.SystemRoot || 'C:\\Windows').toLowerCase();
  const pf = (process.env['ProgramFiles'] || 'C:\\Program Files').toLowerCase();
  const pf86 = (process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)').toLowerCase();
  const pd = (process.env.ProgramData || 'C:\\ProgramData').toLowerCase();
  const blocked = [win, pf, pf86, path.join(pd, 'microsoft'), 'c:\\users', 'c:\\', HOME.toLowerCase()];
  for (const b of blocked) {
    const bl = b.replace(/[\\/]+$/, '');
    if (low === bl) return `"${r}" é uma pasta protegida do sistema/perfil e não pode ser apagada inteira. Escolha uma subpasta específica.`;
    if (bl === win || bl === pf || bl === pf86) { if (low === bl || low.startsWith(bl + '\\')) return `"${r}" está dentro de uma pasta do sistema (${b}). Bloqueado.`; }
  }
  return null;
}

function dangerousLinux(r, low) {
  if (low === '') return 'Não é permitido apagar a raiz do sistema (/).';
  const blocked = ['/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/dev', '/proc', '/sys', '/var', '/opt', '/root', HOME.toLowerCase()];
  for (const b of blocked) {
    const bl = b.replace(/\/+$/, '');
    if (low === bl) return `"${r}" é uma pasta protegida do sistema/perfil e não pode ser apagada inteira. Escolha uma subpasta específica.`;
    if (['/etc', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/boot', '/var'].includes(bl) && low.startsWith(bl + '/')) return `"${r}" está dentro de uma pasta do sistema (${b}). Bloqueado.`;
  }
  return null;
}

function dangerous(p) {
  let r;
  try { r = path.resolve(String(p || '')); } catch { return 'Caminho inválido.'; }
  if (!r || String(p).includes('\0')) return 'Caminho inválido.';
  const low = r.toLowerCase().replace(/[\\/]+$/, '');
  const d = process.platform === 'win32' ? dangerousWin(r, low) : dangerousLinux(r, low);
  if (d) return d;
  // impede apagar a propria pasta de dados do Sentinel enquanto ele roda (perderia o PIN no meio)
  if (low === path.resolve(store.DATA_DIR).toLowerCase()) return 'A pasta de dados do Sentinel é protegida aqui.';
  return null;
}

function cfg() { return store.get('panic', { targets: [], overwrite: false }); }
function save(c) { store.set('panic', c); return c; }

function state() {
  const c = cfg();
  const targets = c.targets.map((t) => {
    let exists = false, kind = null;
    try { const st = fs.statSync(t.path); exists = true; kind = st.isDirectory() ? 'dir' : 'file'; } catch { /* sumiu */ }
    return { ...t, exists, kind };
  });
  return { targets, overwrite: !!c.overwrite };
}

function addTarget(p, note) {
  const d = dangerous(p);
  if (d) throw new Error(d);
  const resolved = path.resolve(p);
  if (!fs.existsSync(resolved)) throw new Error('Esse caminho não existe.');
  const c = cfg();
  if (c.targets.some((t) => t.path.toLowerCase() === resolved.toLowerCase())) throw new Error('Esse alvo já está na lista.');
  c.targets.push({ path: resolved, note: String(note || '').slice(0, 120), addedAt: Date.now() });
  save(c);
  store.audit('panic.target.add', { path: resolved });
  return state();
}

function removeTarget(p) {
  const c = cfg();
  c.targets = c.targets.filter((t) => t.path.toLowerCase() !== path.resolve(p).toLowerCase());
  save(c);
  store.audit('panic.target.remove', { path: p });
  return state();
}

function setOverwrite(on) { const c = cfg(); c.overwrite = !!on; save(c); return state(); }

// ---------- prévia: conta arquivos e bytes de cada alvo ----------
function walk(target, onFile, budget) {
  const stack = [target];
  while (stack.length) {
    if (budget.files >= WALK_FILE_CAP || Date.now() > budget.until) { budget.truncated = true; return; }
    const cur = stack.pop();
    let st; try { st = fs.lstatSync(cur); } catch { continue; }
    if (st.isSymbolicLink()) { onFile(cur, 0, true); continue; } // não segue links
    if (st.isDirectory()) {
      let entries = []; try { entries = fs.readdirSync(cur); } catch { budget.errors++; continue; }
      for (const e of entries) stack.push(path.join(cur, e));
      budget.dirs++;
    } else {
      budget.files++; onFile(cur, st.size, false);
    }
  }
}

function preview() {
  const c = cfg();
  const until = Date.now() + 8000;
  const budget = { files: 0, dirs: 0, errors: 0, truncated: false, until };
  let bytes = 0;
  const per = [];
  for (const t of c.targets) {
    let exists = true; try { fs.statSync(t.path); } catch { exists = false; }
    if (!exists) { per.push({ path: t.path, exists: false, files: 0, bytes: 0 }); continue; }
    const before = budget.files; let tb = 0;
    const st = fs.statSync(t.path);
    if (st.isDirectory()) walk(t.path, (_f, size) => { bytes += size; tb += size; }, budget);
    else { budget.files++; bytes += st.size; tb += st.size; }
    per.push({ path: t.path, exists: true, files: budget.files - before, bytes: tb });
  }
  return { totalFiles: budget.files, totalBytes: bytes, dirs: budget.dirs, errors: budget.errors, truncated: budget.truncated, per, overwrite: !!c.overwrite };
}

// ---------- apagar ----------
function overwriteFile(file, size) {
  if (size <= 0 || size > 512 * 1024 * 1024) return; // não sobrescreve arquivos enormes (lento)
  try {
    const fd = fs.openSync(file, 'r+');
    const chunk = crypto.randomBytes(Math.min(size, 1 << 20));
    let off = 0;
    while (off < size) { const n = Math.min(chunk.length, size - off); fs.writeSync(fd, chunk, 0, n, off); off += n; }
    fs.fsyncSync(fd); fs.closeSync(fd);
  } catch { /* segue para o unlink de qualquer forma */ }
}

function wipeTarget(target, overwrite, report) {
  let st; try { st = fs.lstatSync(target); } catch { return; }
  if (st.isSymbolicLink() || st.isFile()) {
    try { if (overwrite && st.isFile()) overwriteFile(target, st.size); fs.rmSync(target, { force: true }); report.files++; report.bytes += st.size || 0; }
    catch (e) { report.errors.push(`${target}: ${e.code || e.message}`); }
    return;
  }
  // diretório: apaga arquivos (de baixo pra cima), depois a árvore
  if (overwrite) {
    const budget = { files: 0, dirs: 0, errors: 0, truncated: false, until: Date.now() + 10 * 60 * 1000 };
    walk(target, (f, size, isLink) => { if (!isLink) overwriteFile(f, size); }, budget);
  }
  try {
    // conta antes de remover
    const budget = { files: 0, dirs: 0, errors: 0, truncated: false, until: Date.now() + 60 * 1000 };
    let bytes = 0; walk(target, (_f, size) => { bytes += size; }, budget);
    fs.rmSync(target, { recursive: true, force: true });
    report.files += budget.files; report.bytes += bytes; report.dirs += budget.dirs + 1;
  } catch (e) { report.errors.push(`${target}: ${e.code || e.message}`); }
}

// exige PIN sempre. 'confirm' deve ser a palavra APAGAR (dupla confirmação na UI).
function execute({ pin, confirm }) {
  if (String(confirm || '').trim().toUpperCase() !== 'APAGAR') throw new Error('Confirmação inválida. Digite APAGAR para confirmar.');
  if (!auth.verifyPin(pin)) throw Object.assign(new Error('PIN inválido.'), { status: 401 });
  const c = cfg();
  if (!c.targets.length) throw new Error('Nenhum alvo na lista.');
  store.audit('panic.execute.start', { targets: c.targets.length, overwrite: !!c.overwrite });
  const report = { files: 0, dirs: 0, bytes: 0, errors: [], startedAt: Date.now() };
  for (const t of c.targets) {
    const d = dangerous(t.path); // revalida na hora (caminho pode ter mudado de significado)
    if (d) { report.errors.push(`${t.path}: ${d}`); continue; }
    wipeTarget(t.path, !!c.overwrite, report);
  }
  // alvos que sumiram saem da lista; o resto fica (pode ter sido recriado)
  const survivors = c.targets.filter((t) => fs.existsSync(t.path));
  save({ ...c, targets: survivors });
  report.endedAt = Date.now();
  store.audit('panic.execute.done', { files: report.files, bytes: report.bytes, errors: report.errors.length });
  return report;
}

// ---------- sugestões: pastas comuns de cache/log/histórico de apps instalados ----------
// Só propõe o que EXISTE de fato neste PC. O dono escolhe quais adicionar; nada é automático.
const LOCALAPPDATA = process.env.LOCALAPPDATA || path.join(HOME, 'AppData', 'Local');
const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');

function candidatesWin() {
  return [
    { group: 'Navegadores', label: 'Histórico e cache do Chrome', path: path.join(LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default', 'History') },
    { group: 'Navegadores', label: 'Cache do Chrome', path: path.join(LOCALAPPDATA, 'Google', 'Chrome', 'User Data', 'Default', 'Cache') },
    { group: 'Navegadores', label: 'Histórico e cache do Edge', path: path.join(LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data', 'Default', 'History') },
    { group: 'Navegadores', label: 'Cache do Edge', path: path.join(LOCALAPPDATA, 'Microsoft', 'Edge', 'User Data', 'Default', 'Cache') },
    { group: 'Navegadores', label: 'Histórico e cache do Firefox', path: path.join(APPDATA, 'Mozilla', 'Firefox', 'Profiles') },
    { group: 'Windows', label: 'Itens recentes (Recent)', path: path.join(APPDATA, 'Microsoft', 'Windows', 'Recent') },
    { group: 'Windows', label: 'Lixeira (todas as unidades, se acessível)', path: 'C:\\$Recycle.Bin' },
    { group: 'Windows', label: 'Arquivos temporários do usuário (%TEMP%)', path: process.env.TEMP || path.join(LOCALAPPDATA, 'Temp') },
    { group: 'Windows', label: 'Miniaturas (thumbnail cache)', path: path.join(LOCALAPPDATA, 'Microsoft', 'Windows', 'Explorer') },
    { group: 'Office/Produtividade', label: 'Documentos recentes do Office', path: path.join(APPDATA, 'Microsoft', 'Office', 'Recent') },
    { group: 'Conversas', label: 'Cache do Discord', path: path.join(APPDATA, 'discord', 'Cache') },
    { group: 'Conversas', label: 'Logs/cache do Discord (todo o perfil local)', path: path.join(APPDATA, 'discord') },
    { group: 'Conversas', label: 'Cache do Telegram Desktop', path: path.join(APPDATA, 'Telegram Desktop', 'tdata') },
    { group: 'Dev', label: 'Logs do VS Code', path: path.join(APPDATA, 'Code', 'logs') },
    { group: 'Dev', label: 'Histórico de comandos do PowerShell', path: path.join(APPDATA, 'Microsoft', 'Windows', 'PowerShell', 'PSReadLine') },
  ];
}

function candidatesLinux() {
  const cfgHome = process.env.XDG_CONFIG_HOME || path.join(HOME, '.config');
  const cacheHome = process.env.XDG_CACHE_HOME || path.join(HOME, '.cache');
  const dataHome = process.env.XDG_DATA_HOME || path.join(HOME, '.local', 'share');
  return [
    { group: 'Navegadores', label: 'Cache do Chrome/Chromium', path: path.join(cacheHome, 'google-chrome') },
    { group: 'Navegadores', label: 'Histórico e cookies do Chrome/Chromium', path: path.join(cfgHome, 'google-chrome', 'Default') },
    { group: 'Navegadores', label: 'Cache do Firefox', path: path.join(cacheHome, 'mozilla', 'firefox') },
    { group: 'Navegadores', label: 'Perfil do Firefox (histórico, cookies)', path: path.join(HOME, '.mozilla', 'firefox') },
    { group: 'Sistema', label: 'Lixeira (Trash)', path: path.join(dataHome, 'Trash') },
    { group: 'Sistema', label: 'Cache do usuário (~/.cache)', path: cacheHome },
    { group: 'Sistema', label: 'Arquivos recentes (recently-used)', path: path.join(dataHome, 'recently-used.xbel') },
    { group: 'Shell', label: 'Histórico do bash', path: path.join(HOME, '.bash_history') },
    { group: 'Shell', label: 'Histórico do zsh', path: path.join(HOME, '.zsh_history') },
    { group: 'Conversas', label: 'Cache do Discord', path: path.join(cfgHome, 'discord', 'Cache') },
    { group: 'Conversas', label: 'Logs/cache do Discord (todo o perfil local)', path: path.join(cfgHome, 'discord') },
    { group: 'Conversas', label: 'Cache do Telegram Desktop', path: path.join(dataHome, 'TelegramDesktop', 'tdata') },
    { group: 'Dev', label: 'Logs do VS Code', path: path.join(cfgHome, 'Code', 'logs') },
    { group: 'Dev', label: 'Histórico do Bash via readline (~/.local/share/bash)', path: path.join(dataHome, 'bash') },
  ];
}

function candidates() { return process.platform === 'win32' ? candidatesWin() : candidatesLinux(); }
function presets() {
  return candidates().map((c) => {
    let exists = false, kind = null;
    try { const st = fs.statSync(c.path); exists = true; kind = st.isDirectory() ? 'dir' : 'file'; } catch { /* nao existe neste PC */ }
    return { ...c, exists, kind, blocked: !!dangerous(c.path) };
  }).filter((c) => c.exists && !c.blocked);
}

// ---------- backup explícito do Sentinel (você escolhe a pasta de destino) ----------
// Alternativa HONESTA a "mandar copia pra nuvem escondido": voce escolhe uma pasta (pode ser uma
// pasta sincronizada com OneDrive/Google Drive/Dropbox no seu PC) e o app grava ali um arquivo
// .sntl cifrado (AES-256-GCM) com sua senha. Nada e enviado pela rede por este recurso.
async function backupApp(destDir, password) {
  if (!password || String(password).length < 8) throw new Error('Use uma senha de backup com pelo menos 8 caracteres.');
  const dest = path.resolve(String(destDir || ''));
  let st; try { st = fs.statSync(dest); } catch { throw new Error('Pasta de destino não existe.'); }
  if (!st.isDirectory()) throw new Error('Escolha uma pasta, não um arquivo.');
  const dataAbs = path.resolve(store.DATA_DIR);
  if (dest.toLowerCase() === dataAbs.toLowerCase() || dest.toLowerCase().startsWith(dataAbs.toLowerCase() + path.sep)) throw new Error('Escolha uma pasta fora da pasta de dados do Sentinel.');
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const staging = path.join(dest, `sentinel-backup-${stamp}`);
  fs.cpSync(dataAbs, staging, { recursive: true });
  const r = await vault.encryptFile(staging, password, { removeOriginal: true });
  store.audit('panic.backup', { dest: r.output });
  return { file: r.output, size: r.size };
}

// ---------- desinstalar o Sentinel (apaga o APP INTEIRO, de si mesmo) ----------
// Explícito, visível, com PIN + palavra de confirmação. NÃO se disfarça de outro programa,
// NÃO tem gatilho oculto, NÃO exfiltra nada sem o backup explicito acima ter sido feito antes
// por voce mesmo. Isso e um "desinstalar", nao uma backdoor.
function selfDestructWin(logFile) {
  // helper destacado: espera o node encerrar (libera os arquivos) e so entao apaga tudo.
  // IMPORTANTE: um processo filho "detached" comum ainda morre junto com o pai se este estiver
  // dentro de um Job Object do Windows (comum em terminais, editores e ferramentas de automacao).
  // Por isso disparamos via Agendador de Tarefas do Windows (schtasks /run), que roda o processo
  // pelo servico do Task Scheduler - de verdade fora do job object do processo atual.
  const scriptFile = path.join(os.tmpdir(), `sentinel-uninstall-${crypto.randomBytes(4).toString('hex')}.ps1`);
  const taskName = `SentinelUninstall_${crypto.randomBytes(4).toString('hex')}`;
  const q = (s) => s.replace(/'/g, "''");
  const ps = [
    `$log = '${q(logFile)}'`,
    `function W($m) { Add-Content -LiteralPath $log -Value "$(Get-Date -Format o)  $m" }`,
    `W 'inicio: aguardando o Sentinel encerrar...'`,
    `Start-Sleep -Seconds 2`,
    `for ($i = 1; $i -le 10; $i++) {`,
    `  try {`,
    `    Remove-Item -LiteralPath '${q(APP_DIR)}' -Recurse -Force -ErrorAction Stop`,
    `    W 'apagado com sucesso'`,
    `    break`,
    `  }`,
    `  catch {`,
    `    W "tentativa $i falhou: $($_.Exception.Message)"`,
    `    Start-Sleep -Seconds 2`,
    `  }`,
    `}`,
    `if (Test-Path -LiteralPath '${q(APP_DIR)}') { W 'DESISTIU apos 10 tentativas. Feche o Sentinel.exe e qualquer janela/terminal nesta pasta, depois apague manualmente.' }`,
    `schtasks /delete /tn '${q(taskName)}' /f *> $null`,
    `$selfArgs = "/c timeout /t 2 >nul & del /f /q \`"$PSCommandPath\`""`,
    `Start-Process -FilePath cmd.exe -ArgumentList $selfArgs -WindowStyle Hidden`,
  ].join('\r\n');
  fs.writeFileSync(scriptFile, ps, 'utf8');
  const psCmd = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "${scriptFile}"`;
  try {
    execFileSync('schtasks', ['/create', '/tn', taskName, '/tr', psCmd, '/sc', 'once', '/st', '23:59', '/f'], { windowsHide: true, timeout: 8000 });
    execFileSync('schtasks', ['/run', '/tn', taskName], { windowsHide: true, timeout: 8000 });
  } catch (e) {
    throw new Error(`Não consegui agendar a remoção (${e.message}). Nada foi apagado ainda.`);
  }
}

function selfDestructLinux(logFile) {
  // Linux não tem o problema do Job Object do Windows: um processo filho com setsid() próprio
  // (nova sessão, desligado do terminal/grupo que o criou) sobrevive normalmente ao pai terminar.
  // Ainda assim usamos setsid + nohup + disown, igual a prática padrão para daemonizar no shell.
  const scriptFile = path.join(os.tmpdir(), `sentinel-uninstall-${crypto.randomBytes(4).toString('hex')}.sh`);
  const q = (s) => s.replace(/'/g, "'\\''");
  const sh = [
    '#!/bin/sh',
    `log='${q(logFile)}'`,
    `w() { printf '%s  %s\\n' "$(date -Iseconds)" "$1" >> "$log"; }`,
    `w 'inicio: aguardando o Sentinel encerrar...'`,
    'sleep 2',
    'i=1',
    `while [ "$i" -le 10 ]; do`,
    `  if rm -rf -- '${q(APP_DIR)}' 2>>"$log"; then w 'apagado com sucesso'; break; fi`,
    `  w "tentativa $i falhou"`,
    '  sleep 2',
    '  i=$((i + 1))',
    'done',
    `if [ -e '${q(APP_DIR)}' ]; then w 'DESISTIU apos 10 tentativas. Feche quaisquer janelas/terminais nesta pasta, depois apague manualmente.'; fi`,
    `rm -f -- "$0"`,
  ].join('\n');
  fs.writeFileSync(scriptFile, sh, 'utf8');
  fs.chmodSync(scriptFile, 0o700);
  try {
    const child = spawn('setsid', ['sh', scriptFile], { detached: true, stdio: 'ignore' });
    child.unref();
  } catch (e) {
    // setsid pode não existir em sistemas mínimos; cai para spawn detached simples
    try { spawn('sh', [scriptFile], { detached: true, stdio: 'ignore' }).unref(); }
    catch (e2) { throw new Error(`Não consegui iniciar a remoção (${e2.message}). Nada foi apagado ainda.`); }
  }
}

function selfDestruct({ pin, confirm }) {
  if (String(confirm || '').trim().toUpperCase() !== 'DESINSTALAR') throw new Error('Confirmação inválida. Digite DESINSTALAR para apagar o Sentinel inteiro.');
  if (!auth.verifyPin(pin)) throw Object.assign(new Error('PIN inválido.'), { status: 401 });
  if (!fs.existsSync(path.join(APP_DIR, 'server.js')) || !fs.existsSync(path.join(APP_DIR, 'lib'))) {
    throw new Error('Não reconheci a pasta do app (proteção contra apagar o lugar errado). Cancelado.');
  }
  store.audit('panic.selfdestruct', { dir: APP_DIR });
  const logFile = path.join(os.tmpdir(), 'sentinel-uninstall.log');
  if (process.platform === 'win32') selfDestructWin(logFile);
  else selfDestructLinux(logFile);
  setTimeout(() => process.exit(0), 600).unref();
  return { ok: true, dir: APP_DIR, log: logFile };
}

module.exports = { state, addTarget, removeTarget, setOverwrite, preview, execute, presets, dangerous, backupApp, selfDestruct, APP_DIR, _test: { dangerousWin, dangerousLinux } };
