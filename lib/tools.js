'use strict';
// Registro de ferramentas externas (nmap, nikto, metasploit, sqlmap...). Detecta instalação
// (PATH, pastas conhecidas, WSL) e executa SEM shell, com argumentos validados e escopo obrigatório.
const fs = require('fs');
const path = require('path');
const { spawn, execFile } = require('child_process');
const scope = require('./scope');
const jobs = require('./jobs');
const store = require('./store');

const PF = process.env['ProgramFiles'] || 'C:\\Program Files';
const PF86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
const HOME = process.env.USERPROFILE || '';

const LINUX = process.platform === 'linux';

const REGISTRY = {
  nmap: {
    label: 'Nmap', desc: 'Mapeamento de rede, portas, serviços e scripts NSE.',
    bins: ['nmap'], paths: [`${PF86}\\Nmap\\nmap.exe`, `${PF}\\Nmap\\nmap.exe`],
    install: {
      winget: ['install', '-e', '--id', 'Insecure.Nmap', '--accept-source-agreements', '--accept-package-agreements'],
      hint: LINUX ? 'sudo apt install nmap   (ou: sudo dnf install nmap / sudo pacman -S nmap)' : 'winget install -e --id Insecure.Nmap',
    },
  },
  nikto: {
    label: 'Nikto', desc: 'Scanner de servidor web (configurações inseguras, arquivos perigosos).',
    bins: ['nikto', 'nikto.pl'], paths: [`${HOME}\\nikto\\program\\nikto.pl`], wsl: 'nikto',
    install: { hint: LINUX ? 'sudo apt install nikto   |   ou: git clone https://github.com/sullo/nikto  (requer Perl)' : 'No WSL (Kali/Ubuntu): sudo apt install nikto   |   ou: git clone https://github.com/sullo/nikto  (requer Perl)' },
  },
  msfconsole: {
    label: 'Metasploit', desc: 'Framework de testes de intrusão (modulos auxiliares, exploits, payloads).',
    bins: ['msfconsole', 'msfconsole.bat'], paths: [`C:\\metasploit-framework\\bin\\msfconsole.bat`, `${PF}\\Metasploit\\bin\\msfconsole.bat`], wsl: 'msfconsole',
    install: {
      winget: ['install', '-e', '--id', 'Rapid7.Metasploit', '--accept-source-agreements', '--accept-package-agreements'],
      hint: LINUX ? 'curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod +x /tmp/msfinstall && sudo /tmp/msfinstall' : 'winget install -e --id Rapid7.Metasploit',
    },
  },
  sqlmap: {
    label: 'sqlmap', desc: 'Detecção e exploração de SQL injection (use só em alvos autorizados).',
    bins: ['sqlmap'], paths: [], wsl: 'sqlmap',
    install: { hint: 'pip install sqlmap   |   ou: git clone https://github.com/sqlmapproject/sqlmap' },
  },
  whatweb: {
    label: 'WhatWeb', desc: 'Fingerprinting de tecnologias web.',
    bins: ['whatweb'], paths: [], wsl: 'whatweb',
    install: { hint: LINUX ? 'sudo apt install whatweb' : 'No WSL: sudo apt install whatweb' },
  },
  gobuster: {
    label: 'Gobuster', desc: 'Força bruta de diretorios/DNS (alvos autorizados).',
    bins: ['gobuster'], paths: [], wsl: 'gobuster',
    install: {
      winget: ['install', '-e', '--id', 'OJ.Gobuster', '--accept-source-agreements', '--accept-package-agreements'],
      hint: LINUX ? 'sudo apt install gobuster   |   ou: go install github.com/OJ/gobuster/v3@latest' : 'winget install -e --id OJ.Gobuster',
    },
  },
};

// Procura um binário no PATH. No Windows testa cada extensão de PATHEXT; no Linux/macOS
// confere o bit de execução (sem extensão).
function whichAny(name) {
  const dirs = (process.env.PATH || '').split(path.delimiter);
  if (process.platform === 'win32') {
    const exts = (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';').concat(['']);
    for (const dir of dirs) {
      if (!dir) continue;
      for (const e of exts) {
        const p = path.join(dir, name + e.toLowerCase());
        try { if (fs.statSync(p).isFile()) return p; } catch { /* next */ }
        const p2 = path.join(dir, name + e);
        try { if (fs.statSync(p2).isFile()) return p2; } catch { /* next */ }
      }
    }
    return null;
  }
  for (const dir of dirs) {
    if (!dir) continue;
    const p = path.join(dir, name);
    try { fs.accessSync(p, fs.constants.X_OK); if (fs.statSync(p).isFile()) return p; } catch { /* next */ }
  }
  return null;
}

// WSL pode estar quebrado/lento (wsl.exe chega a travar por ~1 min). Por isso a detecção roda
// em SEGUNDO PLANO e a interface só lê o último resultado conhecido (nunca espera o WSL).
const wsl = { up: false, has: {}, checkedAt: 0, running: false };

function wslExec(args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile('wsl.exe', args, { timeout, windowsHide: true, encoding: 'utf16le' }, (err, out) => resolve(err ? null : String(out || '').replace(/\0/g, '').trim()));
  });
}

async function refreshWsl() {
  if (process.platform !== 'win32' || wsl.running) return;
  wsl.running = true;
  try {
    wsl.up = /ok/.test((await wslExec(['-e', 'sh', '-c', 'echo ok'])) || '');
    const has = {};
    if (wsl.up) {
      for (const t of Object.values(REGISTRY)) if (t.wsl) has[t.wsl] = !!(await wslExec(['-e', 'sh', '-c', `command -v ${t.wsl}`]));
    }
    wsl.has = has; wsl.checkedAt = Date.now();
  } finally { wsl.running = false; }
}

function detect(id) {
  const t = REGISTRY[id];
  for (const b of t.bins) { const p = whichAny(b); if (p) return { mode: 'native', path: p }; }
  for (const p of t.paths) { try { if (fs.statSync(p).isFile()) return { mode: 'native', path: p }; } catch { /* next */ } }
  if (t.wsl && wsl.up && wsl.has[t.wsl]) return { mode: 'wsl', path: t.wsl };
  return null;
}

async function status() {
  if (Date.now() - wsl.checkedAt > 5 * 60 * 1000) refreshWsl().catch(() => {}); // não espera
  const out = [];
  for (const id of Object.keys(REGISTRY)) {
    const t = REGISTRY[id];
    const found = detect(id);
    out.push({ id, label: t.label, desc: t.desc, installed: !!found, mode: found?.mode || null, path: found?.path || null, installHint: t.install.hint, canInstall: process.platform === 'win32' && !!t.install.winget });
  }
  return out;
}

// ---------- validacao de argumentos ----------
const SAFE_TOKEN = /^[A-Za-z0-9_.:/\-]+$/;
function safe(v, what) {
  const s = String(v ?? '');
  if (!s || !SAFE_TOKEN.test(s) || s.length > 200) throw new Error(`Valor inválido para ${what}.`);
  return s;
}

const NMAP_PRESETS = {
  quick: ['-T4', '-F'],
  service: ['-sV', '-T4'],
  default: ['-sC', '-sV', '-T4'],
  vuln: ['-sV', '--script', 'vuln', '-T4'],
  full: ['-p-', '-T4'],
  os: ['-O', '-sV', '-T4'],
};

function buildCommand(id, params) {
  switch (id) {
    case 'nmap': {
      const host = scope.assertAllowed(params.target);
      const preset = NMAP_PRESETS[params.preset] || NMAP_PRESETS.quick;
      const args = [...preset];
      if (params.ports) { if (!/^[0-9,\-]+$/.test(params.ports)) throw new Error('Portas invalidas.'); args.push('-p', params.ports); }
      args.push('-Pn', host);
      return args;
    }
    case 'nikto': {
      const host = scope.assertAllowed(params.target);
      const args = ['-h', host, '-nointeractive'];
      if (params.port) args.push('-p', String(parseInt(params.port, 10)));
      if (params.ssl) args.push('-ssl');
      return args;
    }
    case 'sqlmap': {
      const u = new URL(params.target); scope.assertAllowed(u.href);
      return ['-u', u.href, '--batch', `--level=${Math.min(+params.level || 1, 3)}`, `--risk=1`, '--random-agent'];
    }
    case 'whatweb': { const host = scope.assertAllowed(params.target); return ['-a', '1', host]; }
    case 'gobuster': {
      const u = new URL(params.target); scope.assertAllowed(u.href);
      const wl = safe(params.wordlist || 'common.txt', 'wordlist');
      return ['dir', '-u', u.href, '-w', wl, '-t', '10'];
    }
    case 'msfconsole': {
      const mod = String(params.module || '');
      if (!/^(auxiliary|exploit|post)\/[a-z0-9_\/]+$/i.test(mod)) throw new Error('Modulo inválido (ex.: auxiliary/scanner/portscan/tcp).');
      const host = scope.assertAllowed(params.target);
      const cmds = [`use ${mod}`, `set RHOSTS ${host}`];
      for (const [k, v] of Object.entries(params.options || {})) {
        if (!/^[A-Z][A-Z0-9_]{0,30}$/.test(k)) throw new Error('Opção inválida.');
        if (!/^[A-Za-z0-9_.:/\-]{1,100}$/.test(String(v))) throw new Error(`Valor inválido em ${k}.`);
        if (/^RHOSTS?$/.test(k)) continue; // RHOSTS sempre vem do alvo validado
        cmds.push(`set ${k} ${v}`);
      }
      cmds.push('run', 'exit');
      return ['-q', '-x', cmds.join('; ')];
    }
    default: throw new Error('Ferramenta desconhecida.');
  }
}

async function run(id, params) {
  if (!REGISTRY[id]) throw new Error('Ferramenta desconhecida.');
  const found = detect(id);
  if (!found) throw Object.assign(new Error(`${REGISTRY[id].label} não está instalado. ${REGISTRY[id].install.hint}`), { status: 409 });
  const args = buildCommand(id, params);
  const job = jobs.create('tool', `${REGISTRY[id].label}: ${params.target || params.module}`, { tool: id });
  store.audit('tool.run', { tool: id, target: params.target, mode: found.mode });
  jobs.emit(job, `$ ${id} ${args.join(' ')}`, 'sys');
  let file = found.path; let finalArgs = args;
  if (found.mode === 'wsl') { file = 'wsl.exe'; finalArgs = ['-e', found.path, ...args]; }
  else if (process.platform === 'win32' && /\.(bat|cmd)$/i.test(file)) { finalArgs = ['/c', file, ...args]; file = 'cmd.exe'; }
  else if (process.platform === 'win32' && /\.pl$/i.test(file)) { finalArgs = [file, ...args]; file = 'perl'; }
  jobs.runProcess(job, file, finalArgs, { timeoutMs: 30 * 60 * 1000 });
  return job;
}

function install(id) {
  const t = REGISTRY[id];
  if (!t?.install.winget) throw new Error('Instalação automática indisponível para esta ferramenta.');
  const job = jobs.create('install', `Instalar ${t.label}`, { tool: id });
  store.audit('tool.install', { tool: id });
  jobs.emit(job, `$ winget ${t.install.winget.join(' ')}`, 'sys');
  jobs.runProcess(job, 'winget', t.install.winget);
  return job;
}

module.exports = { status, run, install, refreshWsl, REGISTRY, NMAP_PRESETS };
