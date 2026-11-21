'use strict';
// Máquinas virtuais: VirtualBox (VBoxManage) e Hyper-V (PowerShell; exige administrador).
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const store = require('./store');

function findVBox() {
  if (process.platform === 'win32') {
    const cands = [process.env.VBOX_MSI_INSTALL_PATH && path.join(process.env.VBOX_MSI_INSTALL_PATH, 'VBoxManage.exe'),
      'C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe'].filter(Boolean);
    return cands.find((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } }) || null;
  }
  // Linux: normalmente no PATH; alguns pacotes instalam em /usr/lib/virtualbox
  for (const dir of [...(process.env.PATH || '').split(path.delimiter), '/usr/lib/virtualbox']) {
    if (!dir) continue;
    const p = path.join(dir, 'VBoxManage');
    try { fs.accessSync(p, fs.constants.X_OK); if (fs.statSync(p).isFile()) return p; } catch { /* next */ }
  }
  return null;
}
const VBOX = findVBox();

function run(file, args, timeout = 30000) {
  return new Promise((resolve, reject) => {
    execFile(file, args, { windowsHide: true, timeout, maxBuffer: 8 * 1024 * 1024, encoding: 'utf8' }, (err, out, errOut) => {
      if (err) return reject(new Error((errOut || err.message).toString().trim().slice(0, 600)));
      resolve(out);
    });
  });
}
const ps = (script, t) => run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], t);

const NAME = /^[A-Za-z0-9][A-Za-z0-9 ._\-]{0,63}$/;
function vmName(n) { if (!NAME.test(String(n || ''))) throw new Error('Nome de VM inválido (letras, números, espaço, . _ -).'); return String(n); }

async function hyperVAvailable() {
  if (process.platform !== 'win32') return false; // Hyper-V não existe fora do Windows
  try { const o = await ps('(Get-Command Get-VM -ErrorAction SilentlyContinue) -ne $null', 8000); return /True/i.test(o); } catch { return false; }
}

async function providers() {
  return { virtualbox: !!VBOX, hyperv: await hyperVAvailable(), vboxPath: VBOX || null };
}

async function list() {
  const out = [];
  if (VBOX) {
    try {
      const all = await run(VBOX, ['list', 'vms']);
      const running = await run(VBOX, ['list', 'runningvms']);
      const runningIds = new Set([...running.matchAll(/\{([0-9a-f-]+)\}/g)].map((m) => m[1]));
      for (const m of all.matchAll(/"(.+)" \{([0-9a-f-]+)\}/g)) out.push({ provider: 'virtualbox', name: m[1], id: m[2], state: runningIds.has(m[2]) ? 'running' : 'off' });
    } catch (e) { out.push({ provider: 'virtualbox', error: e.message }); }
  }
  if (await hyperVAvailable()) {
    try {
      const o = await ps('Get-VM | Select-Object Name,State,MemoryAssigned | ConvertTo-Json -Compress', 15000);
      if (o.trim()) for (const v of [].concat(JSON.parse(o))) out.push({ provider: 'hyperv', name: v.Name, id: v.Name, state: String(v.State).toLowerCase().includes('running') || v.State === 2 ? 'running' : 'off' });
    } catch (e) { out.push({ provider: 'hyperv', error: e.message }); }
  }
  return out;
}

async function action(provider, name, act) {
  name = vmName(name);
  store.audit('vm.action', { provider, name, act });
  if (provider === 'virtualbox') {
    if (!VBOX) throw new Error('VirtualBox não encontrado.');
    switch (act) {
      case 'start': return run(VBOX, ['startvm', name, '--type', 'headless']);
      case 'stop': return run(VBOX, ['controlvm', name, 'acpipowerbutton']);
      case 'poweroff': return run(VBOX, ['controlvm', name, 'poweroff']);
      case 'pause': return run(VBOX, ['controlvm', name, 'pause']);
      case 'resume': return run(VBOX, ['controlvm', name, 'resume']);
      case 'snapshot': return run(VBOX, ['snapshot', name, 'take', `sentinel-${new Date().toISOString().replace(/[:.]/g, '-')}`]);
      case 'delete': return run(VBOX, ['unregistervm', name, '--delete'], 120000);
      default: throw new Error('Ação inválida.');
    }
  }
  if (provider === 'hyperv') {
    const n = name.replace(/'/g, "''");
    const map = { start: `Start-VM -Name '${n}'`, stop: `Stop-VM -Name '${n}'`, poweroff: `Stop-VM -Name '${n}' -TurnOff -Force`, pause: `Suspend-VM -Name '${n}'`, resume: `Resume-VM -Name '${n}'`, snapshot: `Checkpoint-VM -Name '${n}'`, delete: `Remove-VM -Name '${n}' -Force` };
    if (!map[act]) throw new Error('Ação inválida.');
    return ps(map[act], 60000);
  }
  throw new Error('Provedor inválido.');
}

// Cria VM VirtualBox vazia (sem ISO) pronta para receber uma imagem.
async function create({ name, os = 'Linux_64', cpus = 2, memMB = 2048, diskGB = 20, iso }) {
  if (!VBOX) throw new Error('VirtualBox não encontrado.');
  name = vmName(name);
  cpus = Math.min(Math.max(+cpus | 0, 1), 6); memMB = Math.min(Math.max(+memMB | 0, 512), 8192); diskGB = Math.min(Math.max(+diskGB | 0, 4), 60);
  if (!/^[A-Za-z0-9_]+$/.test(os)) throw new Error('Tipo de SO inválido.');
  store.audit('vm.create', { name, cpus, memMB, diskGB });
  await run(VBOX, ['createvm', '--name', name, '--ostype', os, '--register']);
  await run(VBOX, ['modifyvm', name, '--cpus', String(cpus), '--memory', String(memMB), '--vram', '16', '--nic1', 'nat', '--graphicscontroller', 'vmsvga']);
  const folder = (await run(VBOX, ['showvminfo', name, '--machinereadable'])).match(/CfgFile="(.+)"/)?.[1];
  const dir = folder ? path.dirname(folder) : path.join(process.env.USERPROFILE || require('os').homedir() || '.', 'VirtualBox VMs', name);
  const vdi = path.join(dir, `${name}.vdi`);
  await run(VBOX, ['createmedium', 'disk', '--filename', vdi, '--size', String(diskGB * 1024), '--format', 'VDI'], 120000);
  await run(VBOX, ['storagectl', name, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci']);
  await run(VBOX, ['storageattach', name, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', vdi]);
  if (iso) {
    const isoPath = path.resolve(String(iso));
    if (!fs.existsSync(isoPath) || !/\.iso$/i.test(isoPath)) throw new Error('ISO não encontrada.');
    await run(VBOX, ['storagectl', name, '--name', 'IDE', '--add', 'ide']);
    await run(VBOX, ['storageattach', name, '--storagectl', 'IDE', '--port', '0', '--device', '0', '--type', 'dvddrive', '--medium', isoPath]);
  }
  return { name };
}

module.exports = { providers, list, action, create };
