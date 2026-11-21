'use strict';
// Acesso remoto SEGURO: o Sentinel nunca escuta em IP público. Além de 127.0.0.1, só aceita
// ligar em endereços de rede privada/VPN (Tailscale 100.64/10, WireGuard, LAN 10/8, 172.16/12, 192.168/16).
// Sem port-forward no roteador: a ideia é acessar de fora pela VPN (Tailscale recomendado).
const os = require('os');
const store = require('./store');

function isPrivate(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !(n >= 0 && n <= 255))) return false;
  return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}
const isTailscale = (ip) => { const p = ip.split('.').map(Number); return p[0] === 100 && p[1] >= 64 && p[1] <= 127; };

function interfaces() {
  const out = [];
  for (const [name, list] of Object.entries(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.family !== 'IPv4' || a.internal || !isPrivate(a.address)) continue;
      out.push({ name, ip: a.address, kind: isTailscale(a.address) ? 'tailscale' : 'lan' });
    }
  }
  return out;
}

function config() { return store.get('remote', { enabled: false, bindIp: null }); }

function setConfig({ enabled, bindIp }) {
  if (enabled) {
    if (!interfaces().some((i) => i.ip === bindIp)) throw new Error('Endereço inválido: escolha uma interface privada/VPN detectada.');
  }
  store.set('remote', { enabled: !!enabled, bindIp: enabled ? bindIp : null });
  store.audit('remote.config', { enabled: !!enabled, bindIp });
  return config();
}

module.exports = { interfaces, config, setConfig, isPrivate };
