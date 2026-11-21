'use strict';
// Escopo de alvos autorizados. Ferramentas ofensivas (scans, nmap, nikto, metasploit,
// descoberta ativa) SO rodam contra alvos desta lista.
const net = require('net');
const store = require('./store');

const DEFAULTS = [
  { value: '127.0.0.1', note: 'Esta máquina', builtin: true },
  { value: 'localhost', note: 'Esta máquina', builtin: true },
  { value: '::1', note: 'Esta máquina', builtin: true },
];

function list() {
  const user = store.get('scope', []);
  return [...DEFAULTS, ...user];
}

function hostOf(target) {
  let t = String(target || '').trim();
  if (!t) return '';
  try { if (/^[a-z]+:\/\//i.test(t)) t = new URL(t).hostname; } catch { return ''; }
  t = t.replace(/^\[|\]$/g, '').replace(/:\d+$/, (m) => (net.isIPv6(t) ? m : ''));
  return t.toLowerCase();
}

function ipv4ToInt(ip) { return ip.split('.').reduce((a, o) => (a << 8) + (+o), 0) >>> 0; }

function matches(entry, host) {
  const e = entry.value.toLowerCase();
  if (e === host) return true;
  if (e.startsWith('*.') && host.endsWith(e.slice(1))) return true;
  if (e.includes('/') && net.isIPv4(host)) {
    const [base, bitsStr] = e.split('/');
    const bits = +bitsStr;
    if (!net.isIPv4(base) || !(bits >= 0 && bits <= 32)) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ipv4ToInt(host) & mask) === (ipv4ToInt(base) & mask);
  }
  return false;
}

function check(target) {
  const host = hostOf(target);
  if (!host) return { ok: false, host, reason: 'Alvo inválido.' };
  if (/^127\./.test(host)) return { ok: true, host };
  const hit = list().find((e) => matches(e, host));
  if (hit) return { ok: true, host };
  return { ok: false, host, reason: `"${host}" não está na lista de alvos autorizados. Adicione em Escopo, confirmando que você tem permissão para testá-lo.` };
}

function assertAllowed(target) {
  const r = check(target);
  if (!r.ok) throw Object.assign(new Error(r.reason), { status: 403, code: 'OUT_OF_SCOPE' });
  return r.host;
}

const VALID = /^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$|^[0-9a-f:]+$|^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/i;

function add(value, note, attested) {
  if (attested !== true) throw new Error('Confirme que você tem autorização para testar este alvo.');
  const v = hostOf(value) || String(value).trim().toLowerCase();
  if (!v || !VALID.test(v) || v.length > 253) throw new Error('Alvo inválido. Use domínio, IP, *.dominio ou CIDR IPv4.');
  if (v === '*' || v === '0.0.0.0/0' || /^\*\.[a-z]{2,}$/.test(v)) throw new Error('Alvo amplo demais.');
  if (list().some((e) => e.value === v)) throw new Error('Já está na lista.');
  store.update('scope', (l) => [...l, { value: v, note: String(note || '').slice(0, 120), addedAt: Date.now() }], []);
  store.audit('scope.add', { value: v });
  return list();
}

function remove(value) {
  store.update('scope', (l) => l.filter((e) => e.value !== value), []);
  store.audit('scope.remove', { value });
  return list();
}

module.exports = { list, check, assertAllowed, add, remove, hostOf };
