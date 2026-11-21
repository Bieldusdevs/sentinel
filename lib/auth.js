'use strict';
// Autenticação: PIN/senha (scrypt), 2FA TOTP opcional, sessoes, rate limit e recuperação.
const crypto = require('crypto');
const store = require('./store');

const SESSION_IDLE_MS = 12 * 60 * 60 * 1000;
const sessions = new Map(); // token -> { created, last, ip }
const attempts = new Map(); // ip -> { n, until }

function scryptHash(secret, salt) {
  return crypto.scryptSync(String(secret), salt, 64, { N: 16384, r: 8, p: 1 });
}

function makeHash(secret) {
  const salt = crypto.randomBytes(16);
  return { salt: salt.toString('hex'), hash: scryptHash(secret, salt).toString('hex') };
}

function checkHash(secret, rec) {
  if (!rec) return false;
  const h = scryptHash(secret, Buffer.from(rec.salt, 'hex'));
  const want = Buffer.from(rec.hash, 'hex');
  return h.length === want.length && crypto.timingSafeEqual(h, want);
}

// --- TOTP (RFC 6238, SHA1, 6 dígitos, 30s) ---
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32encode(buf) {
  let bits = '', out = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)];
  return out;
}
function b32decode(str) {
  let bits = '';
  for (const c of str.replace(/=+$/, '').toUpperCase()) {
    const i = B32.indexOf(c);
    if (i < 0) continue;
    bits += i.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function totpAt(secretB32, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', b32decode(secretB32)).update(buf).digest();
  const o = h[h.length - 1] & 0xf;
  const code = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(code % 1e6).padStart(6, '0');
}
function totpVerify(secretB32, token) {
  const c = Math.floor(Date.now() / 30000);
  const t = String(token || '').trim();
  for (const d of [-1, 0, 1]) {
    const exp = totpAt(secretB32, c + d);
    if (exp.length === t.length && crypto.timingSafeEqual(Buffer.from(exp), Buffer.from(t))) return true;
  }
  return false;
}

// --- Estado ---
function isSetup() { return !!store.get('auth'); }

function validateSecret(pin) {
  const s = String(pin || '');
  if (s.length < 6) throw new Error('Use pelo menos 6 caracteres.');
  if (s.length > 128) throw new Error('Máximo de 128 caracteres.');
  return s;
}

function genRecovery() {
  const groups = [];
  for (let i = 0; i < 6; i++) groups.push(String(crypto.randomInt(0, 10000)).padStart(4, '0'));
  return groups.join('-');
}

function setup(pin) {
  if (isSetup()) throw new Error('Já configurado.');
  validateSecret(pin);
  const recovery = genRecovery();
  store.set('auth', { pin: makeHash(pin), recovery: makeHash(recovery), totp: null, createdAt: Date.now() });
  store.audit('auth.setup');
  return { recovery };
}

function limited(ip) {
  const a = attempts.get(ip);
  if (a && a.until > Date.now()) return Math.ceil((a.until - Date.now()) / 1000);
  return 0;
}
function fail(ip) {
  const a = attempts.get(ip) || { n: 0, until: 0 };
  a.n += 1;
  if (a.n >= 5) a.until = Date.now() + Math.min(15 * 60 * 1000, 30000 * 2 ** (a.n - 5));
  attempts.set(ip, a);
}

function newSession(ip) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { created: Date.now(), last: Date.now(), ip });
  return token;
}

function login({ pin, totp }, ip) {
  const wait = limited(ip);
  if (wait) throw Object.assign(new Error(`Muitas tentativas. Tente de novo em ${wait}s.`), { status: 429 });
  const auth = store.get('auth');
  if (!auth) throw new Error('Configure o PIN primeiro.');
  const okPin = checkHash(pin, auth.pin);
  const okTotp = !auth.totp?.enabled || totpVerify(auth.totp.secret, totp);
  if (!okPin || !okTotp) {
    fail(ip);
    store.audit('auth.fail', { ip });
    throw Object.assign(new Error(auth.totp?.enabled && okPin ? 'Código 2FA inválido.' : 'PIN inválido.'), { status: 401 });
  }
  attempts.delete(ip);
  store.audit('auth.login', { ip });
  return newSession(ip);
}

function needs2fa() { return !!store.get('auth')?.totp?.enabled; }

function verifyPin(pin) { return checkHash(pin, store.get('auth')?.pin); }

function recover({ recovery, newPin }, ip) {
  const wait = limited(ip);
  if (wait) throw Object.assign(new Error(`Muitas tentativas. Tente de novo em ${wait}s.`), { status: 429 });
  const auth = store.get('auth');
  if (!auth || !checkHash(String(recovery || '').replace(/\s/g, ''), auth.recovery) &&
      !checkHash(String(recovery || ''), auth.recovery)) {
    fail(ip);
    throw Object.assign(new Error('Número de recuperação inválido.'), { status: 401 });
  }
  validateSecret(newPin);
  const newRecovery = genRecovery();
  store.set('auth', { ...auth, pin: makeHash(newPin), recovery: makeHash(newRecovery), totp: null });
  sessions.clear();
  store.audit('auth.recover', { ip });
  return { recovery: newRecovery };
}

function changePin({ pin, newPin }) {
  if (!verifyPin(pin)) throw Object.assign(new Error('PIN atual inválido.'), { status: 401 });
  validateSecret(newPin);
  store.update('auth', (a) => ({ ...a, pin: makeHash(newPin) }));
  store.audit('auth.changePin');
}

function totpBegin() {
  const secret = b32encode(crypto.randomBytes(20));
  store.update('auth', (a) => ({ ...a, totp: { secret, enabled: false } }));
  return { secret, uri: `otpauth://totp/Sentinel?secret=${secret}&issuer=Sentinel&digits=6&period=30` };
}
function totpConfirm(code) {
  const a = store.get('auth');
  if (!a?.totp || !totpVerify(a.totp.secret, code)) throw new Error('Código inválido.');
  store.update('auth', (x) => ({ ...x, totp: { ...x.totp, enabled: true } }));
  store.audit('auth.2fa.enable');
}
function totpDisable(pin) {
  if (!verifyPin(pin)) throw Object.assign(new Error('PIN inválido.'), { status: 401 });
  store.update('auth', (x) => ({ ...x, totp: null }));
  store.audit('auth.2fa.disable');
}

function sessionFor(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() - s.last > SESSION_IDLE_MS) { sessions.delete(token); return null; }
  s.last = Date.now();
  return s;
}
function logout(token) { sessions.delete(token); }

module.exports = {
  isSetup, setup, login, recover, changePin, verifyPin, needs2fa,
  totpBegin, totpConfirm, totpDisable, sessionFor, logout,
};
