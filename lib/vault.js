'use strict';
// Gerador de senhas + criptografia de arquivos/pastas (AES-256-GCM, chave via scrypt).
// Formato .sntl: "SNTL1" | log2N(1) | salt(16) | iv(12) | nameLen(2) | name | ciphertext | tag(16)
// O nome original vai em claro, mas autenticado como AAD (alteração => falha na decifragem).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const store = require('./store');

const MAGIC = Buffer.from('SNTL1');
const LOGN = 17; // N = 131072 (~128 MB de memória durante a derivação)

// ---------- senhas ----------
const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~',
};
const AMBIGUOUS = /[O0oIl1|`'"\\]/g;

function generatePassword({ length = 32, lower = true, upper = true, digits = true, symbols = true, avoidAmbiguous = false, count = 1 } = {}) {
  length = Math.floor(+length);
  if (!(length >= 4 && length <= 1024)) throw new Error('Tamanho entre 4 e 1024.');
  count = Math.min(Math.max(Math.floor(+count) || 1, 1), 20);
  const classes = [];
  for (const [name, on] of Object.entries({ lower, upper, digits, symbols })) {
    if (!on) continue;
    let chars = SETS[name]; if (avoidAmbiguous) chars = chars.replace(AMBIGUOUS, '');
    if (chars) classes.push(chars);
  }
  if (!classes.length) throw new Error('Selecione ao menos um tipo de caractere.');
  const pool = classes.join('');
  const out = [];
  for (let n = 0; n < count; n++) {
    const chars = classes.map((c) => c[crypto.randomInt(c.length)]); // garante 1 de cada classe
    while (chars.length < length) chars.push(pool[crypto.randomInt(pool.length)]);
    for (let i = chars.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; } // Fisher-Yates
    out.push(chars.slice(0, length).join(''));
  }
  const entropy = Math.round(length * Math.log2(pool.length));
  return { passwords: out, entropyBits: entropy, poolSize: pool.length };
}

function generatePassphrase(words = 6) {
  // Diceware simples sem lista externa: silabas pronunciaveis (menos entropia/palavra que diceware real, compensada pelo tamanho).
  const C = 'bcdfghjklmnprstvz'; const V = 'aeiou';
  const w = [];
  for (let i = 0; i < Math.min(Math.max(words, 4), 12); i++) {
    let s = ''; for (let k = 0; k < 3; k++) s += C[crypto.randomInt(C.length)] + V[crypto.randomInt(V.length)];
    w.push(s);
  }
  const bits = Math.round(w.length * 3 * Math.log2(C.length * V.length));
  return { passphrase: w.join('-'), entropyBits: bits };
}

// ---------- arquivos ----------
function deriveKey(password, salt, logN) {
  return crypto.scryptSync(String(password), salt, 32, { N: 2 ** logN, r: 8, p: 1, maxmem: 512 * 1024 * 1024 });
}

function assertPath(p) {
  if (!p || typeof p !== 'string' || p.includes('\0')) throw new Error('Caminho inválido.');
  return path.resolve(p);
}

// bsdtar nativo do Windows; caminho fixo evita pegar o GNU tar do Git (que le "C:" como host).
const TAR = process.platform === 'win32' ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'tar.exe') : 'tar';

function tarRun(args) {
  return new Promise((resolve, reject) => {
    const c = spawn(TAR, args, { windowsHide: true });
    let err = ''; c.stderr.on('data', (d) => { err += d; });
    c.on('error', reject);
    c.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`tar falhou: ${err.trim()}`))));
  });
}

async function encryptFile(src, password, { removeOriginal = false } = {}) {
  src = assertPath(src);
  if (String(password).length < 8) throw new Error('Use uma senha de ao menos 8 caracteres.');
  let st; try { st = fs.statSync(src); } catch { throw new Error('Arquivo ou pasta não encontrado.'); }
  let source = src; let tmpTar = null; let name = path.basename(src);
  if (st.isDirectory()) {
    tmpTar = src.replace(/[\\/]+$/, '') + '.tar';
    await tarRun(['-cf', tmpTar, '-C', path.dirname(src), path.basename(src)]);
    source = tmpTar; name = path.basename(tmpTar);
  }
  const out = source + '.sntl';
  if (fs.existsSync(out)) throw new Error('Já existe um arquivo .sntl com esse nome.');
  const salt = crypto.randomBytes(16); const iv = crypto.randomBytes(12);
  const nameBuf = Buffer.from(name, 'utf8');
  const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16BE(nameBuf.length);
  const header = Buffer.concat([MAGIC, Buffer.from([LOGN]), salt, iv, lenBuf, nameBuf]);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(password, salt, LOGN), iv);
  cipher.setAAD(header);
  const ws = fs.createWriteStream(out, { mode: 0o600 });
  ws.write(header);
  try {
    await pipeline(fs.createReadStream(source), cipher, ws, { end: false });
    await new Promise((res, rej) => ws.end(cipher.getAuthTag(), (e) => (e ? rej(e) : res())));
  } catch (e) { try { fs.unlinkSync(out); } catch { /* */ } throw e; }
  finally { if (tmpTar) try { fs.unlinkSync(tmpTar); } catch { /* */ } }
  if (removeOriginal) {
    if (st.isDirectory()) fs.rmSync(src, { recursive: true, force: true }); else fs.unlinkSync(src);
  }
  store.audit('vault.encrypt', { file: path.basename(src), removed: !!removeOriginal });
  return { output: out, size: fs.statSync(out).size };
}

async function decryptFile(src, password, { extract = true } = {}) {
  src = assertPath(src);
  const fd = fs.openSync(src, 'r');
  try {
    const st = fs.fstatSync(fd);
    const fixed = Buffer.alloc(MAGIC.length + 1 + 16 + 12 + 2);
    fs.readSync(fd, fixed, 0, fixed.length, 0);
    if (!fixed.subarray(0, MAGIC.length).equals(MAGIC)) throw new Error('Arquivo não é um .sntl válido.');
    const logN = fixed[MAGIC.length];
    if (logN < 14 || logN > 20) throw new Error('Parametros inválidos.');
    const salt = fixed.subarray(MAGIC.length + 1, MAGIC.length + 17);
    const iv = fixed.subarray(MAGIC.length + 17, MAGIC.length + 29);
    const nameLen = fixed.readUInt16BE(MAGIC.length + 29);
    const nameBuf = Buffer.alloc(nameLen); fs.readSync(fd, nameBuf, 0, nameLen, fixed.length);
    const headerLen = fixed.length + nameLen;
    const header = Buffer.concat([fixed, nameBuf]);
    const tag = Buffer.alloc(16); fs.readSync(fd, tag, 0, 16, st.size - 16);
    const name = path.basename(nameBuf.toString('utf8')); // basename impede path traversal no nome armazenado
    const dir = path.dirname(src);
    let out = path.join(dir, name);
    if (fs.existsSync(out)) out = path.join(dir, `restaurado-${Date.now()}-${name}`);
    const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(password, salt, logN), iv);
    decipher.setAAD(header); decipher.setAuthTag(tag);
    const ws = fs.createWriteStream(out, { mode: 0o600 });
    try {
      await pipeline(fs.createReadStream(src, { start: headerLen, end: st.size - 17 }), decipher, ws);
    } catch {
      try { fs.unlinkSync(out); } catch { /* */ }
      throw new Error('Senha incorreta ou arquivo corrompido.');
    }
    let result = out;
    if (extract && /\.tar$/i.test(out)) {
      await tarRun(['-xf', out, '-C', dir]);
      fs.unlinkSync(out); result = path.join(dir, name.replace(/\.tar$/i, ''));
    }
    store.audit('vault.decrypt', { file: path.basename(src) });
    return { output: result };
  } finally { fs.closeSync(fd); }
}

module.exports = { generatePassword, generatePassphrase, encryptFile, decryptFile };
