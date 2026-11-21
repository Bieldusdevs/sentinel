'use strict';
// Armazenamento local em SQLite (node:sqlite - builtin, sem dependencia externa) + auditoria.
// Mesma interface de antes (get/set/update/audit/readAudit), so troca o que guarda os dados por
// baixo: um banco de verdade (data/sentinel.db) em vez de um JSON solto + um .log.
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = process.env.SENTINEL_DATA || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const DB_FILE = path.join(DATA_DIR, 'sentinel.db');
const db = new DatabaseSync(DB_FILE);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    t TEXT NOT NULL,
    type TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS audit_t_idx ON audit (id DESC);
`);

migrateFromJsonIfPresent();

const stmtGet = db.prepare('SELECT value FROM kv WHERE key = ?');
const stmtUpsert = db.prepare('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
const stmtAuditIns = db.prepare('INSERT INTO audit (t, type, actor, detail) VALUES (?, ?, ?, ?)');
const stmtAuditSel = db.prepare('SELECT t, type, actor, detail FROM audit ORDER BY id DESC LIMIT ?');

function get(key, fallback) {
  const row = stmtGet.get(key);
  if (row === undefined) return fallback;
  try { return JSON.parse(row.value); } catch { return fallback; }
}

function set(key, value) {
  stmtUpsert.run(key, JSON.stringify(value));
  return value;
}

function update(key, fn, fallback) {
  const next = fn(get(key, fallback));
  return set(key, next);
}

// Auditoria: uma linha por evento. Nunca registrar segredos aqui.
function audit(type, detail = {}, actor = 'system') {
  try { stmtAuditIns.run(new Date().toISOString(), String(type), String(actor), JSON.stringify(detail)); }
  catch { /* ignore */ }
}

function readAudit(limit = 200) {
  try {
    return stmtAuditSel.all(limit).map((r) => {
      let d = {}; try { d = JSON.parse(r.detail); } catch { /* ignore */ }
      return { t: r.t, type: r.type, actor: r.actor, ...d };
    });
  } catch { return []; }
}

// Primeira vez num diretório que já tinha o formato antigo (config.json + audit.log): importa uma
// vez só e renomeia os arquivos antigos com ".migrated" pra não reimportar de novo.
function migrateFromJsonIfPresent() {
  const configFile = path.join(DATA_DIR, 'config.json');
  const auditFile = path.join(DATA_DIR, 'audit.log');
  try {
    if (fs.existsSync(configFile)) {
      const cfg = JSON.parse(fs.readFileSync(configFile, 'utf8'));
      const up = db.prepare('INSERT INTO kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
      for (const [k, v] of Object.entries(cfg)) up.run(k, JSON.stringify(v));
      fs.renameSync(configFile, configFile + '.migrated');
    }
  } catch { /* se der errado, segue sem migrar - nao trava o app */ }
  try {
    if (fs.existsSync(auditFile)) {
      const lines = fs.readFileSync(auditFile, 'utf8').trim().split('\n').filter(Boolean);
      const ins = db.prepare('INSERT INTO audit (t, type, actor, detail) VALUES (?, ?, ?, ?)');
      for (const line of lines) {
        try {
          const { t, type, actor, ...detail } = JSON.parse(line);
          ins.run(t || new Date().toISOString(), type || 'legacy', actor || 'system', JSON.stringify(detail));
        } catch { /* linha corrompida, pula */ }
      }
      fs.renameSync(auditFile, auditFile + '.migrated');
    }
  } catch { /* idem */ }
}

module.exports = { DATA_DIR, DB_FILE, get, set, update, audit, readAudit };
