'use strict';
// Notas: campo de anotações simples, salvo no servidor (visivel tambem pelo acesso remoto).
const crypto = require('crypto');
const store = require('./store');

function list() { return store.get('notes', []).map((n) => ({ id: n.id, title: n.title, body: n.body, updatedAt: n.updatedAt })).sort((a, b) => b.updatedAt - a.updatedAt); }

function upsert({ id, title, body }) {
  title = String(title ?? '').slice(0, 200);
  body = String(body ?? '').slice(0, 200000);
  const notes = store.get('notes', []);
  if (id) {
    const i = notes.findIndex((n) => n.id === id);
    if (i < 0) throw new Error('Nota não encontrada.');
    notes[i] = { ...notes[i], title, body, updatedAt: Date.now() };
  } else {
    id = crypto.randomBytes(6).toString('hex');
    notes.push({ id, title, body, createdAt: Date.now(), updatedAt: Date.now() });
  }
  store.set('notes', notes.slice(-300));
  return { id };
}

function remove(id) {
  store.update('notes', (l) => l.filter((n) => n.id !== id), []);
}

module.exports = { list, upsert, remove };
