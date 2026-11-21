'use strict';
// IA 100% local: Ollama (roda na GPU/CPU do seu PC). Nada sai da maquina.
const { spawn } = require('child_process');
const store = require('./store');
const jobs = require('./jobs');

const DEFAULTS = {
  ollamaUrl: 'http://127.0.0.1:11434',
  ollamaModel: 'qwen2.5-coder:7b',
  numCtx: 8192,
  temperature: 0.2,
};

// Para ~6 GB de VRAM + 16 GB de RAM. 7B/8B cabem inteiros na GPU; 14B e dividido entre GPU e CPU (mais forte, mais lento).
const RECOMMENDED = [
  { id: 'qwen2.5-coder:7b', size: '4.7 GB', note: 'Melhor custo/benefício para código. Cabe inteiro na GPU. Padrão.' },
  { id: 'qwen2.5-coder:14b', size: '9.0 GB', note: 'Bem mais capaz em código; divide GPU/CPU, então é mais lento.' },
  { id: 'qwen3:8b', size: '5.2 GB', note: 'Raciocina antes de responder; uso geral e análise. Cabe na GPU.' },
  { id: 'qwen3:14b', size: '9.3 GB', note: 'Raciocínio mais forte; mais lento (divide GPU/CPU).' },
  { id: 'qwen2.5-coder:3b', size: '1.9 GB', note: 'Muito rápido, para tarefas simples.' },
];

function settings() { return { ...DEFAULTS, ...store.get('ai', {}) }; }
function publicSettings() { return settings(); }

async function saveSettings(patch) {
  const next = { ...settings() };
  if (typeof patch.ollamaModel === 'string') {
    const m = patch.ollamaModel.trim();
    if (!/^[a-z0-9][a-z0-9._:/\-]{1,80}$/i.test(m)) throw new Error('Nome de modelo inválido.');
    next.ollamaModel = m;
  }
  if (patch.ollamaUrl) {
    const u = new URL(patch.ollamaUrl);
    if (!['127.0.0.1', 'localhost', '::1', '[::1]'].includes(u.hostname)) throw new Error('O Ollama deve estar nesta máquina (127.0.0.1).');
    next.ollamaUrl = u.origin;
  }
  if (patch.numCtx) next.numCtx = Math.min(Math.max(+patch.numCtx | 0, 2048), 32768);
  if (patch.temperature !== undefined) next.temperature = Math.min(Math.max(+patch.temperature, 0), 1.5);
  store.set('ai', next);
  store.audit('ai.settings', { model: next.ollamaModel });
  return publicSettings();
}

// ---------- Ollama ----------
async function ollamaFetch(path, opts = {}) {
  return fetch(settings().ollamaUrl + path, opts);
}

async function ollamaStatus() {
  try {
    const v = await (await ollamaFetch('/api/version', { signal: AbortSignal.timeout(2500) })).json();
    const t = await (await ollamaFetch('/api/tags', { signal: AbortSignal.timeout(4000) })).json();
    return { running: true, version: v.version, models: (t.models || []).map((m) => ({ name: m.name, size: m.size, modified: m.modified_at })), recommended: RECOMMENDED };
  } catch { return { running: false, models: [], recommended: RECOMMENDED }; }
}

function ollamaServe() {
  const child = spawn('ollama', ['serve'], { detached: true, stdio: 'ignore', windowsHide: true });
  child.on('error', () => {}); child.unref();
  store.audit('ollama.serve');
}

function ollamaPull(model) {
  if (!/^[a-z0-9][a-z0-9._:/\-]{1,80}$/i.test(model || '')) throw new Error('Nome de modelo inválido.');
  const job = jobs.create('pull', `Baixar modelo ${model}`, { model });
  store.audit('ollama.pull', { model });
  (async () => {
    try {
      const res = await ollamaFetch('/api/pull', { method: 'POST', body: JSON.stringify({ name: model, stream: true }) });
      if (!res.ok || !res.body) throw new Error(`Ollama respondeu ${res.status}. Ele está rodando?`);
      const dec = new TextDecoder(); let buf = ''; let lastPct = -1;
      for await (const chunk of res.body) {
        buf += dec.decode(chunk, { stream: true });
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, i); buf = buf.slice(i + 1);
          if (!line.trim()) continue;
          const j = JSON.parse(line);
          if (j.error) throw new Error(j.error);
          if (j.total && j.completed) {
            const pct = Math.floor((j.completed / j.total) * 100);
            if (pct !== lastPct && pct % 2 === 0) { lastPct = pct; jobs.emit(job, `${j.status}  ${pct}%  (${(j.completed / 1e9).toFixed(2)} / ${(j.total / 1e9).toFixed(2)} GB)`); }
          } else if (j.status) jobs.emit(job, j.status);
        }
      }
      jobs.finish(job, 'done', 0);
    } catch (e) { jobs.emit(job, `Erro: ${e.message}`, 'err'); jobs.finish(job, 'failed', 1); }
  })();
  return job;
}

// ---------- streaming de chat ----------
async function* readLines(body) {
  const dec = new TextDecoder(); let buf = '';
  for await (const chunk of body) {
    buf += dec.decode(chunk, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) { yield buf.slice(0, i).replace(/\r$/, ''); buf = buf.slice(i + 1); }
  }
  if (buf.trim()) yield buf;
}

// Modelos de raciocínio (qwen3, deepseek-r1) podem emitir <think>...</think> no texto. Remove do fluxo,
// tratando tags partidas entre pedaços ("<thi" + "nk>").
function createThinkFilter() {
  let inThink = false; let hold = '';
  const OPEN = '<think>'; const CLOSE = '</think>';
  return (chunk, flush = false) => {
    let s = hold + chunk; hold = ''; let out = '';
    while (s.length) {
      if (inThink) {
        const i = s.indexOf(CLOSE);
        if (i < 0) { hold = flush ? '' : s.slice(-(CLOSE.length - 1)); return out; } // ainda dentro do raciocinio
        s = s.slice(i + CLOSE.length).replace(/^\s+/, ''); inThink = false;
      } else {
        const i = s.indexOf(OPEN);
        if (i >= 0) { out += s.slice(0, i); s = s.slice(i + OPEN.length); inThink = true; continue; }
        // guarda um possivel inicio de tag no fim do pedaço
        let keep = 0;
        if (!flush) for (let k = Math.min(OPEN.length - 1, s.length); k > 0; k--) if (OPEN.startsWith(s.slice(-k))) { keep = k; break; }
        out += s.slice(0, s.length - keep); hold = s.slice(s.length - keep); return out;
      }
    }
    return out;
  };
}

async function* streamChat({ system, messages, signal }) {
  const s = settings();
  const res = await ollamaFetch('/api/chat', {
    method: 'POST', signal,
    body: JSON.stringify({
      model: s.ollamaModel, stream: true, keep_alive: '10m',
      // stop: o modelo nunca deve escrever o marcador de resultado (quem o devolve e o sistema); evita resultados inventados
      options: { temperature: s.temperature, num_ctx: s.numCtx, stop: ['[RESULTADO_DA_FERRAMENTA'] },
      messages: [{ role: 'system', content: system }, ...messages],
    }),
  }).catch(() => { throw new Error('Não consegui falar com o Ollama. Inicie-o em Modelos de IA.'); });
  if (!res.ok) {
    const body = (await res.text()).slice(0, 300);
    if (res.status === 404) throw new Error(`O modelo "${s.ollamaModel}" não está instalado. Baixe-o em Modelos de IA.`);
    throw new Error(`Ollama: ${body}`);
  }
  const filter = createThinkFilter();
  for await (const line of readLines(res.body)) {
    if (!line) continue;
    const j = JSON.parse(line);
    if (j.error) throw new Error(j.error);
    // j.message.thinking (campo separado em versoes novas) e ignorado de proposito.
    if (j.message?.content) { const t = filter(j.message.content); if (t) yield t; }
    if (j.done) { const t = filter('', true); if (t) yield t; }
  }
}

module.exports = { settings, publicSettings, saveSettings, ollamaStatus, ollamaServe, ollamaPull, streamChat, createThinkFilter, RECOMMENDED };
