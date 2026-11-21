'use strict';
// Gerenciador de jobs: processos/tarefas longas com saída em streaming (SSE).
const { spawn } = require('child_process');
const crypto = require('crypto');

const jobs = new Map();
const MAX_LINES = 4000;

function create(kind, title, meta = {}) {
  const id = crypto.randomBytes(6).toString('hex');
  const job = {
    id, kind, title, meta, status: 'running', startedAt: Date.now(), endedAt: null,
    lines: [], subs: new Set(), child: null, code: null,
  };
  jobs.set(id, job);
  // limita histórico de jobs
  if (jobs.size > 60) {
    const old = [...jobs.values()].filter((j) => j.status !== 'running').sort((a, b) => a.startedAt - b.startedAt)[0];
    if (old) jobs.delete(old.id);
  }
  return job;
}

function emit(job, text, stream = 'out') {
  for (const raw of String(text).split(/\r?\n/)) {
    if (raw === '' && stream !== 'sys') continue;
    const line = { t: Date.now(), s: stream, x: raw };
    job.lines.push(line);
    if (job.lines.length > MAX_LINES) job.lines.shift();
    for (const send of job.subs) send(line);
  }
}

function finish(job, status, code = null) {
  if (job.status !== 'running') return;
  job.status = status; job.code = code; job.endedAt = Date.now();
  for (const send of job.subs) send({ t: Date.now(), s: 'end', x: status, code });
}

// Executa um binário SEM shell (argumentos como array => sem injeção de comando).
function runProcess(job, file, args, opts = {}) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(file, args, { windowsHide: true, ...opts });
    } catch (e) {
      emit(job, `Falha ao iniciar: ${e.message}`, 'err');
      finish(job, 'failed', -1);
      return resolve(-1);
    }
    job.child = child;
    child.stdout.on('data', (d) => emit(job, d.toString('utf8'), 'out'));
    child.stderr.on('data', (d) => emit(job, d.toString('utf8'), 'err'));
    child.on('error', (e) => { emit(job, `Erro: ${e.message}`, 'err'); finish(job, 'failed', -1); resolve(-1); });
    child.on('close', (code) => {
      finish(job, job.status === 'killed' ? 'killed' : code === 0 ? 'done' : 'failed', code);
      resolve(code);
    });
    if (opts.timeoutMs) {
      setTimeout(() => { if (job.status === 'running') kill(job.id); }, opts.timeoutMs).unref();
    }
  });
}

function kill(id) {
  const job = jobs.get(id);
  if (!job || job.status !== 'running') return false;
  job.status = 'killed';
  if (job.child) {
    try {
      if (process.platform === 'win32') spawn('taskkill', ['/pid', String(job.child.pid), '/T', '/F'], { windowsHide: true });
      else job.child.kill('SIGKILL');
    } catch { /* ignore */ }
  }
  finish(job, 'killed');
  return true;
}

function get(id) { return jobs.get(id); }

function list() {
  return [...jobs.values()].sort((a, b) => b.startedAt - a.startedAt).map((j) => ({
    id: j.id, kind: j.kind, title: j.title, status: j.status, startedAt: j.startedAt, endedAt: j.endedAt, code: j.code, lines: j.lines.length,
  }));
}

// Resposta SSE: reenvia o histórico e depois segue ao vivo.
function stream(job, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  const send = (line) => res.write(`data: ${JSON.stringify(line)}\n\n`);
  for (const l of job.lines) send(l);
  if (job.status !== 'running') { send({ t: Date.now(), s: 'end', x: job.status, code: job.code }); return res.end(); }
  job.subs.add(send);
  const ping = setInterval(() => res.write(': ping\n\n'), 15000);
  res.on('close', () => { job.subs.delete(send); clearInterval(ping); });
}

module.exports = { create, emit, finish, runProcess, kill, get, list, stream };
