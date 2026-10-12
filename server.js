'use strict';
// Overlap server: serves overlap.html and keeps everyone's answers.
//   node server.js          reachable from this laptop only
//   node server.js --lan    also reachable from other devices on the same network
// On a host such as Render it listens publicly on the PORT it is given.
// Answers go to Postgres when DATABASE_URL is set (the only dependency, "pg", is loaded just for that),
// otherwise to data/events.json (DATA_DIR moves that folder, e.g. onto a mounted disk).
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 8080;
const ON_RENDER = Boolean(process.env.RENDER);
const HOST = process.env.HOST || (ON_RENDER || process.argv.includes('--lan') ? '0.0.0.0' : '127.0.0.1');
const PAGE = path.join(__dirname, 'overlap.html');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA = path.join(DATA_DIR, 'events.json');
const MAX_BODY = 1024 * 1024, MAX_EVENTS = 500, MAX_PEOPLE = 300, MAX_TOKENS = 5000;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

// ---------- storage ----------
// Events are held in memory and written through to the database or the data file.
// Render's free plan wipes the disk whenever the service restarts, so it needs the database.
const events = Object.create(null); // id -> event
const unsaved = new Set();          // ids changed since the last write
let pool = null, saveTimer = null, writes = Promise.resolve();

function loadFile() {
  if (!fs.existsSync(DATA)) return;
  try { Object.assign(events, JSON.parse(fs.readFileSync(DATA, 'utf8'))); }
  catch (e) {
    const kept = DATA + '.unreadable-' + Date.now();
    fs.copyFileSync(DATA, kept);
    console.error('data/events.json could not be read. Kept a copy at ' + kept + ' and started empty.');
  }
}
async function openDatabase(url) {
  const { Pool } = require('pg');
  let lastError;
  for (const ssl of [{ rejectUnauthorized: false }, false]) { // hosted databases usually want TLS; fall back to plain
    const p = new Pool({ connectionString: url, ssl, max: 3 });
    p.on('error', (e) => console.error('Database connection problem: ' + e.message));
    try {
      await p.query('CREATE TABLE IF NOT EXISTS overlap_events (id text PRIMARY KEY, data jsonb NOT NULL)');
      for (const row of (await p.query('SELECT id, data FROM overlap_events')).rows) events[row.id] = row.data;
      return p;
    } catch (e) { lastError = e; await p.end().catch(() => {}); }
  }
  throw lastError;
}
async function writeOut() {
  const ids = [...unsaved];
  unsaved.clear();
  if (!ids.length) return;
  if (!pool) {
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(DATA + '.tmp', JSON.stringify(events));
      fs.renameSync(DATA + '.tmp', DATA);
    } catch (e) { console.error('Could not save data/events.json: ' + e.message); }
    return;
  }
  for (const id of ids) {
    try {
      await pool.query('INSERT INTO overlap_events (id, data) VALUES ($1, $2::jsonb) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data', [id, JSON.stringify(events[id])]);
    } catch (e) { console.error('Could not save event ' + id + ' to the database: ' + e.message); unsaved.add(id); }
  }
  if (unsaved.size && !saveTimer) saveTimer = setTimeout(flush, 5000); // try again shortly
}
function flush() { // one write at a time, so an older copy can never land after a newer one
  if (saveTimer) { clearTimeout(saveTimer); saveTimer = null; }
  writes = writes.then(writeOut, writeOut);
  return writes;
}
function persist(ev) { unsaved.add(ev.id); if (!saveTimer) saveTimer = setTimeout(flush, 150); }

// ---------- model ----------
function validTz(tz) {
  try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); return true; } catch (e) { return false; }
}
function allKeys(ev) {
  const keys = new Set();
  for (const d of ev.days) {
    if (ev.mode === 'days') keys.add(d);
    else for (let m = ev.start; m < ev.end; m += 15) keys.add(d + '@' + m);
  }
  return keys;
}
function newEvent(o) {
  const kind = o.kind === 'dow' ? 'dow' : 'dates', mode = o.mode === 'days' ? 'days' : 'times';
  const days = [...new Set((Array.isArray(o.days) ? o.days : []).filter((k) => typeof k === 'string' && DATE.test(k)))].sort().slice(0, 366);
  if (!days.length) return null;
  let start = Number(o.start), end = Number(o.end);
  if (mode === 'days') { start = 540; end = 1020; }
  else if (!(Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end <= 1440 && end > start && start % 15 === 0 && end % 15 === 0)) return null;
  const tz = typeof o.tz === 'string' && o.tz.length <= 64 && validTz(o.tz) ? o.tz : 'UTC';
  const name = String(o.name || '').trim().slice(0, 120) || 'New event';
  return { id: crypto.randomBytes(8).toString('hex'), name, kind, mode, days, start, end, tz, created: Date.now(), people: [] };
}
function publicEvent(ev) { // never includes password salts or hashes
  return {
    id: ev.id, name: ev.name, kind: ev.kind, mode: ev.mode, days: ev.days, start: ev.start, end: ev.end, tz: ev.tz, created: ev.created,
    people: ev.people.map((p) => ({ name: p.name, slots: p.slots, updated: p.updated }))
  };
}

// ---------- sign in ----------
const tokens = new Map(); // token -> { id, name }; kept in memory, so a restart asks people to sign in again
const fails = new Map();  // event/name -> { n, until }
const scrypt = (pw, salt) => crypto.scryptSync(String(pw), salt, 32);
function signIn(ev, body) {
  const name = String(body.name || '').trim().slice(0, 40), pw = String(body.pw || '').slice(0, 200);
  if (!name) return { status: 400, error: 'name' };
  const key = ev.id + '/' + name.toLowerCase(), f = fails.get(key);
  if (f && f.until > Date.now()) return { status: 429, error: 'wait' };
  let person = ev.people.find((p) => p.name.toLowerCase() === name.toLowerCase());
  if (person) {
    if (person.hash && !crypto.timingSafeEqual(scrypt(pw, person.salt), Buffer.from(person.hash, 'hex'))) {
      const n = ((f && f.n) || 0) + 1;
      fails.set(key, n >= 8 ? { n: 0, until: Date.now() + 60000 } : { n, until: 0 });
      return { status: 403, error: 'password' };
    }
  } else {
    if (ev.people.length >= MAX_PEOPLE) return { status: 409, error: 'full' };
    person = { name, slots: {}, updated: Date.now() };
    if (pw) { person.salt = crypto.randomBytes(16).toString('hex'); person.hash = scrypt(pw, person.salt).toString('hex'); }
    ev.people.push(person);
    persist(ev);
  }
  fails.delete(key);
  const token = crypto.randomBytes(24).toString('hex');
  tokens.set(token, { id: ev.id, name: person.name });
  if (tokens.size > MAX_TOKENS) tokens.delete(tokens.keys().next().value);
  return { status: 200, name: person.name, token };
}

// ---------- http ----------
function send(res, status, body, type) {
  res.writeHead(status, {
    'Content-Type': type || 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Robots-Tag': 'noindex',
    'Referrer-Policy': 'no-referrer'
  });
  res.end(Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function fail(status, message) { return Object.assign(new Error(message), { status }); }
function readJson(req) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) { req.resume(); reject(fail(415, 'json only')); return; }
    const chunks = [];
    let size = 0, over = false;
    req.on('data', (c) => { size += c.length; if (size > MAX_BODY) over = true; else chunks.push(c); });
    req.on('error', reject);
    req.on('end', () => {
      if (over) { reject(fail(413, 'too large')); return; }
      try {
        const o = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!o || typeof o !== 'object' || Array.isArray(o)) throw new Error('shape');
        resolve(o);
      } catch (e) { reject(fail(400, 'bad json')); }
    });
  });
}
async function handle(req, res) {
  let p;
  try { p = new URL(req.url, 'http://localhost').pathname; } catch (e) { throw fail(400, 'bad url'); }
  const method = req.method;

  if (method === 'GET' && (p === '/' || p === '/overlap.html')) return send(res, 200, fs.readFileSync(PAGE), 'text/html; charset=utf-8');
  if (method === 'GET' && p === '/api/ping') {
    // durable is false when answers would be lost on the next restart (Render without a database or disk);
    // unsaved counts events still waiting to be written, so it stays above 0 if writes keep failing;
    // up is seconds since this process started, keepAwake how many self-requests were sent and answered
    return send(res, 200, {
      ok: true, app: 'overlap', store: pool ? 'database' : 'file', durable: Boolean(pool) || !ON_RENDER || Boolean(process.env.DATA_DIR),
      unsaved: unsaved.size, up: Math.round(process.uptime()), keepAwake: KEEP_AWAKE_URL ? awake : false
    });
  }

  if (method === 'POST' && p === '/api/events') {
    if (Object.keys(events).length >= MAX_EVENTS) throw fail(409, 'full');
    const ev = newEvent(await readJson(req));
    if (!ev) throw fail(400, 'invalid');
    events[ev.id] = ev;
    persist(ev);
    return send(res, 201, { event: publicEvent(ev) });
  }

  const m = /^\/api\/events\/([a-z0-9]{4,24})(\/signin|\/slots)?$/.exec(p);
  const ev = m ? events[m[1]] : null;
  if (!ev) throw fail(404, 'not found');

  if (!m[2] && method === 'GET') return send(res, 200, { event: publicEvent(ev) });

  if (m[2] === '/signin' && method === 'POST') {
    const r = signIn(ev, await readJson(req));
    if (r.status !== 200) throw fail(r.status, r.error);
    return send(res, 200, { ok: true, name: r.name, token: r.token, event: publicEvent(ev) });
  }

  if (m[2] === '/slots' && method === 'PUT') {
    const body = await readJson(req);
    const t = tokens.get(String(body.token || ''));
    const person = t && t.id === ev.id ? ev.people.find((x) => x.name === t.name) : null;
    if (!person) throw fail(401, 'sign in');
    const ok = allKeys(ev), slots = {};
    if (body.slots && typeof body.slots === 'object') for (const k of Object.keys(body.slots)) if (body.slots[k] && ok.has(k)) slots[k] = 1;
    person.slots = slots;
    person.updated = Date.now();
    persist(ev);
    return send(res, 200, { ok: true, updated: person.updated });
  }

  throw fail(404, 'not found');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    if (!e.status) console.error(e);
    if (res.headersSent) res.end(); else send(res, e.status || 500, { error: e.status ? e.message : 'server error' });
  });
});
server.on('error', (e) => {
  console.error(e.code === 'EADDRINUSE' ? 'Port ' + PORT + ' is already in use. Close the other program or run with a different PORT.' : e.message);
  process.exit(1);
});
// Render's free plan stops a service after 15 minutes without a visit, and the next visitor then waits
// about a minute for it to boot. Requesting our own public address every 10 minutes counts as a visit.
// Render sets RENDER_EXTERNAL_URL itself; KEEP_AWAKE_URL does the same on other hosts.
const KEEP_AWAKE_URL = (process.env.KEEP_AWAKE_URL || process.env.RENDER_EXTERNAL_URL || '').replace(/\/+$/, '');
const KEEP_AWAKE_MS = (Number(process.env.KEEP_AWAKE_MINUTES) || 10) * 60000;
const awake = { sent: 0, ok: 0 };
function keepAwake() {
  if (!KEEP_AWAKE_URL || typeof fetch !== 'function') return;
  setInterval(() => {
    awake.sent++;
    fetch(KEEP_AWAKE_URL + '/api/ping', { signal: AbortSignal.timeout(20000) })
      .then((r) => r.arrayBuffer().then(() => { if (r.ok) awake.ok++; }))
      .catch((e) => console.error('Keep-awake request failed: ' + e.message));
  }, KEEP_AWAKE_MS).unref();
}

async function start() {
  if (process.env.DATABASE_URL) {
    try { pool = await openDatabase(process.env.DATABASE_URL); }
    catch (e) { console.error('Could not use the database (' + String(e.message).split('\n')[0] + '). Using the data file instead.'); }
  }
  if (!pool) loadFile();
  server.listen(PORT, HOST, () => {
    console.log('Overlap is running on port ' + PORT + (HOST === '127.0.0.1' ? ', this laptop only: http://localhost:' + PORT : ''));
    console.log(pool ? 'Answers are saved in the database.'
      : 'Answers are saved in ' + DATA + (ON_RENDER && !process.env.DATA_DIR ? ' (temporary: this host wipes it on restart)' : ''));
    if (KEEP_AWAKE_URL) console.log('Keeping awake by requesting ' + KEEP_AWAKE_URL + ' every ' + KEEP_AWAKE_MS / 60000 + ' minutes.');
    keepAwake();
  });
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { flush().then(() => process.exit(0)); });
start();
