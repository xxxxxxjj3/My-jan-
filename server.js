const express = require('express'), http = require('http'), path = require('path');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 16) { console.error('JWT_SECRET (কমপক্ষে ১৬ অক্ষর) সেট করুন'); process.exit(1); }
const PORT = process.env.PORT || 3000;

const db = new Database(process.env.DB_FILE || 'bondhu.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, hash TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, chat TEXT NOT NULL, sender TEXT NOT NULL, recipient TEXT NOT NULL, text TEXT NOT NULL, t INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_chat ON messages(chat, t);`);

const chatId = (a, b) => [a, b].sort().join('__');
const NAME = /^[a-z0-9_]{3,20}$/;

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// সহজ রেট লিমিট: ১৫ মিনিটে ১০টি চেষ্টা
const hits = new Map();
function limit(req, res, next) {
  const k = req.ip, now = Date.now(), h = hits.get(k) || { n: 0, t: now };
  if (now - h.t > 15 * 60 * 1000) { h.n = 0; h.t = now; }
  if (++h.n > 10) return res.status(429).json({ error: 'অনেক বেশি চেষ্টা। কিছুক্ষণ পরে আবার চেষ্টা করুন।' });
  hits.set(k, h); next();
}

app.post('/api/signup', limit, async (req, res) => {
  const u = String(req.body.username || '').trim().toLowerCase(), p = String(req.body.password || '');
  if (!NAME.test(u)) return res.status(400).json({ error: 'ইউজারনেম: ৩–২০ অক্ষর, শুধু a-z, 0-9, _' });
  if (p.length < 6 || p.length > 64) return res.status(400).json({ error: 'পাসওয়ার্ড ৬–৬৪ অক্ষরের হতে হবে' });
  if (db.prepare('SELECT 1 FROM users WHERE username=?').get(u)) return res.status(409).json({ error: 'এই ইউজারনেম আগে থেকেই নেওয়া' });
  const hash = await bcrypt.hash(p, 10);
  try { db.prepare('INSERT INTO users VALUES(?,?,?)').run(u, hash, Date.now()); }
  catch { return res.status(409).json({ error: 'এই ইউজারনেম আগে থেকেই নেওয়া' }); }
  res.status(201).json({ ok: true });
});

app.post('/api/login', limit, async (req, res) => {
  const u = String(req.body.username || '').trim().toLowerCase(), p = String(req.body.password || '');
  const row = db.prepare('SELECT * FROM users WHERE username=?').get(u);
  // ইউজার না থাকলেও একই সময় লাগানো, যাতে ইউজারনেম আন্দাজ করা না যায়
  const ok = await bcrypt.compare(p, row ? row.hash : '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinv');
  if (!row || !ok) return res.status(401).json({ error: 'ইউজারনেম বা পাসওয়ার্ড ভুল' });
  res.json({ token: jwt.sign({ u }, SECRET, { expiresIn: '7d' }), username: u });
});

function auth(req, res, next) {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET).u; next(); }
  catch { res.status(401).json({ error: 'লগইন দরকার' }); }
}

app.get('/api/users', auth, (req, res) => {
  const q = String(req.query.q || '').toLowerCase().replace(/[^a-z0-9_]/g, '');
  res.json(db.prepare("SELECT username FROM users WHERE username!=? AND username LIKE ? ORDER BY username LIMIT 50")
    .all(req.user, q + '%').map(r => r.username));
});

app.get('/api/messages/:peer', auth, (req, res) => {
  res.json(db.prepare('SELECT sender,text,t FROM messages WHERE chat=? ORDER BY t DESC LIMIT 200')
    .all(chatId(req.user, req.params.peer)).reverse());
});

app.get('/api/ice', auth, (req, res) => {
  const s = [{ urls: 'stun:stun.l.google.com:19302' }];
  if (process.env.TURN_URL) s.push({ urls: process.env.TURN_URL, username: process.env.TURN_USER, credential: process.env.TURN_PASS });
  res.json({ iceServers: s });
});

// ---- WebSocket: মেসেজ, উপস্থিতি, কলের সিগন্যালিং ----
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 64 * 1024 });
const online = new Map(); // username -> Set<ws>

const send = (ws, o) => ws.readyState === 1 && ws.send(JSON.stringify(o));
const toUser = (u, o) => (online.get(u) || []).forEach(w => send(w, o));
const broadcastPresence = () => { const l = [...online.keys()]; wss.clients.forEach(w => send(w, { type: 'presence', online: l })); };

wss.on('connection', (ws, req) => {
  let user;
  try { user = jwt.verify(new URL(req.url, 'http://x').searchParams.get('token'), SECRET).u; }
  catch { return ws.close(4001, 'unauthorized'); }
  if (!online.has(user)) online.set(user, new Set());
  online.get(user).add(ws); ws.alive = true;
  ws.on('pong', () => ws.alive = true);
  broadcastPresence();

  ws.on('message', raw => {
    let m; try { m = JSON.parse(raw); } catch { return; }
    if (typeof m.to !== 'string' || !NAME.test(m.to) || m.to === user) return;
    if (m.type === 'msg') {
      const text = String(m.text || '').slice(0, 2000).trim();
      if (!text || !db.prepare('SELECT 1 FROM users WHERE username=?').get(m.to)) return;
      const t = Date.now();
      db.prepare('INSERT INTO messages(chat,sender,recipient,text,t) VALUES(?,?,?,?,?)').run(chatId(user, m.to), user, m.to, text, t);
      const out = { type: 'msg', from: user, to: m.to, text, t };
      toUser(user, out); toUser(m.to, out);
    } else if (m.type === 'sig') {
      // শুধু সিগন্যাল ফরওয়ার্ড; প্রেরক সবসময় সার্ভার থেকে বসানো হয়
      toUser(m.to, { type: 'sig', from: user, to: m.to, d: m.d });
    }
  });
  ws.on('close', () => {
    const s = online.get(user); s.delete(ws);
    if (!s.size) online.delete(user);
    broadcastPresence();
  });
});
setInterval(() => wss.clients.forEach(w => { if (!w.alive) return w.terminate(); w.alive = false; w.ping(); }), 30000);

server.listen(PORT, () => console.log('চালু: http://localhost:' + PORT));
