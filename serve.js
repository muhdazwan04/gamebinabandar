// Pelayan kecil untuk "Bina Bandar 3D" — tiada pakej luar (Node.js 18+ sahaja).
// Jalankan:  node server.js      (PORT=3000 DATA_DIR=./data ALLOW_ORIGIN=* )
// Ia menyajikan index.html DAN menyimpan akaun (ID + kata laluan) serta rekod game dalam folder data/.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = +process.env.PORT || 3000;
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const ORIGIN = process.env.ALLOW_ORIGIN || '*';          // jika index.html di host lain, letak URL tepat host itu
const SAVES = path.join(DATA, 'saves');
fs.mkdirSync(SAVES, { recursive: true });

const readJ = (f, d) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { return d; } };
const writeJ = (f, o) => { const t = f + '.tmp'; fs.writeFileSync(t, JSON.stringify(o)); fs.renameSync(t, f); };
const UF = path.join(DATA, 'users.json'), SF = path.join(DATA, 'sessions.json');
let users = readJ(UF, {}), sessions = readJ(SF, {});
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const scrypt = (pw, salt) => new Promise((ok, no) => crypto.scrypt(pw, salt, 64, (e, k) => e ? no(e) : ok(k.toString('hex'))));
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const ID_RE = /^[a-z0-9_.]{3,20}$/, TTL = 90 * 864e5;

// had cubaan log masuk: 10 kali / 10 minit bagi setiap IP + ID
const tries = new Map();
function limited(key) { const n = Date.now(), a = (tries.get(key) || []).filter(t => n - t < 6e5); tries.set(key, a); return a.length >= 10; }
function hit(key) { const a = tries.get(key) || []; a.push(Date.now()); tries.set(key, a); }

function send(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}
function body(req, max = 2e6) {
  return new Promise((ok, no) => { let n = 0; const c = []; req.on('data', d => { n += d.length; if (n > max) { no(new Error('big')); req.destroy(); } else c.push(d); }); req.on('end', () => { try { ok(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch (e) { no(e); } }); req.on('error', no); });
}
function newSession(id) {
  const tok = crypto.randomBytes(32).toString('hex');
  sessions[sha(tok)] = { id, exp: Date.now() + TTL };
  for (const k in sessions) if (sessions[k].exp < Date.now()) delete sessions[k];
  writeJ(SF, sessions); return tok;
}
function auth(req) {
  const m = /^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization || ''); if (!m) return null;
  const s = sessions[sha(m[1])]; if (!s || s.exp < Date.now() || !users[s.id]) return null; return s.id;
}
const saveFile = id => path.join(SAVES, users[id].uid + '.json');
const ip = req => req.socket.remoteAddress || '';

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0];
    if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS' }); return res.end(); }
    if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
      const h = fs.readFileSync(path.join(__dirname, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' }); return res.end(h);
    }
    if (!url.startsWith('/api/')) return send(res, 404, { error: 'Tidak dijumpai.' });

    if (url === '/api/register' && req.method === 'POST') {
      const { id, pw } = await body(req, 5e3);
      if (typeof id !== 'string' || !ID_RE.test(id)) return send(res, 400, { error: 'ID mesti 3–20 aksara: huruf kecil, nombor, _ atau .' });
      if (typeof pw !== 'string' || pw.length < 6 || pw.length > 100) return send(res, 400, { error: 'Kata laluan minimum 6 aksara.' });
      if (users[id]) return send(res, 409, { error: 'ID ini sudah digunakan. Pilih ID lain.' });
      if (Object.keys(users).length >= 5000) return send(res, 503, { error: 'Pendaftaran penuh.' });
      const salt = crypto.randomBytes(16).toString('hex');
      users[id] = { uid: crypto.randomBytes(12).toString('hex'), salt, hash: await scrypt(pw, salt), created: Date.now() };
      writeJ(UF, users); return send(res, 200, { id, token: newSession(id) });
    }
    if (url === '/api/login' && req.method === 'POST') {
      const { id, pw } = await body(req, 5e3), key = ip(req) + '|' + id;
      if (limited(key)) return send(res, 429, { error: 'Terlalu banyak cubaan. Cuba lagi 10 minit kemudian.' });
      const u = typeof id === 'string' && typeof pw === 'string' ? users[id] : null;
      if (!u || !eq(await scrypt(pw, u.salt), u.hash)) { hit(key); return send(res, 401, { error: 'ID atau kata laluan salah.' }); }
      return send(res, 200, { id, token: newSession(id) });
    }
    const id = auth(req);
    if (!id) return send(res, 401, { error: 'Sesi tamat. Sila log masuk semula.' });
    if (url === '/api/me' && req.method === 'GET') return send(res, 200, { id });
    if (url === '/api/logout' && req.method === 'POST') { delete sessions[sha(req.headers.authorization.slice(7))]; writeJ(SF, sessions); return send(res, 200, { ok: 1 }); }
    if (url === '/api/save' && req.method === 'GET') {
      const d = readJ(saveFile(id), null); return send(res, 200, d ? { exists: true, save: d.save || '', prof: d.prof || '', ts: d.ts || 0 } : { exists: false });
    }
    if (url === '/api/save' && req.method === 'PUT') {
      const d = await body(req, 2e6);
      if (typeof d.save !== 'string' || typeof d.prof !== 'string' || d.save.length > 1.5e6 || d.prof.length > 500) return send(res, 400, { error: 'Data tidak sah.' });
      writeJ(saveFile(id), { save: d.save, prof: d.prof, ts: +d.ts || Date.now() }); return send(res, 200, { ok: 1 });
    }
    if (url === '/api/password' && req.method === 'POST') {
      const { old, nw } = await body(req, 5e3), u = users[id], key = ip(req) + '|pw|' + id;
      if (limited(key)) return send(res, 429, { error: 'Terlalu banyak cubaan. Cuba lagi kemudian.' });
      if (typeof nw !== 'string' || nw.length < 6 || nw.length > 100) return send(res, 400, { error: 'Kata laluan baharu minimum 6 aksara.' });
      if (typeof old !== 'string' || !eq(await scrypt(old, u.salt), u.hash)) { hit(key); return send(res, 401, { error: 'Kata laluan lama salah.' }); }
      u.salt = crypto.randomBytes(16).toString('hex'); u.hash = await scrypt(nw, u.salt); writeJ(UF, users);
      for (const k in sessions) if (sessions[k].id === id) delete sessions[k];  // log keluar semua peranti lain
      return send(res, 200, { id, token: newSession(id) });
    }
    return send(res, 404, { error: 'Tidak dijumpai.' });
  } catch (e) { send(res, 400, { error: 'Permintaan tidak sah.' }); }
});
server.listen(PORT, () => console.log('Bina Bandar 3D berjalan di http://localhost:' + PORT + '  (data: ' + DATA + ')'));
