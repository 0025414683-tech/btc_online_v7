'use strict';
// C++ MasterHub backend: node:http + node:sqlite + scrypt. Không cần npm install. Yêu cầu Node >= 22.5
const http = require('node:http'), fs = require('node:fs'), path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const scrypt = require('node:util').promisify(crypto.scrypt);

const PORT = +process.env.PORT || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';      // chỉ bật khi đứng sau reverse proxy tin cậy
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1';   // bật khi chạy HTTPS
const SESSION_DAYS = 30;
const USERNAME_RE = /^[A-Za-z0-9._-]{3,24}$/;

const db = new DatabaseSync(process.env.DB_FILE || path.join(__dirname, 'data.sqlite'));
db.exec(`
PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS Users (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL,
  username_key TEXT NOT NULL UNIQUE,                       -- chữ thường, chống trùng tên khác hoa/thường
  pw_salt      TEXT NOT NULL,
  pw_hash      TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'User' CHECK (role IN ('User','Admin')),
  device_fp    TEXT NOT NULL,                              -- thiết bị lúc tạo tài khoản
  signup_ip    TEXT,
  created_by   INTEGER REFERENCES Users(id),               -- NULL = tự đăng ký; khác NULL = Admin cấp
  created_at   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS Login_Logs (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id       INTEGER REFERENCES Users(id),              -- NULL khi thử tên không tồn tại
  username_tried TEXT,
  success       INTEGER NOT NULL,
  logged_at     TEXT NOT NULL,
  device_fp     TEXT NOT NULL,
  ip            TEXT,
  user_agent    TEXT
);
CREATE TABLE IF NOT EXISTS Sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_fp ON Users(device_fp);
CREATE INDEX IF NOT EXISTS idx_logs_fp  ON Login_Logs(device_fp);
CREATE INDEX IF NOT EXISTS idx_logs_user ON Login_Logs(user_id);
`);

// ---------- tiện ích ----------
class HttpError extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const now = () => new Date().toISOString();
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const send = (res, status, obj, headers = {}) => {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...headers });
  res.end(JSON.stringify(obj));
};
function ipOf(req) {
  const xf = TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return (xf || req.socket.remoteAddress || '').replace(/^::ffff:/, '').slice(0, 64);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    if (!/^application\/json/i.test(req.headers['content-type'] || '')) return reject(new HttpError(415, 'Cần Content-Type: application/json.'));
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > 10240) { reject(new HttpError(413, 'Dữ liệu quá lớn.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { const v = JSON.parse(Buffer.concat(chunks).toString() || '{}'); resolve(v && typeof v === 'object' ? v : {}); } catch (e) { reject(new HttpError(400, 'JSON không hợp lệ.')); } });
    req.on('error', reject);
  });
}
const buckets = new Map();   // giới hạn tốc độ trong bộ nhớ (đủ cho 1 tiến trình)
function limit(key, max, windowMs) {
  const t = Date.now(); let b = buckets.get(key);
  if (!b || b.reset < t) { b = { n: 0, reset: t + windowMs }; buckets.set(key, b); }
  if (++b.n > max) throw new HttpError(429, 'Quá nhiều lần thử. Hãy đợi một lúc rồi thử lại.');
}
setInterval(() => { const t = Date.now(); for (const [k, b] of buckets) if (b.reset < t) buckets.delete(k); db.prepare('DELETE FROM Sessions WHERE expires_at < ?').run(t); }, 600000).unref();

async function hashPw(pw, saltHex) {
  const salt = saltHex ? Buffer.from(saltHex, 'hex') : crypto.randomBytes(16);
  const hash = await scrypt(pw.normalize('NFC'), salt, 64);
  return { salt: salt.toString('hex'), hash: hash.toString('hex') };
}
function checkCreds(username, pw) {
  if (!USERNAME_RE.test(username)) throw new HttpError(400, 'Tên đăng nhập phải gồm 3–24 ký tự: chữ cái, số, dấu chấm, gạch dưới hoặc gạch ngang.');
  if (typeof pw !== 'string' || pw.length < 6) throw new HttpError(400, 'Mật khẩu phải có ít nhất 6 ký tự.');
  if (pw.length > 128) throw new HttpError(400, 'Mật khẩu quá dài (tối đa 128 ký tự).');
}
const fpOf = v => (typeof v === 'string' && /^[a-f0-9]{64}$/.test(v)) ? v : 'unknown';
const publicUser = u => ({ id: u.id, username: u.username, role: u.role, created_at: u.created_at });

async function createUser({ username, password, role, fp, ip, createdBy }) {
  checkCreds(username, password);
  const key = username.toLowerCase();
  if (db.prepare('SELECT 1 FROM Users WHERE username_key = ?').get(key)) throw new HttpError(409, 'Tên đăng nhập này đã được sử dụng.');
  const { salt, hash } = await hashPw(password);
  try {
    const r = db.prepare('INSERT INTO Users (username, username_key, pw_salt, pw_hash, role, device_fp, signup_ip, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(username, key, salt, hash, role, fp, ip, createdBy || null, now());
    return db.prepare('SELECT * FROM Users WHERE id = ?').get(Number(r.lastInsertRowid));
  } catch (e) { throw new HttpError(409, 'Tên đăng nhập này đã được sử dụng.'); }   // race: UNIQUE bắt trùng
}
function logLogin(userId, tried, ok, fp, req) {
  db.prepare('INSERT INTO Login_Logs (user_id, username_tried, success, logged_at, device_fp, ip, user_agent) VALUES (?,?,?,?,?,?,?)')
    .run(userId, String(tried).slice(0, 24), ok ? 1 : 0, now(), fp, ipOf(req), String(req.headers['user-agent'] || '').slice(0, 300));
}
function startSession(res, userId, remember) {
  const token = crypto.randomBytes(32).toString('base64url');
  const ttl = SESSION_DAYS * 86400000;
  db.prepare('INSERT INTO Sessions (token_hash, user_id, expires_at) VALUES (?,?,?)').run(sha(token), userId, Date.now() + ttl);
  return `sid=${token}; HttpOnly; SameSite=Strict; Path=/${COOKIE_SECURE ? '; Secure' : ''}${remember ? `; Max-Age=${ttl / 1000}` : ''}`;
}
function sessionUser(req) {
  const m = /(?:^|;\s*)sid=([\w-]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const row = db.prepare('SELECT u.*, s.expires_at FROM Sessions s JOIN Users u ON u.id = s.user_id WHERE s.token_hash = ?').get(sha(m[1]));
  if (!row || row.expires_at < Date.now()) return null;
  return row;
}
const requireAdmin = req => {                     // phân quyền kiểm tra Ở MÁY CHỦ, không tin giao diện
  const u = sessionUser(req);
  if (!u) throw new HttpError(401, 'Chưa đăng nhập.');
  if (u.role !== 'Admin') throw new HttpError(403, 'Bạn không có quyền truy cập.');
  return u;
};

// ---------- API ----------
const routes = {
  'POST /api/register': async (req, res) => {
    const ip = ipOf(req); limit('reg:' + ip, 10, 3600000);
    const b = await readJson(req); const fp = fpOf(b.device_fp);
    // Cố ý bỏ qua b.role: đăng ký công khai luôn là 'User'
    const user = await createUser({ username: String(b.username || '').trim(), password: b.password, role: 'User', fp, ip });
    logLogin(user.id, user.username, true, fp, req);
    send(res, 201, { user: publicUser(user) }, { 'Set-Cookie': startSession(res, user.id, true) });
  },
  'POST /api/login': async (req, res) => {
    const ip = ipOf(req); const b = await readJson(req); const fp = fpOf(b.device_fp);
    const username = String(b.username || '').trim();
    limit('login:' + ip, 20, 900000); limit('loginu:' + username.toLowerCase(), 10, 900000);
    const u = db.prepare('SELECT * FROM Users WHERE username_key = ?').get(username.toLowerCase());
    const { hash } = await hashPw(String(b.password || ''), u ? u.pw_salt : '00'.repeat(16));   // luôn băm → thời gian đồng đều
    const ok = u && hash.length === u.pw_hash.length && crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(u.pw_hash));
    logLogin(ok ? u.id : (u ? u.id : null), username, !!ok, fp, req);
    if (!ok) throw new HttpError(401, 'Sai tên đăng nhập hoặc mật khẩu.');
    send(res, 200, { user: publicUser(u) }, { 'Set-Cookie': startSession(res, u.id, b.remember !== false) });
  },
  'POST /api/logout': async (req, res) => {
    const m = /(?:^|;\s*)sid=([\w-]+)/.exec(req.headers.cookie || '');
    if (m) db.prepare('DELETE FROM Sessions WHERE token_hash = ?').run(sha(m[1]));
    send(res, 200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
  },
  'GET /api/me': async (req, res) => { const u = sessionUser(req); send(res, 200, { user: u ? publicUser(u) : null }); },

  'GET /api/admin/devices': async (req, res) => {
    requireAdmin(req);
    const rows = db.prepare(`
      WITH fps AS (SELECT device_fp FROM Users UNION SELECT device_fp FROM Login_Logs)
      SELECT f.device_fp,
        (SELECT COUNT(*) FROM Users u WHERE u.device_fp = f.device_fp) AS accounts_created,
        (SELECT COUNT(*) FROM Login_Logs l WHERE l.device_fp = f.device_fp AND l.success = 1) AS login_count,
        (SELECT MAX(logged_at) FROM Login_Logs l WHERE l.device_fp = f.device_fp) AS last_seen,
        (SELECT group_concat(ip, ', ') FROM (SELECT ip FROM Login_Logs WHERE device_fp = f.device_fp AND ip IS NOT NULL
           UNION SELECT signup_ip FROM Users WHERE device_fp = f.device_fp AND signup_ip IS NOT NULL)) AS ips
      FROM fps f ORDER BY accounts_created DESC, last_seen DESC LIMIT 500`).all();
    send(res, 200, { devices: rows });
  },
  'GET /api/admin/logs': async (req, res, url) => {
    requireAdmin(req);
    const limitN = Math.min(Math.max(parseInt(url.searchParams.get('limit')) || 50, 1), 200);
    const offset = Math.max(parseInt(url.searchParams.get('offset')) || 0, 0);
    const logs = db.prepare(`SELECT l.id, l.logged_at, l.user_id, COALESCE(u.username, l.username_tried) AS username, u.role,
        l.success, l.device_fp, l.ip, l.user_agent FROM Login_Logs l LEFT JOIN Users u ON u.id = l.user_id
        ORDER BY l.id DESC LIMIT ? OFFSET ?`).all(limitN, offset);
    send(res, 200, { logs, total: db.prepare('SELECT COUNT(*) c FROM Login_Logs').get().c });
  },
  'POST /api/admin/admins': async (req, res) => {
    const admin = requireAdmin(req);
    const b = await readJson(req);
    const user = await createUser({ username: String(b.username || '').trim(), password: b.password, role: 'Admin', fp: 'admin-created', ip: ipOf(req), createdBy: admin.id });
    send(res, 201, { user: publicUser(user) });
  }
};

const INDEX = path.join(__dirname, 'public', 'index.html');
http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' });
      return fs.createReadStream(INDEX).pipe(res);
    }
    const h = routes[req.method + ' ' + url.pathname];
    if (!h) throw new HttpError(404, 'Không tìm thấy.');
    if (req.method === 'POST') {   // chống CSRF: Origin (nếu có) phải trùng Host, cộng SameSite=Strict
      const o = req.headers.origin;
      if (o && new URL(o).host !== req.headers.host) throw new HttpError(403, 'Origin không hợp lệ.');
    }
    await h(req, res, url);
  } catch (e) {
    if (!(e instanceof HttpError)) console.error(e);
    if (!res.headersSent) send(res, e.status || 500, { error: e instanceof HttpError ? e.message : 'Lỗi máy chủ.' });
  }
}).listen(PORT, () => console.log(`http://localhost:${PORT}`));

// ---------- Tạo Admin đầu tiên (chạy một lần khi chưa có Admin nào) ----------
(async () => {
  if (db.prepare("SELECT 1 FROM Users WHERE role = 'Admin'").get()) return;
  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  try {
    await createUser({ username, password, role: 'Admin', fp: 'seed', ip: null });
    console.log(`[SEED] Đã tạo Admin đầu tiên → tên: ${username}${process.env.ADMIN_PASSWORD ? '' : '  mật khẩu: ' + password}\n       Hãy đăng nhập và tạo Admin riêng, rồi đổi/ẩn tài khoản seed.`);
  } catch (e) { console.error('[SEED] Không tạo được Admin đầu tiên:', e.message); }
})();
