require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || SECRET.length < 16) {
  console.error('Isi JWT_SECRET (minimal 16 karakter) di file .env');
  process.exit(1);
}

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME || 'tangga_pintar',
  waitForConnections: true,
  connectionLimit: 10,
  charset: 'utf8mb4',
});

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const GR = ['12', '34', '56'];
const SUB = ['mtk', 'indo', 'ipa', 'ips', 'ing', 'pkn'];
const str = (v, max) => (typeof v === 'string' && v.trim().length > 0 && v.trim().length <= max ? v.trim() : null);
const bad = (res, msg) => res.status(400).json({ error: msg });
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: 'Kesalahan server' });
  });

function auth(req, res, next) {
  try {
    jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Tidak diizinkan, silakan login guru lagi' });
  }
}

/* ---------- STATE (siswa + soal + statistik) ---------- */
app.get('/api/state', wrap(async (req, res) => {
  const [st] = await pool.query('SELECT id, name, grade FROM students ORDER BY name');
  const [gm] = await pool.query('SELECT student_id, COUNT(*) g, SUM(won) w FROM games GROUP BY student_id');
  const [an] = await pool.query('SELECT student_id, subject, COUNT(*) n, SUM(correct) c FROM answers GROUP BY student_id, subject');
  const [qs] = await pool.query('SELECT id, subject, grade, question, options, answer_idx, explanation FROM questions ORDER BY id DESC');
  const map = {};
  const students = st.map((s) => (map[s.id] = { id: String(s.id), name: s.name, kelas: s.grade, st: { g: 0, w: 0, n: 0, c: 0, by: {} } }));
  gm.forEach((r) => { const s = map[r.student_id]; if (s) { s.st.g = +r.g; s.st.w = +r.w; } });
  an.forEach((r) => {
    const s = map[r.student_id];
    if (s) { s.st.by[r.subject] = { n: +r.n, c: +r.c }; s.st.n += +r.n; s.st.c += +r.c; }
  });
  res.json({
    students,
    qs: qs.map((q) => ({
      id: String(q.id), m: q.subject, k: q.grade, q: q.question,
      o: typeof q.options === 'string' ? JSON.parse(q.options) : q.options,
      a: q.answer_idx, e: q.explanation,
    })),
  });
}));

/* ---------- GURU: login & PIN ---------- */
const tries = new Map();
app.post('/api/teacher/login', wrap(async (req, res) => {
  const now = Date.now();
  const t = (tries.get(req.ip) || []).filter((x) => now - x < 60000);
  if (t.length >= 5) return res.status(429).json({ error: 'Terlalu banyak percobaan, tunggu 1 menit' });
  const [[row]] = await pool.query("SELECT v FROM settings WHERE k = 'pin_hash'");
  const ok = row && typeof req.body.pin === 'string' && (await bcrypt.compare(req.body.pin, row.v));
  if (!ok) { t.push(now); tries.set(req.ip, t); return res.status(401).json({ error: 'PIN salah' }); }
  tries.delete(req.ip);
  res.json({ token: jwt.sign({ role: 'teacher' }, SECRET, { expiresIn: '8h' }) });
}));

app.put('/api/teacher/pin', auth, wrap(async (req, res) => {
  const pin = str(req.body.pin, 32);
  if (!pin || pin.length < 4) return bad(res, 'PIN minimal 4 karakter');
  await pool.query("REPLACE INTO settings (k, v) VALUES ('pin_hash', ?)", [await bcrypt.hash(pin, 10)]);
  res.json({ ok: true });
}));

/* ---------- SISWA ---------- */
// Pendaftaran terbuka agar siswa bisa mendaftar sendiri.
app.post('/api/students', wrap(async (req, res) => {
  const name = str(req.body.name, 16);
  if (!name || !GR.includes(req.body.kelas)) return bad(res, 'Data tidak valid');
  const [r] = await pool.query('INSERT INTO students (name, grade) VALUES (?, ?)', [name, req.body.kelas]);
  res.json({ id: String(r.insertId) });
}));

app.delete('/api/students/:id', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM students WHERE id = ?', [Number(req.params.id)]);
  res.json({ ok: true });
}));

app.post('/api/students/:id/reset', auth, wrap(async (req, res) => {
  const id = Number(req.params.id);
  await pool.query('DELETE FROM answers WHERE student_id = ?', [id]);
  await pool.query('DELETE FROM games WHERE student_id = ?', [id]);
  res.json({ ok: true });
}));

/* ---------- SOAL (khusus guru) ---------- */
app.post('/api/questions', auth, wrap(async (req, res) => {
  const { m, k, a } = req.body;
  const q = str(req.body.q, 255);
  const o = Array.isArray(req.body.o) ? req.body.o.map((x) => str(x, 100)) : [];
  const e = typeof req.body.e === 'string' ? req.body.e.trim().slice(0, 255) : '';
  if (!SUB.includes(m) || !GR.includes(k) || !q || o.length !== 3 || o.some((x) => !x) || ![0, 1, 2].includes(a)) {
    return bad(res, 'Data soal tidak valid');
  }
  const [r] = await pool.query(
    'INSERT INTO questions (subject, grade, question, options, answer_idx, explanation) VALUES (?, ?, ?, ?, ?, ?)',
    [m, k, q, JSON.stringify(o), a, e]
  );
  res.json({ id: String(r.insertId) });
}));

app.delete('/api/questions/:id', auth, wrap(async (req, res) => {
  await pool.query('DELETE FROM questions WHERE id = ?', [Number(req.params.id)]);
  res.json({ ok: true });
}));

/* ---------- CATATAN BERMAIN ---------- */
app.post('/api/answers', wrap(async (req, res) => {
  const sid = Number(req.body.studentId);
  const qid = req.body.questionId ? Number(req.body.questionId) : null;
  if (!sid || !SUB.includes(req.body.subject)) return bad(res, 'Data tidak valid');
  try {
    await pool.query('INSERT INTO answers (student_id, question_id, subject, correct) VALUES (?, ?, ?, ?)', [sid, qid, req.body.subject, req.body.correct ? 1 : 0]);
  } catch (e) {
    if (e.code === 'ER_NO_REFERENCED_ROW_2') {
      await pool.query('INSERT INTO answers (student_id, question_id, subject, correct) VALUES (?, NULL, ?, ?)', [sid, req.body.subject, req.body.correct ? 1 : 0]).catch(() => {});
    } else throw e;
  }
  res.json({ ok: true });
}));

app.post('/api/games', wrap(async (req, res) => {
  const sid = Number(req.body.studentId);
  if (!sid) return bad(res, 'Data tidak valid');
  await pool.query('INSERT INTO games (student_id, won) VALUES (?, ?)', [sid, req.body.won ? 1 : 0]).catch(() => {});
  res.json({ ok: true });
}));

/* ---------- START ---------- */
const PORT = process.env.PORT || 3000;
(async () => {
  await pool.query('SELECT 1');
  const [[row]] = await pool.query("SELECT v FROM settings WHERE k = 'pin_hash'");
  if (!row) {
    const h = await bcrypt.hash(process.env.TEACHER_PIN || '1234', 10);
    await pool.query("INSERT INTO settings (k, v) VALUES ('pin_hash', ?)", [h]);
  }
  app.listen(PORT, () => console.log('Tangga Pintar berjalan di http://localhost:' + PORT));
})().catch((e) => {
  console.error('Gagal terhubung ke MySQL:', e.message);
  process.exit(1);
});
