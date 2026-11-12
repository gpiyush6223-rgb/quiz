// Online Quiz App - zero-dependency server (Node 22.5+)
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { db, hashPassword, verifyPassword, audit, closeDb } = require('./db');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------- secret + tokens ----------
const SECRET = process.env.JWT_SECRET;
if (!SECRET) {
  throw new Error('JWT_SECRET is missing');
}
const b64 = (b) => Buffer.from(b).toString('base64url');
function signToken(payload) {
  const body = b64(JSON.stringify(payload));
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(expect);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (p.exp < Date.now()) return null;
    return p;
  } catch { return null; }
}

// ---------- helpers ----------
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = (m) => new HttpError(400, m);
const nowISO = () => new Date().toISOString();
const json = (res, status, data) => {
  const s = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(s);
};
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role, roll_no: u.roll_no, department: u.department, status: u.status, created_at: u.created_at });
const parseJSON = (s, fallback) => { try { return JSON.parse(s); } catch { return fallback; } };

// tiny login rate limiter
const loginFails = new Map();
function checkRate(key) {
  const e = loginFails.get(key);
  if (e && e.until > Date.now()) throw new HttpError(429, 'Too many failed attempts. Try again in a few minutes.');
}
function noteFail(key) {
  const e = loginFails.get(key) || { n: 0, until: 0 };
  e.n += 1;
  if (e.n >= 8) { e.until = Date.now() + 5 * 60 * 1000; e.n = 0; }
  loginFails.set(key, e);
}

// seeded shuffle so a student sees the same order after a refresh
function rng(seed) { let a = seed >>> 0; return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
function shuffle(arr, seed) { const r = rng(seed), a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(r() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

// ---------- grading ----------
function gradeQuestion(q, quiz, answer) {
  const correct = parseJSON(q.correct, []);
  const answered = answer !== undefined && answer !== null && answer !== '' && !(Array.isArray(answer) && answer.length === 0);
  if (!answered) return { awarded: 0, status: 'unanswered' };
  let ok = false;
  if (q.type === 'single' || q.type === 'truefalse') ok = Number(answer) === Number(correct[0]);
  else if (q.type === 'multiple') {
    const a = [...new Set((Array.isArray(answer) ? answer : []).map(Number))].sort();
    const c = [...new Set(correct.map(Number))].sort();
    ok = a.length === c.length && a.every((v, i) => v === c[i]);
  } else if (q.type === 'text') {
    const norm = (s) => String(s).trim().toLowerCase().replace(/\s+/g, ' ');
    ok = correct.some((c) => norm(c) === norm(answer));
  }
  return ok ? { awarded: q.marks, status: 'correct' } : { awarded: -q.marks * quiz.negative_marking, status: 'wrong' };
}
function gradeAttempt(attempt, quiz) {
  const questions = db.prepare('SELECT * FROM questions WHERE quiz_id=?').all(quiz.id);
  const answers = parseJSON(attempt.answers, {});
  let score = 0, total = 0;
  for (const q of questions) { total += q.marks; score += gradeQuestion(q, quiz, answers[q.id]).awarded; }
  return { score: Math.max(0, score + (attempt.manual_adjust || 0)), total };
}

// ---------- attempt lifecycle ----------
function deadlineOf(attempt, quiz) {
  let d = new Date(attempt.started_at).getTime() + quiz.duration_min * 60000;
  if (quiz.end_time) d = Math.min(d, new Date(quiz.end_time).getTime());
  return d;
}
function finalize(attempt, quiz, status, reason) {
  const { score, total } = gradeAttempt(attempt, quiz);
  db.prepare('UPDATE attempts SET status=?, submit_reason=?, submitted_at=?, score=?, total=? WHERE id=? AND status=\'in_progress\'')
    .run(status, reason, nowISO(), score, total, attempt.id);
  return db.prepare('SELECT * FROM attempts WHERE id=?').get(attempt.id);
}
function expireIfNeeded(attempt, quiz) {
  if (attempt.status === 'in_progress' && Date.now() > deadlineOf(attempt, quiz) + 2000) {
    return finalize(attempt, quiz, 'auto_submitted', 'time_up');
  }
  return attempt;
}
const MAX_VIOLATION_LOG_TYPES = ['tab_switch', 'window_blur', 'fullscreen_exit', 'page_exit', 'left_page', 'copy_paste', 'right_click', 'devtools', 'print_screen', 'other'];
function addViolation(attempt, quiz, type, detail) {
  if (!MAX_VIOLATION_LOG_TYPES.includes(type)) type = 'other';
  db.prepare('INSERT INTO violations (attempt_id, type, detail, created_at) VALUES (?,?,?,?)').run(attempt.id, type, String(detail || '').slice(0, 200), nowISO());
  db.prepare('UPDATE attempts SET violations = violations + 1 WHERE id=?').run(attempt.id);
  let fresh = db.prepare('SELECT * FROM attempts WHERE id=?').get(attempt.id);
  if (quiz.max_violations > 0 && fresh.violations >= quiz.max_violations && fresh.status === 'in_progress') {
    fresh = finalize(fresh, quiz, 'auto_submitted', 'violation_limit');
  }
  return fresh;
}

// ---------- CSV ----------
function parseCSV(text) {
  const rows = []; let row = [], cur = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"' && text[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') q = false;
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(cur); cur = ''; if (row.some((x) => x.trim() !== '')) rows.push(row); row = []; }
    else cur += c;
  }
  row.push(cur); if (row.some((x) => x.trim() !== '')) rows.push(row);
  return rows;
}
const csvCell = (v) => { v = v === null || v === undefined ? '' : String(v); return /[",\n\r]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
const toCSV = (rows) => rows.map((r) => r.map(csvCell).join(',')).join('\r\n');

// ---------- question validation ----------
function cleanQuestion(b) {
  const text = String(b.text || '').trim();
  if (!text) throw bad('Question text is required.');
  const type = b.type;
  if (!['single', 'multiple', 'truefalse', 'text'].includes(type)) throw bad('Invalid question type.');
  const marks = Number(b.marks ?? 1);
  if (!(marks > 0)) throw bad('Marks must be greater than 0.');
  let options = [], correct = [];
  if (type === 'truefalse') { options = ['True', 'False']; correct = [Number(Array.isArray(b.correct) ? b.correct[0] : b.correct)]; if (![0, 1].includes(correct[0])) throw bad('True/False needs a correct answer.'); }
  else if (type === 'text') {
    correct = (Array.isArray(b.correct) ? b.correct : String(b.correct || '').split(';')).map((s) => String(s).trim()).filter(Boolean);
    if (!correct.length) throw bad('Add at least one accepted answer.');
  } else {
    options = (b.options || []).map((s) => String(s).trim()).filter(Boolean);
    if (options.length < 2) throw bad('At least 2 options are needed.');
    correct = (Array.isArray(b.correct) ? b.correct : [b.correct]).map(Number).filter((n) => Number.isInteger(n) && n >= 0 && n < options.length);
    if (type === 'single' && correct.length !== 1) throw bad('Single-choice needs exactly one correct option.');
    if (type === 'multiple' && correct.length < 1) throw bad('Select at least one correct option.');
  }
  return { text, type, options, correct, marks, explanation: String(b.explanation || '').trim() };
}
function insertQuestion(quizId, q) {
  const pos = db.prepare('SELECT COALESCE(MAX(position),0)+1 AS p FROM questions WHERE quiz_id=?').get(quizId).p;
  return db.prepare('INSERT INTO questions (quiz_id,text,type,options,correct,marks,explanation,position) VALUES (?,?,?,?,?,?,?,?)')
    .run(quizId, q.text, q.type, JSON.stringify(q.options), JSON.stringify(q.correct), q.marks, q.explanation, pos).lastInsertRowid;
}
function csvRowToQuestion(r) {
  // question,type,opt1,opt2,opt3,opt4,correct,marks,explanation
  const type = (r[1] || '').trim().toLowerCase();
  const opts = [r[2], r[3], r[4], r[5]].map((s) => (s || '').trim()).filter(Boolean);
  const corr = (r[6] || '').trim();
  const letterIdx = (s) => { s = s.trim(); if (/^[a-z]$/i.test(s)) return s.toUpperCase().charCodeAt(0) - 65; if (/^\d+$/.test(s)) return Number(s) - 1; return -1; };
  let correct;
  if (type === 'truefalse') correct = [/^t/i.test(corr) ? 0 : 1];
  else if (type === 'text') correct = corr.split(';');
  else correct = corr.split(/[;|]/).map(letterIdx);
  return cleanQuestion({ text: r[0], type, options: opts, correct, marks: r[7] || 1, explanation: r[8] });
}

// ---------- router ----------
const routes = [];
function route(method, pattern, roles, handler) {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:([a-z_]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
  routes.push({ method, re, keys, roles, handler });
}
const ANY = null;

function getQuizFor(user, id) {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id=?').get(id);
  if (!quiz) throw new HttpError(404, 'Quiz not found.');
  if (user.role === 'faculty' && quiz.faculty_id !== user.id) throw new HttpError(403, 'This quiz belongs to another faculty member.');
  return quiz;
}

// ===== AUTH =====
route('POST', '/api/auth/register', ANY, ({ body }) => {
  const name = String(body.name || '').trim();
  const email = String(body.email || '').trim().toLowerCase();
  const password = String(body.password || '');
  const role = body.role === 'faculty' ? 'faculty' : 'student';
  if (name.length < 2) throw bad('Please enter your name.');
  if (!EMAIL_RE.test(email)) throw bad('Please enter a valid email.');
  if (password.length < 6) throw bad('Password must be at least 6 characters.');
  if (role === 'student' && !String(body.roll_no || '').trim()) throw bad('Roll number is required for students.');
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) throw new HttpError(409, 'An account with this email already exists.');
  const status = role === 'faculty' ? 'pending' : 'active';   // faculty must be approved by admin
  const info = db.prepare('INSERT INTO users (name,email,password_hash,role,roll_no,department,status) VALUES (?,?,?,?,?,?,?)')
    .run(name, email, hashPassword(password), role, String(body.roll_no || '').trim(), String(body.department || '').trim(), status);
  audit(info.lastInsertRowid, 'register', `${role} ${email}`);
  return { ok: true, pending: status === 'pending', message: status === 'pending' ? 'Account created. An admin must approve your faculty account before you can log in.' : 'Account created. You can log in now.' };
});

route('POST', '/api/auth/login', ANY, ({ body, req }) => {
  const email = String(body.email || '').trim().toLowerCase();
  const key = req.socket.remoteAddress + '|' + email;
  checkRate(key);
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !verifyPassword(String(body.password || ''), u.password_hash)) { noteFail(key); throw new HttpError(401, 'Wrong email or password.'); }
  if (body.role && body.role !== u.role) throw new HttpError(403, `This account is a ${u.role} account. Use the ${u.role} login.`);
  if (u.status === 'pending') throw new HttpError(403, 'Your account is waiting for admin approval.');
  if (u.status === 'blocked') throw new HttpError(403, 'Your account has been blocked. Contact the admin.');
  loginFails.delete(key);
  audit(u.id, 'login', u.role);
  return { token: signToken({ id: u.id, role: u.role, exp: Date.now() + 12 * 3600 * 1000 }), user: publicUser(u) };
});

route('GET', '/api/me', ['student', 'faculty', 'admin'], ({ user }) => ({ user: publicUser(user) }));

route('POST', '/api/me/password', ['student', 'faculty', 'admin'], ({ user, body }) => {
  if (!verifyPassword(String(body.current || ''), user.password_hash)) throw bad('Current password is wrong.');
  if (String(body.next || '').length < 6) throw bad('New password must be at least 6 characters.');
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(body.next), user.id);
  audit(user.id, 'password_change');
  return { ok: true };
});

// ===== ANNOUNCEMENTS =====
route('GET', '/api/announcements', ['student', 'faculty', 'admin'], () =>
  db.prepare('SELECT a.id,a.title,a.body,a.created_at,a.author_id,u.name AS author FROM announcements a JOIN users u ON u.id=a.author_id ORDER BY a.id DESC LIMIT 20').all());
route('POST', '/api/announcements', ['faculty', 'admin'], ({ user, body }) => {
  const title = String(body.title || '').trim(), text = String(body.body || '').trim();
  if (!title || !text) throw bad('Title and message are required.');
  db.prepare('INSERT INTO announcements (author_id,title,body,created_at) VALUES (?,?,?,?)').run(user.id, title, text, nowISO());
  return { ok: true };
});
route('DELETE', '/api/announcements/:id', ['faculty', 'admin'], ({ user, params }) => {
  const a = db.prepare('SELECT * FROM announcements WHERE id=?').get(params.id);
  if (!a) throw new HttpError(404, 'Not found.');
  if (user.role !== 'admin' && a.author_id !== user.id) throw new HttpError(403, 'Not yours.');
  db.prepare('DELETE FROM announcements WHERE id=?').run(a.id);
  return { ok: true };
});

// ===== STUDENT =====
route('GET', '/api/student/quizzes', ['student'], ({ user }) => {
  const rows = db.prepare(`
    SELECT q.id,q.title,q.description,q.subject,q.duration_min,q.start_time,q.end_time,q.max_violations,q.access_code,q.show_result,q.pass_percent,
           u.name AS faculty, (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS question_count,
           (SELECT COALESCE(SUM(marks),0) FROM questions WHERE quiz_id=q.id) AS total_marks,
           a.id AS attempt_id, a.status AS attempt_status, a.score, a.total
    FROM quizzes q JOIN users u ON u.id=q.faculty_id
    LEFT JOIN attempts a ON a.quiz_id=q.id AND a.student_id=?
    WHERE q.published=1 ORDER BY q.id DESC`).all(user.id);
  const now = Date.now();
  return rows.map((r) => {
    let state = 'open';
    if (r.attempt_status === 'in_progress') {
      const quiz = db.prepare('SELECT * FROM quizzes WHERE id=?').get(r.id);
      const att = expireIfNeeded(db.prepare('SELECT * FROM attempts WHERE id=?').get(r.attempt_id), quiz);
      r.attempt_status = att.status; r.score = att.score; r.total = att.total;
    }
    if (r.attempt_status === 'in_progress') state = 'in_progress';
    else if (r.attempt_status) state = 'done';
    else if (r.start_time && now < new Date(r.start_time).getTime()) state = 'upcoming';
    else if (r.end_time && now > new Date(r.end_time).getTime()) state = 'closed';
    if (r.attempt_status && !r.show_result) { r.score = null; r.total = null; }
    const needs_code = !!r.access_code; delete r.access_code;
    return { ...r, state, needs_code };
  });
});

route('POST', '/api/student/quizzes/:id/start', ['student'], ({ user, params, body }) => {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id=? AND published=1').get(params.id);
  if (!quiz) throw new HttpError(404, 'Quiz not available.');
  let attempt = db.prepare('SELECT * FROM attempts WHERE quiz_id=? AND student_id=?').get(quiz.id, user.id);
  if (attempt) {
    attempt = expireIfNeeded(attempt, quiz);
    if (attempt.status !== 'in_progress') throw new HttpError(409, 'You have already submitted this quiz.');
    return { attempt_id: attempt.id, resumed: true };
  }
  const now = Date.now();
  if (quiz.start_time && now < new Date(quiz.start_time).getTime()) throw new HttpError(403, 'This quiz has not started yet.');
  if (quiz.end_time && now > new Date(quiz.end_time).getTime()) throw new HttpError(403, 'This quiz is closed.');
  if (quiz.access_code && String(body.access_code || '').trim() !== quiz.access_code) throw new HttpError(403, 'Wrong access code.');
  const count = db.prepare('SELECT COUNT(*) AS c FROM questions WHERE quiz_id=?').get(quiz.id).c;
  if (!count) throw new HttpError(409, 'This quiz has no questions yet.');
  const info = db.prepare('INSERT INTO attempts (quiz_id,student_id,started_at,last_seen,seed) VALUES (?,?,?,?,?)')
    .run(quiz.id, user.id, nowISO(), nowISO(), crypto.randomInt(1, 2 ** 31 - 1));
  return { attempt_id: Number(info.lastInsertRowid), resumed: false };
});

function getOwnAttempt(user, id) {
  const attempt = db.prepare('SELECT * FROM attempts WHERE id=? AND student_id=?').get(id, user.id);
  if (!attempt) throw new HttpError(404, 'Attempt not found.');
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id=?').get(attempt.quiz_id);
  return { attempt: expireIfNeeded(attempt, quiz), quiz };
}

route('GET', '/api/student/attempts/:id', ['student'], ({ user, params, query }) => {
  let { attempt, quiz } = getOwnAttempt(user, params.id);
  if (attempt.status !== 'in_progress') return { finished: true, status: attempt.status, reason: attempt.submit_reason };
  // Detect leaving the page / closing the browser: no heartbeat for a while, and the client did not report it
  if (query.resume === '1' && attempt.last_seen && Date.now() - new Date(attempt.last_seen).getTime() > 25000) {
    const reported = db.prepare("SELECT COUNT(*) AS c FROM violations WHERE attempt_id=? AND type='page_exit' AND created_at >= ?").get(attempt.id, attempt.last_seen).c;
    if (!reported) {
      const mins = Math.round((Date.now() - new Date(attempt.last_seen).getTime()) / 1000);
      attempt = addViolation(attempt, quiz, 'left_page', `Page was closed/reloaded for ~${mins}s`);
      if (attempt.status !== 'in_progress') return { finished: true, status: attempt.status, reason: attempt.submit_reason };
    }
  }
  db.prepare('UPDATE attempts SET last_seen=? WHERE id=?').run(nowISO(), attempt.id);
  let qs = db.prepare('SELECT * FROM questions WHERE quiz_id=? ORDER BY position, id').all(quiz.id);
  if (quiz.shuffle_questions) qs = shuffle(qs, attempt.seed);
  const questions = qs.map((q) => {
    let options = parseJSON(q.options, []).map((text, i) => ({ i, text }));
    if (quiz.shuffle_options && q.type !== 'truefalse') options = shuffle(options, attempt.seed + q.id);
    return { id: q.id, text: q.text, type: q.type, marks: q.marks, options };
  });
  return {
    finished: false,
    quiz: { id: quiz.id, title: quiz.title, subject: quiz.subject, duration_min: quiz.duration_min, max_violations: quiz.max_violations, negative_marking: quiz.negative_marking },
    questions,
    answers: parseJSON(attempt.answers, {}),
    violations: attempt.violations,
    remaining_seconds: Math.max(0, Math.floor((deadlineOf(attempt, quiz) - Date.now()) / 1000)),
  };
});

route('PUT', '/api/student/attempts/:id/answer', ['student'], ({ user, params, body }) => {
  const { attempt } = getOwnAttempt(user, params.id);
  if (attempt.status !== 'in_progress') throw new HttpError(409, 'Quiz already submitted.');
  const q = db.prepare('SELECT id FROM questions WHERE id=? AND quiz_id=?').get(body.question_id, attempt.quiz_id);
  if (!q) throw bad('Unknown question.');
  const answers = parseJSON(attempt.answers, {});
  if (body.answer === null || body.answer === '' || (Array.isArray(body.answer) && !body.answer.length)) delete answers[q.id];
  else answers[q.id] = body.answer;
  db.prepare('UPDATE attempts SET answers=?, last_seen=? WHERE id=?').run(JSON.stringify(answers), nowISO(), attempt.id);
  return { ok: true };
});

route('POST', '/api/student/attempts/:id/heartbeat', ['student'], ({ user, params }) => {
  const { attempt } = getOwnAttempt(user, params.id);
  if (attempt.status !== 'in_progress') return { finished: true, status: attempt.status, reason: attempt.submit_reason };
  db.prepare('UPDATE attempts SET last_seen=? WHERE id=?').run(nowISO(), attempt.id);
  return { finished: false, violations: attempt.violations };
});

route('POST', '/api/student/attempts/:id/violation', ['student'], ({ user, params, body }) => {
  const { attempt, quiz } = getOwnAttempt(user, params.id);
  if (attempt.status !== 'in_progress') return { finished: true, status: attempt.status, reason: attempt.submit_reason, violations: attempt.violations };
  const fresh = addViolation(attempt, quiz, String(body.type || 'other'), body.detail);
  return { finished: fresh.status !== 'in_progress', status: fresh.status, reason: fresh.submit_reason, violations: fresh.violations, max_violations: quiz.max_violations };
});

route('POST', '/api/student/attempts/:id/submit', ['student'], ({ user, params, body }) => {
  const { attempt, quiz } = getOwnAttempt(user, params.id);
  if (attempt.status === 'in_progress') {
    if (body && body.answers && typeof body.answers === 'object') {
      const valid = new Set(db.prepare('SELECT id FROM questions WHERE quiz_id=?').all(quiz.id).map((r) => String(r.id)));
      const merged = parseJSON(attempt.answers, {});
      for (const [k, v] of Object.entries(body.answers)) if (valid.has(k)) merged[k] = v;
      db.prepare('UPDATE attempts SET answers=? WHERE id=?').run(JSON.stringify(merged), attempt.id);
      attempt.answers = JSON.stringify(merged);
    }
    finalize(attempt, quiz, 'submitted', 'student');
  }
  return { ok: true };
});

route('GET', '/api/student/attempts/:id/result', ['student'], ({ user, params }) => {
  const { attempt, quiz } = getOwnAttempt(user, params.id);
  if (attempt.status === 'in_progress') throw new HttpError(409, 'Quiz not submitted yet.');
  const out = { title: quiz.title, status: attempt.status, reason: attempt.submit_reason, violations: attempt.violations, submitted_at: attempt.submitted_at, show_result: !!quiz.show_result, pass_percent: quiz.pass_percent };
  if (quiz.show_result) {
    out.score = attempt.score; out.total = attempt.total;
    out.percent = attempt.total ? Math.round((attempt.score / attempt.total) * 1000) / 10 : 0;
    out.passed = out.percent >= quiz.pass_percent;
    const answers = parseJSON(attempt.answers, {});
    out.review = db.prepare('SELECT * FROM questions WHERE quiz_id=? ORDER BY position,id').all(quiz.id).map((q) => {
      const g = gradeQuestion(q, quiz, answers[q.id]);
      return { text: q.text, type: q.type, options: parseJSON(q.options, []), your_answer: answers[q.id] ?? null, correct: parseJSON(q.correct, []), status: g.status, awarded: g.awarded, marks: q.marks, explanation: q.explanation };
    });
  }
  return out;
});

route('GET', '/api/student/history', ['student'], ({ user }) =>
  db.prepare(`SELECT a.id, q.title, q.subject, a.status, a.score, a.total, a.violations, a.submitted_at, q.show_result
              FROM attempts a JOIN quizzes q ON q.id=a.quiz_id WHERE a.student_id=? AND a.status!='in_progress' ORDER BY a.id DESC`).all(user.id)
    .map((r) => (r.show_result ? r : { ...r, score: null, total: null })));

// ===== FACULTY =====
route('GET', '/api/faculty/quizzes', ['faculty'], ({ user }) =>
  db.prepare(`SELECT q.*, (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS question_count,
              (SELECT COUNT(*) FROM attempts WHERE quiz_id=q.id AND status!='in_progress') AS submissions,
              (SELECT COUNT(*) FROM attempts WHERE quiz_id=q.id AND status='in_progress') AS in_progress,
              (SELECT COALESCE(SUM(violations),0) FROM attempts WHERE quiz_id=q.id) AS total_violations
              FROM quizzes q WHERE faculty_id=? ORDER BY id DESC`).all(user.id));

function cleanQuiz(b) {
  const title = String(b.title || '').trim();
  if (!title) throw bad('Quiz title is required.');
  const duration = Number(b.duration_min);
  if (!(duration >= 1 && duration <= 600)) throw bad('Duration must be 1-600 minutes.');
  const iso = (v) => { if (!v) return null; const d = new Date(v); if (isNaN(d)) throw bad('Invalid date.'); return d.toISOString(); };
  const start = iso(b.start_time), end = iso(b.end_time);
  if (start && end && new Date(end) <= new Date(start)) throw bad('End time must be after start time.');
  return {
    title, description: String(b.description || '').trim(), subject: String(b.subject || '').trim(), duration_min: Math.round(duration),
    start_time: start, end_time: end, max_violations: Math.max(0, Math.round(Number(b.max_violations ?? 5))),
    shuffle_questions: b.shuffle_questions ? 1 : 0, shuffle_options: b.shuffle_options ? 1 : 0, show_result: b.show_result === false || b.show_result === 0 ? 0 : 1,
    negative_marking: Math.min(1, Math.max(0, Number(b.negative_marking || 0))), pass_percent: Math.min(100, Math.max(0, Math.round(Number(b.pass_percent ?? 40)))),
    access_code: String(b.access_code || '').trim(),
  };
}

route('POST', '/api/faculty/quizzes', ['faculty'], ({ user, body }) => {
  const q = cleanQuiz(body);
  const info = db.prepare(`INSERT INTO quizzes (faculty_id,title,description,subject,duration_min,start_time,end_time,max_violations,shuffle_questions,shuffle_options,show_result,negative_marking,pass_percent,access_code)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(user.id, q.title, q.description, q.subject, q.duration_min, q.start_time, q.end_time, q.max_violations, q.shuffle_questions, q.shuffle_options, q.show_result, q.negative_marking, q.pass_percent, q.access_code);
  return { id: Number(info.lastInsertRowid) };
});

route('GET', '/api/faculty/quizzes/:id', ['faculty'], ({ user, params }) => {
  const quiz = getQuizFor(user, params.id);
  const questions = db.prepare('SELECT * FROM questions WHERE quiz_id=? ORDER BY position,id').all(quiz.id).map((q) => ({ ...q, options: parseJSON(q.options, []), correct: parseJSON(q.correct, []) }));
  return { quiz, questions };
});

route('PUT', '/api/faculty/quizzes/:id', ['faculty'], ({ user, params, body }) => {
  const quiz = getQuizFor(user, params.id);
  const q = cleanQuiz(body);
  db.prepare(`UPDATE quizzes SET title=?,description=?,subject=?,duration_min=?,start_time=?,end_time=?,max_violations=?,shuffle_questions=?,shuffle_options=?,show_result=?,negative_marking=?,pass_percent=?,access_code=? WHERE id=?`)
    .run(q.title, q.description, q.subject, q.duration_min, q.start_time, q.end_time, q.max_violations, q.shuffle_questions, q.shuffle_options, q.show_result, q.negative_marking, q.pass_percent, q.access_code, quiz.id);
  return { ok: true };
});

route('POST', '/api/faculty/quizzes/:id/publish', ['faculty'], ({ user, params, body }) => {
  const quiz = getQuizFor(user, params.id);
  const publish = body.published ? 1 : 0;
  if (publish && !db.prepare('SELECT COUNT(*) AS c FROM questions WHERE quiz_id=?').get(quiz.id).c) throw bad('Add at least one question before publishing.');
  db.prepare('UPDATE quizzes SET published=? WHERE id=?').run(publish, quiz.id);
  return { published: publish };
});

route('POST', '/api/faculty/quizzes/:id/duplicate', ['faculty'], ({ user, params }) => {
  const quiz = getQuizFor(user, params.id);
  const info = db.prepare(`INSERT INTO quizzes (faculty_id,title,description,subject,duration_min,start_time,end_time,max_violations,shuffle_questions,shuffle_options,show_result,negative_marking,pass_percent,access_code,published)
    VALUES (?,?,?,?,?,NULL,NULL,?,?,?,?,?,?,?,0)`).run(user.id, quiz.title + ' (copy)', quiz.description, quiz.subject, quiz.duration_min, quiz.max_violations, quiz.shuffle_questions, quiz.shuffle_options, quiz.show_result, quiz.negative_marking, quiz.pass_percent, quiz.access_code);
  db.prepare('INSERT INTO questions (quiz_id,text,type,options,correct,marks,explanation,position) SELECT ?,text,type,options,correct,marks,explanation,position FROM questions WHERE quiz_id=?').run(info.lastInsertRowid, quiz.id);
  return { id: Number(info.lastInsertRowid) };
});

route('DELETE', '/api/faculty/quizzes/:id', ['faculty'], ({ user, params }) => {
  const quiz = getQuizFor(user, params.id);
  db.prepare('DELETE FROM quizzes WHERE id=?').run(quiz.id);
  audit(user.id, 'quiz_delete', quiz.title);
  return { ok: true };
});

function assertEditable(quiz) {
  const n = db.prepare('SELECT COUNT(*) AS c FROM attempts WHERE quiz_id=?').get(quiz.id).c;
  if (n) throw new HttpError(409, 'Students have already started this quiz, so questions are locked. Duplicate the quiz to make changes.');
}

route('POST', '/api/faculty/quizzes/:id/questions', ['faculty'], ({ user, params, body }) => {
  const quiz = getQuizFor(user, params.id); assertEditable(quiz);
  return { id: Number(insertQuestion(quiz.id, cleanQuestion(body))) };
});

route('POST', '/api/faculty/quizzes/:id/questions/bulk', ['faculty'], ({ user, params, body }) => {
  const quiz = getQuizFor(user, params.id); assertEditable(quiz);
  let items = [];
  if (body.format === 'csv') {
    const rows = parseCSV(String(body.data || ''));
    if (rows.length && /^question$/i.test((rows[0][0] || '').trim())) rows.shift();   // skip header
    items = rows.map((r, i) => { try { return csvRowToQuestion(r); } catch (e) { throw bad(`Row ${i + 1}: ${e.message}`); } });
  } else {
    const arr = typeof body.data === 'string' ? parseJSON(body.data, null) : body.data;
    if (!Array.isArray(arr)) throw bad('JSON must be an array of questions.');
    items = arr.map((q, i) => { try { return cleanQuestion(q); } catch (e) { throw bad(`Question ${i + 1}: ${e.message}`); } });
  }
  if (!items.length) throw bad('No questions found in the upload.');
  db.exec('BEGIN');
  try { items.forEach((q) => insertQuestion(quiz.id, q)); db.exec('COMMIT'); } catch (e) { db.exec('ROLLBACK'); throw e; }
  return { added: items.length };
});

function getQuestionFor(user, id) {
  const q = db.prepare('SELECT * FROM questions WHERE id=?').get(id);
  if (!q) throw new HttpError(404, 'Question not found.');
  return { q, quiz: getQuizFor(user, q.quiz_id) };
}
route('PUT', '/api/faculty/questions/:id', ['faculty'], ({ user, params, body }) => {
  const { q, quiz } = getQuestionFor(user, params.id); assertEditable(quiz);
  const c = cleanQuestion(body);
  db.prepare('UPDATE questions SET text=?,type=?,options=?,correct=?,marks=?,explanation=? WHERE id=?').run(c.text, c.type, JSON.stringify(c.options), JSON.stringify(c.correct), c.marks, c.explanation, q.id);
  return { ok: true };
});
route('DELETE', '/api/faculty/questions/:id', ['faculty'], ({ user, params }) => {
  const { q, quiz } = getQuestionFor(user, params.id); assertEditable(quiz);
  db.prepare('DELETE FROM questions WHERE id=?').run(q.id);
  return { ok: true };
});

// results table
function resultRows(quizId) {
  return db.prepare(`SELECT a.id AS attempt_id, u.id AS student_id, u.name, u.email, u.roll_no, u.department, a.status, a.submit_reason, a.score, a.total, a.violations, a.started_at, a.submitted_at, a.manual_adjust
    FROM attempts a JOIN users u ON u.id=a.student_id WHERE a.quiz_id=? ORDER BY a.violations DESC, u.name`).all(quizId);
}
function flagLevel(v, max) { if (!v) return 'clean'; if (max && v >= max * 0.6) return 'high'; if (v >= 3) return 'medium'; return 'low'; }

route('GET', '/api/faculty/quizzes/:id/results', ['faculty'], ({ user, params }) => {
  const quiz = getQuizFor(user, params.id);
  // finalise any attempts that ran out of time
  for (const a of db.prepare("SELECT * FROM attempts WHERE quiz_id=? AND status='in_progress'").all(quiz.id)) expireIfNeeded(a, quiz);
  const rows = resultRows(quiz.id).map((r) => ({ ...r, percent: r.total ? Math.round((r.score / r.total) * 1000) / 10 : null, flag: flagLevel(r.violations, quiz.max_violations),
    seconds_taken: r.submitted_at ? Math.round((new Date(r.submitted_at) - new Date(r.started_at)) / 1000) : null }));
  return { quiz: { id: quiz.id, title: quiz.title, max_violations: quiz.max_violations, pass_percent: quiz.pass_percent }, rows };
});

route('GET', '/api/faculty/quizzes/:id/export', ['faculty'], ({ user, params }) => {
  const quiz = getQuizFor(user, params.id);
  const rows = resultRows(quiz.id);
  const csv = toCSV([['Name', 'Roll No', 'Email', 'Department', 'Status', 'Score', 'Total', 'Percent', 'Violations', 'Submit reason', 'Started', 'Submitted'],
    ...rows.map((r) => [r.name, r.roll_no, r.email, r.department, r.status, r.score, r.total, r.total ? ((r.score / r.total) * 100).toFixed(1) : '', r.violations, r.submit_reason, r.started_at, r.submitted_at])]);
  return { __raw: csv, contentType: 'text/csv; charset=utf-8', filename: `${quiz.title.replace(/[^\w]+/g, '_')}_results.csv` };
});

route('GET', '/api/faculty/quizzes/:id/analytics', ['faculty'], ({ user, params }) => {
  const quiz = getQuizFor(user, params.id);
  const attempts = db.prepare("SELECT * FROM attempts WHERE quiz_id=? AND status!='in_progress'").all(quiz.id);
  const qs = db.prepare('SELECT * FROM questions WHERE quiz_id=? ORDER BY position,id').all(quiz.id);
  const per = qs.map((q) => ({ id: q.id, text: q.text, correct: 0, wrong: 0, unanswered: 0 }));
  for (const a of attempts) {
    const ans = parseJSON(a.answers, {});
    qs.forEach((q, i) => { per[i][gradeQuestion(q, quiz, ans[q.id]).status]++; });
  }
  const pct = attempts.map((a) => (a.total ? (a.score / a.total) * 100 : 0));
  const buckets = Array(10).fill(0); pct.forEach((p) => { buckets[Math.min(9, Math.floor(p / 10))]++; });
  const n = attempts.length;
  return {
    submissions: n, avg_percent: n ? +(pct.reduce((s, x) => s + x, 0) / n).toFixed(1) : 0, highest: n ? +Math.max(...pct).toFixed(1) : 0, lowest: n ? +Math.min(...pct).toFixed(1) : 0,
    pass_rate: n ? +((pct.filter((p) => p >= quiz.pass_percent).length / n) * 100).toFixed(1) : 0,
    flagged: attempts.filter((a) => a.violations > 0).length, auto_submitted: attempts.filter((a) => a.status === 'auto_submitted').length,
    avg_violations: n ? +(attempts.reduce((s, a) => s + a.violations, 0) / n).toFixed(1) : 0, buckets, per_question: per,
  };
});

route('GET', '/api/faculty/attempts/:id', ['faculty'], ({ user, params }) => {
  const attempt = db.prepare('SELECT * FROM attempts WHERE id=?').get(params.id);
  if (!attempt) throw new HttpError(404, 'Attempt not found.');
  const quiz = getQuizFor(user, attempt.quiz_id);
  const student = db.prepare('SELECT name,email,roll_no,department FROM users WHERE id=?').get(attempt.student_id);
  const answers = parseJSON(attempt.answers, {});
  const review = db.prepare('SELECT * FROM questions WHERE quiz_id=? ORDER BY position,id').all(quiz.id).map((q) => {
    const g = gradeQuestion(q, quiz, answers[q.id]);
    return { id: q.id, text: q.text, type: q.type, options: parseJSON(q.options, []), your_answer: answers[q.id] ?? null, correct: parseJSON(q.correct, []), status: g.status, awarded: g.awarded, marks: q.marks };
  });
  const violations = db.prepare('SELECT type,detail,created_at FROM violations WHERE attempt_id=? ORDER BY id').all(attempt.id);
  return { student, quiz: { id: quiz.id, title: quiz.title, max_violations: quiz.max_violations }, attempt: { id: attempt.id, status: attempt.status, submit_reason: attempt.submit_reason, score: attempt.score, total: attempt.total, violations: attempt.violations, started_at: attempt.started_at, submitted_at: attempt.submitted_at, manual_adjust: attempt.manual_adjust }, review, violations };
});

route('POST', '/api/faculty/attempts/:id/reset', ['faculty'], ({ user, params }) => {   // allow retake
  const attempt = db.prepare('SELECT * FROM attempts WHERE id=?').get(params.id);
  if (!attempt) throw new HttpError(404, 'Attempt not found.');
  const quiz = getQuizFor(user, attempt.quiz_id);
  db.prepare('DELETE FROM attempts WHERE id=?').run(attempt.id);
  audit(user.id, 'attempt_reset', `attempt ${attempt.id} of quiz ${quiz.id}`);
  return { ok: true };
});
route('POST', '/api/faculty/attempts/:id/adjust', ['faculty'], ({ user, params, body }) => {   // manual marks tweak
  const attempt = db.prepare('SELECT * FROM attempts WHERE id=?').get(params.id);
  if (!attempt) throw new HttpError(404, 'Attempt not found.');
  const quiz = getQuizFor(user, attempt.quiz_id);
  if (attempt.status === 'in_progress') throw new HttpError(409, 'Attempt still in progress.');
  const adj = Number(body.adjust);
  if (!Number.isFinite(adj)) throw bad('Enter a number.');
  db.prepare('UPDATE attempts SET manual_adjust=? WHERE id=?').run(adj, attempt.id);
  const { score, total } = gradeAttempt({ ...attempt, manual_adjust: adj }, quiz);
  db.prepare('UPDATE attempts SET score=?, total=? WHERE id=?').run(Math.min(score, total), total, attempt.id);
  return { score: Math.min(score, total), total };
});
route('POST', '/api/faculty/attempts/:id/force-submit', ['faculty'], ({ user, params }) => {
  const attempt = db.prepare('SELECT * FROM attempts WHERE id=?').get(params.id);
  if (!attempt) throw new HttpError(404, 'Attempt not found.');
  const quiz = getQuizFor(user, attempt.quiz_id);
  if (attempt.status === 'in_progress') finalize(attempt, quiz, 'auto_submitted', 'faculty');
  return { ok: true };
});

// ===== ADMIN =====
route('GET', '/api/admin/stats', ['admin'], () => {
  const c = (sql) => db.prepare(sql).get().c;
  return {
    students: c("SELECT COUNT(*) AS c FROM users WHERE role='student'"), faculty: c("SELECT COUNT(*) AS c FROM users WHERE role='faculty' AND status='active'"),
    pending_faculty: c("SELECT COUNT(*) AS c FROM users WHERE status='pending'"), blocked: c("SELECT COUNT(*) AS c FROM users WHERE status='blocked'"),
    quizzes: c('SELECT COUNT(*) AS c FROM quizzes'), published: c('SELECT COUNT(*) AS c FROM quizzes WHERE published=1'),
    attempts: c("SELECT COUNT(*) AS c FROM attempts WHERE status!='in_progress'"), live: c("SELECT COUNT(*) AS c FROM attempts WHERE status='in_progress'"),
    flagged: c('SELECT COUNT(*) AS c FROM attempts WHERE violations>0'), auto_submitted: c("SELECT COUNT(*) AS c FROM attempts WHERE status='auto_submitted' AND submit_reason='violation_limit'"),
    total_violations: c('SELECT COALESCE(SUM(violations),0) AS c FROM attempts'),
  };
});
route('GET', '/api/admin/users', ['admin'], ({ query }) => {
  const role = ['student', 'faculty', 'admin'].includes(query.role) ? query.role : null;
  return db.prepare(`SELECT id,name,email,role,roll_no,department,status,created_at FROM users ${role ? 'WHERE role=?' : ''} ORDER BY (status='pending') DESC, id DESC`).all(...(role ? [role] : []));
});
route('POST', '/api/admin/users', ['admin'], ({ user, body }) => {
  const name = String(body.name || '').trim(), email = String(body.email || '').trim().toLowerCase(), role = body.role;
  if (!name || !EMAIL_RE.test(email) || !['student', 'faculty', 'admin'].includes(role) || String(body.password || '').length < 6) throw bad('Name, valid email, role and a 6+ character password are required.');
  if (db.prepare('SELECT id FROM users WHERE email=?').get(email)) throw new HttpError(409, 'Email already exists.');
  db.prepare("INSERT INTO users (name,email,password_hash,role,roll_no,department,status) VALUES (?,?,?,?,?,?, 'active')").run(name, email, hashPassword(body.password), role, String(body.roll_no || ''), String(body.department || ''));
  audit(user.id, 'user_create', `${role} ${email}`);
  return { ok: true };
});
route('POST', '/api/admin/users/bulk', ['admin'], ({ user, body }) => {   // CSV: name,email,roll_no,department,password
  const rows = parseCSV(String(body.data || ''));
  if (rows.length && /^name$/i.test((rows[0][0] || '').trim())) rows.shift();
  let added = 0; const skipped = [];
  for (const r of rows) {
    const [name, email, roll, dept, pw] = r.map((s) => (s || '').trim());
    if (!name || !EMAIL_RE.test(email || '') || (pw || 'welcome123').length < 6 || db.prepare('SELECT id FROM users WHERE email=?').get(email.toLowerCase())) { skipped.push(email || name || '(blank)'); continue; }
    db.prepare("INSERT INTO users (name,email,password_hash,role,roll_no,department,status) VALUES (?,?,?,?,?,?, 'active')").run(name, email.toLowerCase(), hashPassword(pw || 'welcome123'), body.role === 'faculty' ? 'faculty' : 'student', roll, dept);
    added++;
  }
  audit(user.id, 'user_bulk_create', `${added} added`);
  return { added, skipped };
});
route('PATCH', '/api/admin/users/:id', ['admin'], ({ user, params, body }) => {
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(params.id);
  if (!target) throw new HttpError(404, 'User not found.');
  if (target.id === user.id) throw bad("You can't change your own account here.");
  if (!['active', 'pending', 'blocked'].includes(body.status)) throw bad('Invalid status.');
  db.prepare('UPDATE users SET status=? WHERE id=?').run(body.status, target.id);
  audit(user.id, 'user_status', `${target.email} -> ${body.status}`);
  return { ok: true };
});
route('POST', '/api/admin/users/:id/reset-password', ['admin'], ({ user, params, body }) => {
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(params.id);
  if (!target) throw new HttpError(404, 'User not found.');
  const pw = String(body.password || '');
  if (pw.length < 6) throw bad('Password must be at least 6 characters.');
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(pw), target.id);
  audit(user.id, 'password_reset', target.email);
  return { ok: true };
});
route('DELETE', '/api/admin/users/:id', ['admin'], ({ user, params }) => {
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(params.id);
  if (!target) throw new HttpError(404, 'User not found.');
  if (target.id === user.id) throw bad("You can't delete yourself.");
  db.prepare('DELETE FROM users WHERE id=?').run(target.id);
  audit(user.id, 'user_delete', target.email);
  return { ok: true };
});
route('GET', '/api/admin/quizzes', ['admin'], () =>
  db.prepare(`SELECT q.id,q.title,q.subject,q.published,q.created_at,u.name AS faculty,
    (SELECT COUNT(*) FROM questions WHERE quiz_id=q.id) AS question_count,
    (SELECT COUNT(*) FROM attempts WHERE quiz_id=q.id) AS attempts,
    (SELECT COALESCE(SUM(violations),0) FROM attempts WHERE quiz_id=q.id) AS violations
    FROM quizzes q JOIN users u ON u.id=q.faculty_id ORDER BY q.id DESC`).all());
route('DELETE', '/api/admin/quizzes/:id', ['admin'], ({ user, params }) => {
  const quiz = db.prepare('SELECT * FROM quizzes WHERE id=?').get(params.id);
  if (!quiz) throw new HttpError(404, 'Quiz not found.');
  db.prepare('DELETE FROM quizzes WHERE id=?').run(quiz.id);
  audit(user.id, 'quiz_delete', quiz.title);
  return { ok: true };
});
route('GET', '/api/admin/flags', ['admin'], () =>
  db.prepare(`SELECT a.id AS attempt_id, u.name, u.roll_no, q.title, a.status, a.submit_reason, a.violations, a.started_at,
    (SELECT GROUP_CONCAT(type || ' x' || c) FROM (SELECT type, COUNT(*) AS c FROM violations WHERE attempt_id=a.id GROUP BY type)) AS breakdown
    FROM attempts a JOIN users u ON u.id=a.student_id JOIN quizzes q ON q.id=a.quiz_id WHERE a.violations>0 ORDER BY a.violations DESC, a.id DESC LIMIT 200`).all());
route('GET', '/api/admin/audit', ['admin'], () =>
  db.prepare('SELECT l.id,l.action,l.detail,l.created_at,u.email FROM audit_log l LEFT JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 200').all());

// ---------- static files ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json' };
function serveStatic(req, res, pathname) {
  let p = decodeURIComponent(pathname);
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('Forbidden'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

// ---------- main handler ----------
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 2 * 1024 * 1024) { reject(new HttpError(413, 'Request too large.')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { const s = Buffer.concat(chunks).toString(); if (!s) return resolve({}); try { resolve(JSON.parse(s)); } catch { reject(bad('Invalid JSON.')); } });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url.pathname);
  try {
    let matched = null, params = {};
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const m = r.re.exec(url.pathname);
      if (m) { matched = r; r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1]))); break; }
    }
    if (!matched) throw new HttpError(404, 'Not found.');
    let user = null;
    if (matched.roles) {
      const auth = req.headers.authorization || '';
      const payload = verifyToken(auth.startsWith('Bearer ') ? auth.slice(7) : '');
      if (!payload) throw new HttpError(401, 'Please log in again.');
      user = db.prepare('SELECT * FROM users WHERE id=?').get(payload.id);
      if (!user || user.status !== 'active') throw new HttpError(401, 'Account not active.');
      if (!matched.roles.includes(user.role)) throw new HttpError(403, 'You do not have access to this.');
    }
    const body = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) ? await readBody(req) : {};
    const out = await matched.handler({ req, res, user, params, query: Object.fromEntries(url.searchParams), body });
    if (out && out.__raw !== undefined) {
      res.writeHead(200, { 'Content-Type': out.contentType, 'Content-Disposition': `attachment; filename="${out.filename}"` });
      return res.end(out.__raw);
    }
    json(res, 200, out ?? { ok: true });
  } catch (e) {
    if (e instanceof HttpError) return json(res, e.status, { error: e.message });
    console.error(e);
    json(res, 500, { error: 'Something went wrong on the server.' });
  }
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`Quiz app running at http://localhost:${PORT}`));
}

function closeServer() {
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      try { closeDb(); } catch (error) { return reject(error); }
      return resolve();
    }
    server.close((error) => {
      if (error) return reject(error);
      try { closeDb(); } catch (closeError) { return reject(closeError); }
      resolve();
    });
  });
}

module.exports = { server, closeServer };
