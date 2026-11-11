// Database setup (built-in node:sqlite, no npm packages needed)
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const path = require('node:path');

const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'quiz.db');
const db = new DatabaseSync(DB_FILE);

db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('student','faculty','admin')),
  roll_no TEXT,
  department TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','pending','blocked')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS quizzes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  faculty_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT DEFAULT '',
  subject TEXT DEFAULT '',
  duration_min INTEGER NOT NULL DEFAULT 30,
  start_time TEXT,            -- ISO string, null = open immediately
  end_time TEXT,              -- ISO string, null = no deadline
  max_violations INTEGER NOT NULL DEFAULT 5,   -- 0 = never auto-submit
  shuffle_questions INTEGER NOT NULL DEFAULT 0,
  shuffle_options INTEGER NOT NULL DEFAULT 0,
  show_result INTEGER NOT NULL DEFAULT 1,      -- show score to student after submit
  negative_marking REAL NOT NULL DEFAULT 0,    -- fraction of marks deducted for a wrong answer
  pass_percent INTEGER NOT NULL DEFAULT 40,
  access_code TEXT DEFAULT '',                 -- empty = no code needed
  published INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS questions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
  text TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('single','multiple','truefalse','text')),
  options TEXT NOT NULL DEFAULT '[]',   -- JSON array of strings
  correct TEXT NOT NULL DEFAULT '[]',   -- JSON: option indexes, or accepted answers for 'text'
  marks REAL NOT NULL DEFAULT 1,
  explanation TEXT DEFAULT '',
  position INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  quiz_id INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
  student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  started_at TEXT NOT NULL,
  submitted_at TEXT,
  status TEXT NOT NULL DEFAULT 'in_progress' CHECK (status IN ('in_progress','submitted','auto_submitted')),
  submit_reason TEXT,
  score REAL,
  total REAL,
  violations INTEGER NOT NULL DEFAULT 0,
  last_seen TEXT,
  answers TEXT NOT NULL DEFAULT '{}',   -- JSON {questionId: answer}
  seed INTEGER NOT NULL,
  manual_adjust REAL NOT NULL DEFAULT 0,
  UNIQUE (quiz_id, student_id)
);

CREATE TABLE IF NOT EXISTS violations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  detail TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  detail TEXT DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_questions_quiz ON questions(quiz_id);
CREATE INDEX IF NOT EXISTS idx_attempts_quiz ON attempts(quiz_id);
CREATE INDEX IF NOT EXISTS idx_attempts_student ON attempts(student_id);
CREATE INDEX IF NOT EXISTS idx_violations_attempt ON violations(attempt_id);
`);

// ---- password hashing (scrypt) ----
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64);
  const known = Buffer.from(hash, 'hex');
  return known.length === test.length && crypto.timingSafeEqual(known, test);
}

// ---- seed default admin ----
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@quiz.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const hasAdmin = db.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").get();
if (!hasAdmin) {
  db.prepare("INSERT INTO users (name,email,password_hash,role,status) VALUES (?,?,?,?, 'active')")
    .run('Administrator', ADMIN_EMAIL, hashPassword(ADMIN_PASSWORD), 'admin');
  console.log(`Default admin created -> ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}  (change this password!)`);
}

function audit(userId, action, detail = '') {
  db.prepare('INSERT INTO audit_log (user_id, action, detail) VALUES (?,?,?)').run(userId ?? null, action, detail);
}

function closeDb() {
  try {
    db.close();
  } catch (error) {
    if (error && error.code !== 'SQLITE_MISUSE') throw error;
  }
}

module.exports = { db, hashPassword, verifyPassword, audit, closeDb };
