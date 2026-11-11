// End-to-end smoke test: node --no-warnings test.js
const os = require('node:os'), path = require('node:path'), fs = require('node:fs');
const tmp = path.join(os.tmpdir(), `quiz-test-${process.pid}.db`);
process.env.DB_FILE = tmp;
process.env.JWT_SECRET = 'test-secret';
const { server, closeServer } = require('./server');
const { db } = require('./db');
const assert = require('node:assert/strict');

let base, passed = 0;
async function cleanup() {
  try {
    if (server.listening) await closeServer();
  } catch (error) {
    console.warn('Cleanup warning:', error.message);
  }
  for (const file of [tmp, tmp + '-wal', tmp + '-shm']) {
    try { fs.rmSync(file, { force: true }); } catch {}
  }
}
async function call(method, url, body, token) {
  const res = await fetch(base + url, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data };
}
const ok = async (m, u, b, t) => { const r = await call(m, u, b, t); assert.ok(r.status < 300, `${m} ${u} -> ${r.status} ${JSON.stringify(r.data)}`); return r.data; };
const step = (name) => { passed++; console.log('  ok -', name); };

(async () => {
  await new Promise((r) => server.listen(0, r));
  base = 'http://localhost:' + server.address().port;
  console.log('Running tests on', base);

  // ----- auth & roles
  const admin = await ok('POST', '/api/auth/login', { email: 'admin@quiz.com', password: 'admin123', role: 'admin' });
  step('admin login');
  assert.equal((await call('POST', '/api/auth/login', { email: 'admin@quiz.com', password: 'admin123', role: 'student' })).status, 403); step('role mismatch blocked');
  assert.equal((await call('POST', '/api/auth/login', { email: 'admin@quiz.com', password: 'bad' })).status, 401); step('wrong password rejected');

  const reg = await ok('POST', '/api/auth/register', { name: 'Prof Rao', email: 'rao@x.com', password: 'secret1', role: 'faculty' });
  assert.ok(reg.pending);
  assert.equal((await call('POST', '/api/auth/login', { email: 'rao@x.com', password: 'secret1', role: 'faculty' })).status, 403); step('faculty pending until approved');
  const users = await ok('GET', '/api/admin/users?role=faculty', null, admin.token);
  await ok('PATCH', `/api/admin/users/${users[0].id}`, { status: 'active' }, admin.token);
  const fac = await ok('POST', '/api/auth/login', { email: 'rao@x.com', password: 'secret1', role: 'faculty' }); step('admin approves faculty');

  await ok('POST', '/api/auth/register', { name: 'Asha', email: 'asha@x.com', password: 'secret1', role: 'student', roll_no: 'R1' });
  await ok('POST', '/api/auth/register', { name: 'Ben', email: 'ben@x.com', password: 'secret1', role: 'student', roll_no: 'R2' });
  const s1 = await ok('POST', '/api/auth/login', { email: 'asha@x.com', password: 'secret1', role: 'student' });
  const s2 = await ok('POST', '/api/auth/login', { email: 'ben@x.com', password: 'secret1', role: 'student' });
  assert.equal((await call('GET', '/api/faculty/quizzes', null, s1.token)).status, 403); step('students cannot use faculty API');
  assert.equal((await call('GET', '/api/admin/stats', null, fac.token)).status, 403); step('faculty cannot use admin API');

  // ----- quiz creation
  const { id: quizId } = await ok('POST', '/api/faculty/quizzes', { title: 'Maths 1', subject: 'Maths', duration_min: 20, max_violations: 3, negative_marking: 0.25, show_result: true }, fac.token);
  await ok('POST', `/api/faculty/quizzes/${quizId}/questions`, { text: '2+2?', type: 'single', options: ['3', '4', '5'], correct: [1], marks: 2 }, fac.token);
  await ok('POST', `/api/faculty/quizzes/${quizId}/questions`, { text: 'Primes?', type: 'multiple', options: ['2', '4', '5', '9'], correct: [0, 2], marks: 2 }, fac.token);
  await ok('POST', `/api/faculty/quizzes/${quizId}/questions`, { text: 'Sky is blue', type: 'truefalse', correct: [0], marks: 1 }, fac.token);
  const bulk = await ok('POST', `/api/faculty/quizzes/${quizId}/questions/bulk`, { format: 'csv', data: 'question,type,option1,option2,option3,option4,correct,marks,explanation\n"Capital of France, city?",text,,,,,Paris;paris city,1,\n"3*3?",single,6,9,12,,B,1,nine' }, fac.token);
  assert.equal(bulk.added, 2); step('questions added (manual + CSV bulk)');
  assert.equal((await call('POST', `/api/faculty/quizzes/${quizId}/questions`, { text: 'x', type: 'single', options: ['a'], correct: [0] }, fac.token)).status, 400); step('invalid question rejected');
  assert.equal((await call('GET', '/api/student/quizzes', null, s1.token)).data.length, 0); step('draft hidden from students');
  await ok('POST', `/api/faculty/quizzes/${quizId}/publish`, { published: true }, fac.token);

  // ----- student 1: cheats -> auto-submit
  const list = await ok('GET', '/api/student/quizzes', null, s1.token);
  assert.equal(list.length, 1); assert.equal(list[0].state, 'open'); assert.equal(list[0].question_count, 5); step('student sees published quiz');
  const { attempt_id: a1 } = await ok('POST', `/api/student/quizzes/${quizId}/start`, {}, s1.token);
  const att = await ok('GET', `/api/student/attempts/${a1}`, null, s1.token);
  assert.equal(att.questions.length, 5);
  assert.ok(!JSON.stringify(att).includes('"correct"'), 'correct answers leaked to student!'); step('correct answers are not sent to student');
  await ok('PUT', `/api/student/attempts/${a1}/answer`, { question_id: att.questions[0].id, answer: 1 }, s1.token);
  let v = await ok('POST', `/api/student/attempts/${a1}/violation`, { type: 'tab_switch', detail: 'x' }, s1.token);
  assert.equal(v.violations, 1); assert.equal(v.finished, false);
  v = await ok('POST', `/api/student/attempts/${a1}/violation`, { type: 'tab_switch' }, s1.token);
  assert.equal(v.violations, 2); step('violation counter increases');
  // simulate closing the browser for a while: last_seen far in the past, then reopen
  db.prepare('UPDATE attempts SET last_seen=? WHERE id=?').run(new Date(Date.now() - 120000).toISOString(), a1);
  const resumed = await ok('GET', `/api/student/attempts/${a1}?resume=1`, null, s1.token);
  assert.equal(resumed.finished, true); assert.equal(resumed.reason, 'violation_limit'); step('closing/reloading is detected on resume and hits the limit -> auto-submit');
  const res1 = await ok('GET', `/api/student/attempts/${a1}/result`, null, s1.token);
  assert.equal(res1.status, 'auto_submitted'); assert.equal(res1.violations, 3); assert.equal(res1.score, 2); step('auto-submitted attempt graded (answered so far)');
  assert.equal((await call('POST', `/api/student/quizzes/${quizId}/start`, {}, s1.token)).status, 409); step('no second attempt');
  assert.equal((await call('POST', `/api/student/attempts/${a1}/violation`, { type: 'tab_switch' }, s1.token)).data.finished, true);

  // ----- student 2: honest, with negative marking
  const { attempt_id: a2 } = await ok('POST', `/api/student/quizzes/${quizId}/start`, {}, s2.token);
  const q2 = (await ok('GET', `/api/student/attempts/${a2}`, null, s2.token)).questions;
  const byText = Object.fromEntries(q2.map((q) => [q.text, q]));
  const ans = {
    [byText['2+2?'].id]: 1,                      // correct +2
    [byText['Primes?'].id]: [0, 2],              // correct +2
    [byText['Sky is blue'].id]: 1,               // wrong -0.25
    [byText['Capital of France, city?'].id]: ' PARIS ', // correct +1
    [byText['3*3?'].id]: 1,                      // correct +1
  };
  await ok('POST', `/api/student/attempts/${a2}/submit`, { answers: ans }, s2.token);
  const res2 = await ok('GET', `/api/student/attempts/${a2}/result`, null, s2.token);
  assert.equal(res2.score, 5.75); assert.equal(res2.total, 7); assert.equal(res2.violations, 0); step('scoring incl. multi-select, text match and negative marking = 5.75/7');

  // ----- timer expiry
  const q3 = await ok('POST', '/api/faculty/quizzes', { title: 'Short', duration_min: 1, max_violations: 0 }, fac.token);
  await ok('POST', `/api/faculty/quizzes/${q3.id}/questions`, { text: 'a?', type: 'truefalse', correct: [0] }, fac.token);
  await ok('POST', `/api/faculty/quizzes/${q3.id}/publish`, { published: true }, fac.token);
  const { attempt_id: a3 } = await ok('POST', `/api/student/quizzes/${q3.id}/start`, {}, s1.token);
  db.prepare('UPDATE attempts SET started_at=? WHERE id=?').run(new Date(Date.now() - 5 * 60000).toISOString(), a3);
  const expired = await ok('GET', `/api/student/attempts/${a3}`, null, s1.token);
  assert.equal(expired.finished, true); assert.equal(expired.reason, 'time_up'); step('server enforces time limit');

  // ----- faculty views
  const results = await ok('GET', `/api/faculty/quizzes/${quizId}/results`, null, fac.token);
  assert.equal(results.rows.length, 2); assert.equal(results.rows[0].name, 'Asha'); assert.equal(results.rows[0].violations, 3); assert.equal(results.rows[0].flag, 'high'); step('faculty sees results sorted by violations with flag level');
  const detail = await ok('GET', `/api/faculty/attempts/${a1}`, null, fac.token);
  assert.equal(detail.violations.length, 3); assert.equal(detail.violations[2].type, 'left_page'); assert.equal(detail.review.length, 5); step('faculty sees answers + violation timeline');
  const an = await ok('GET', `/api/faculty/quizzes/${quizId}/analytics`, null, fac.token);
  assert.equal(an.submissions, 2); assert.equal(an.flagged, 1); assert.equal(an.auto_submitted, 1); step('analytics');
  const csv = await call('GET', `/api/faculty/quizzes/${quizId}/export`, null, fac.token);
  assert.ok(String(csv.data).startsWith('Name,Roll No')); step('CSV export');
  await ok('POST', `/api/faculty/attempts/${a1}/adjust`, { adjust: 1 }, fac.token);
  assert.equal((await ok('GET', `/api/student/attempts/${a1}/result`, null, s1.token)).score, 3); step('manual mark adjustment');
  assert.equal((await call('POST', `/api/faculty/questions/${(await ok('GET', `/api/faculty/quizzes/${quizId}`, null, fac.token)).questions[0].id}`, {}, fac.token)).status, 404);
  const locked = await call('POST', `/api/faculty/quizzes/${quizId}/questions`, { text: 'late', type: 'truefalse', correct: [0] }, fac.token);
  assert.equal(locked.status, 409); step('questions locked once students started');
  await ok('POST', `/api/faculty/attempts/${a1}/reset`, {}, fac.token);
  assert.equal((await call('POST', `/api/student/quizzes/${quizId}/start`, {}, s1.token)).status, 200); step('faculty can allow a retake');

  // another faculty must not touch this quiz
  await ok('POST', '/api/admin/users', { name: 'Prof B', email: 'b@x.com', role: 'faculty', password: 'secret1' }, admin.token);
  const fac2 = await ok('POST', '/api/auth/login', { email: 'b@x.com', password: 'secret1', role: 'faculty' });
  assert.equal((await call('GET', `/api/faculty/quizzes/${quizId}/results`, null, fac2.token)).status, 403); step('faculty cannot see another faculty\'s quiz');

  // ----- admin
  const stats = await ok('GET', '/api/admin/stats', null, admin.token);
  assert.equal(stats.students, 2); assert.ok(stats.total_violations >= 0);
  const flags = await ok('GET', '/api/admin/flags', null, admin.token); assert.ok(Array.isArray(flags)); step('admin stats + flags');
  assert.equal((await call('GET', '/api/me')).status, 401); step('API requires token');
  assert.equal((await call('GET', '/../server.js')).status, 404);

  console.log(`\nAll ${passed} checks passed.`);
  await cleanup();
  process.exit(0);
})().catch(async (e) => { console.error('\nTEST FAILED:', e.message); await cleanup(); process.exit(1); });
