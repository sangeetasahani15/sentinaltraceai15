'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const DB = process.env.TEST_DATABASE_URL;
if (!DB) { console.log('TEST_DATABASE_URL not set: skipping API/DB integration tests'); process.exit(0); }
process.env.DATABASE_URL = DB; process.env.DATABASE_SSL = 'false';
const db = require('../lib/db');
const server = require('../server');
const SAMPLE = fs.readFileSync(path.join(__dirname, 'fixtures', 'original_app.js'), 'utf8').match(/const SAMPLE=`([\s\S]*?)`;/)[1];
const LEGIT = 'From: "Alice" <alice@company.com>\nTo: bob@company.com\nSubject: Lunch tomorrow?\nMessage-ID: <1@company.com>\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nHi Bob, lunch at noon?';
const K1 = 'a'.repeat(64), K2 = 'b'.repeat(64);
let base;

test.before(async () => {
  await db.initSchema(); await db.initSchema();   // idempotent
  await db.getPool().query('TRUNCATE detections RESTART IDENTITY');
  await new Promise(r => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port;
});
test.after(async () => { server.close(); await db.closePool(); });
const call = (p, o = {}, key = K1) => fetch(base + p, { ...o, headers: { 'Content-Type': 'application/json', ...(key ? { 'X-Client-Key': key } : {}) } });
const post = (raw, key) => call('/api/analyze', { method: 'POST', body: JSON.stringify({ raw }) }, key);

test('health reports database connected', async () => {
  const r = await fetch(base + '/api/health'); const j = await r.json();
  assert.equal(r.status, 200); assert.equal(j.database, 'connected');
});
test('analyze saves a phishing email and returns real engine output + record id', async () => {
  const r = await post(SAMPLE); const j = await r.json();
  assert.equal(r.status, 200); assert.equal(j.label, 'HIGH'); assert.ok(j.risk >= 75);
  assert.ok(j.record.id); assert.equal(j.raw, undefined);
  const { rows } = await db.getPool().query('SELECT * FROM detections WHERE id=$1', [j.record.id]);
  assert.equal(rows[0].risk_score, j.risk); assert.equal(rows[0].risk_label, j.label); assert.equal(rows[0].sender, j.from.addr);
  assert.equal(rows[0].content_sha256.length, 64);
  assert.ok(!JSON.stringify(rows[0]).includes('Verify your payment details'), 'email body must not be stored');
});
test('legitimate email scored LOW and listed in history, newest first', async () => {
  const j = await (await post(LEGIT)).json(); assert.equal(j.label, 'LOW');
  const h = await (await call('/api/history')).json();
  assert.equal(h.items.length, 2); assert.equal(h.items[0].risk_label, 'LOW'); assert.equal(h.items[1].risk_label, 'HIGH');
});
test('history is isolated per client key', async () => {
  assert.equal((await (await call('/api/history', {}, K2)).json()).items.length, 0);
  const id = (await (await call('/api/history')).json()).items[0].id;
  assert.equal((await call('/api/history?id=' + id, { method: 'DELETE' }, K2)).status, 404);   // other user cannot delete
});
test('missing / malformed client key is rejected', async () => {
  assert.equal((await call('/api/history', {}, null)).status, 401);
  assert.equal((await call('/api/history', {}, 'short')).status, 401);
});
test('input validation: empty, non-string, non-email, too large, binary, bad JSON', async () => {
  for (const raw of ['', '   ', 123, 'just some words with no headers', 'From: a@b.c\n\n' + 'x'.repeat(200001), 'From: a@b.c\u0000\n\nx']) {
    const r = await post(raw); assert.equal(r.status, 400, String(raw).slice(0, 20));
  }
  const r = await fetch(base + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Client-Key': K1 }, body: '{bad' });
  assert.equal(r.status, 400);
  assert.equal((await call('/api/analyze', { method: 'GET' })).status, 405);
});
test('SQL injection strings are stored inertly (parameterized queries)', async () => {
  const raw = "From: \"x'); DROP TABLE detections;--\" <a@b.com>\nSubject: '); DROP TABLE detections;--\n\nhi";
  assert.equal((await post(raw)).status, 200);
  assert.equal((await call('/api/history')).status, 200);
  const { rows } = await db.getPool().query('SELECT count(*)::int c FROM detections'); assert.ok(rows[0].c >= 3);
});
test('delete own record', async () => {
  const items = (await (await call('/api/history')).json()).items;
  assert.equal((await call('/api/history?id=' + items[0].id, { method: 'DELETE' })).status, 200);
  assert.equal((await call('/api/history?id=' + items[0].id, { method: 'DELETE' })).status, 404);
  assert.equal((await call('/api/history?id=abc', { method: 'DELETE' })).status, 400);
});
test('static frontend is served and path traversal is blocked', async () => {
  assert.equal((await fetch(base + '/')).status, 200);
  assert.equal((await fetch(base + '/app.js')).status, 200);
  assert.equal((await fetch(base + '/..%2fpackage.json')).status, 404);
  assert.equal((await fetch(base + '/package.json')).status, 404);
});
test('CORS only for allowed origins', async () => {
  process.env.ALLOWED_ORIGINS = 'https://ok.example';
  let r = await fetch(base + '/api/history', { headers: { Origin: 'https://ok.example', 'X-Client-Key': K1 } });
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://ok.example');
  r = await fetch(base + '/api/history', { headers: { Origin: 'https://evil.example', 'X-Client-Key': K1 } });
  assert.equal(r.headers.get('access-control-allow-origin'), null);
  delete process.env.ALLOWED_ORIGINS;
});
