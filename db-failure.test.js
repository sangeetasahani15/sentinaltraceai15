'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const SAMPLE = fs.readFileSync(path.join(__dirname, 'fixtures', 'original_app.js'), 'utf8').match(/const SAMPLE=`([\s\S]*?)`;/)[1];
const K = 'c'.repeat(64);

async function run(url) {
  delete require.cache[require.resolve('../lib/db')];
  if (url === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = url;
  process.env.DATABASE_SSL = 'false';
  const analyze = require('../api/analyze'), health = require('../api/health');
  const mk = () => { const r = { headers: {}, setHeader(k, v) { this.headers[k] = v; }, end(b) { this.body = b ? JSON.parse(b) : null; } }; return r; };
  const res = mk(); await analyze({ method: 'POST', headers: { 'x-client-key': K }, body: { raw: SAMPLE }, url: '/api/analyze' }, res);
  const hres = mk(); await health({ method: 'GET', headers: {} }, hres);
  await require('../lib/db').closePool();
  return { res, hres };
}
test('missing DATABASE_URL -> 503 without leaking details', async () => {
  const { res, hres } = await run(undefined);
  assert.equal(res.statusCode, 503); assert.equal(res.body.error, 'Database is not configured');
  assert.equal(hres.statusCode, 503); assert.equal(hres.body.database, 'not_configured');
});
test('unreachable database -> 503 and credentials are not echoed', async () => {
  const { res, hres } = await run('postgresql://user:SECRETPASS@127.0.0.1:1/none');
  assert.equal(res.statusCode, 503); assert.ok(!JSON.stringify(res.body).includes('SECRETPASS'));
  assert.equal(hres.body.database, 'unreachable');
});
