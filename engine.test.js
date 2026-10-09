'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const engine = require('../lib/engine');

// Load the ORIGINAL (untouched) analysis code from the uploaded app.js and compare outputs.
function loadOriginal() {
  const src = fs.readFileSync(path.join(__dirname, 'fixtures', 'original_app.js'), 'utf8');
  const a = src.indexOf('/* ---------- parsing & analysis ---------- */');
  const b = src.indexOf('const iocs=()=>');
  const ctx = { URL }; vm.createContext(ctx);
  vm.runInContext("'use strict';" + src.slice(a, b) + ';this.analyze=analyze;', ctx);
  return ctx.analyze;
}
const SAMPLE = (() => {
  const s = fs.readFileSync(path.join(__dirname, 'fixtures', 'original_app.js'), 'utf8');
  const m = s.match(/const SAMPLE=`([\s\S]*?)`;/); return m[1];
})();
const LEGIT = 'From: "Alice" <alice@company.com>\nTo: bob@company.com\nSubject: Lunch tomorrow?\nDate: Wed, 7 Oct 2026 10:00:00 +0000\nMessage-ID: <1@company.com>\nAuthentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n\nHi Bob, are we still on for lunch at noon?';
const CASES = [SAMPLE, LEGIT,
  'From: x@gmail.com\nReply-To: y@yahoo.com\nSubject: Wire transfer\n\nPlease send the invoice payment by wire to http://203.0.113.4/pay',
  'Subject: only header\n\n'];

test('engine output is identical to the original app.js analysis', () => {
  const orig = loadOriginal();
  for (const raw of CASES) assert.deepEqual(JSON.parse(JSON.stringify(engine.analyze(raw))), JSON.parse(JSON.stringify(orig(raw))));
});
test('demo phishing sample is scored HIGH, legitimate email LOW', () => {
  const p = engine.analyze(SAMPLE), l = engine.analyze(LEGIT);
  assert.equal(p.label, 'HIGH'); assert.ok(p.risk >= 75); assert.ok(p.sig.length >= 5);
  assert.equal(l.label, 'LOW'); assert.ok(l.risk < 40);
  assert.equal(p.probs.length, 5);
});
test('public/engine.js is an exact copy of lib/engine.js', () => {
  assert.equal(fs.readFileSync(path.join(__dirname, '../public/engine.js'), 'utf8'), fs.readFileSync(path.join(__dirname, '../lib/engine.js'), 'utf8'));
});
