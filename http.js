'use strict';
const crypto = require('crypto');
const MAX_EMAIL_BYTES = Number(process.env.MAX_EMAIL_BYTES || 200000);

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(obj));
}
function cors(req, res) {
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
  const o = req.headers.origin;
  if (o && allowed.includes(o)) {
    res.setHeader('Access-Control-Allow-Origin', o);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Client-Key');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  }
  if (req.method === 'OPTIONS') { res.statusCode = 204; res.end(); return true; }
  return false;
}
// Per-browser anonymous key -> owner hash. Records are only visible to the key that created them.
function owner(req) {
  const k = req.headers['x-client-key'];
  if (typeof k !== 'string' || !/^[A-Za-z0-9_-]{32,128}$/.test(k)) return null;
  return sha256('owner:' + k);
}
function validateEmail(raw) {
  if (typeof raw !== 'string') return 'Field "raw" must be a string containing the email source';
  if (!raw.trim()) return 'Email is empty';
  if (Buffer.byteLength(raw, 'utf8') > MAX_EMAIL_BYTES) return `Email is too large (max ${MAX_EMAIL_BYTES} bytes)`;
  if (raw.includes('\u0000')) return 'Email contains binary data';
  if (!/^[A-Za-z0-9-]+:\s?/m.test(raw)) return 'Input does not look like an email: no RFC 5322 header lines (e.g. "From: ...") found';
  return null;
}
function dbError(res, e) {
  // Never echo connection strings or driver internals to the client.
  if (e && e.name === 'DbConfigError') return send(res, 503, { error: 'Database is not configured' });
  console.error('db error:', e && e.code ? e.code : e && e.name);
  return send(res, 503, { error: 'Database unavailable' });
}
module.exports = { send, cors, owner, validateEmail, dbError, sha256, MAX_EMAIL_BYTES };
