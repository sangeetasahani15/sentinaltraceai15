'use strict';
const engine = require('../lib/engine');
const db = require('../lib/db');
const { send, cors, owner, validateEmail, dbError, sha256 } = require('../lib/http');

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  if (req.method !== 'POST') return send(res, 405, { error: 'Use POST' });
  const own = owner(req);
  if (!own) return send(res, 401, { error: 'Missing or invalid X-Client-Key header' });
  const body = req.body && typeof req.body === 'object' ? req.body : null;
  if (!body) return send(res, 400, { error: 'Body must be JSON: {"raw": "<email source>"}' });
  const bad = validateEmail(body.raw);
  if (bad) return send(res, 400, { error: bad });

  let a;
  try { a = engine.analyze(body.raw); } catch (e) { return send(res, 422, { error: 'Could not parse email' }); }
  const { raw, ...result } = a;                 // raw email is never returned or stored
  try {
    const rec = await db.saveDetection(own, a, sha256(body.raw));
    return send(res, 200, { ...result, record: { id: String(rec.id), created_at: rec.created_at }, engine: db.ENGINE });
  } catch (e) { return dbError(res, e); }
};
