'use strict';
const db = require('../lib/db');
const { send } = require('../lib/http');

module.exports = async (req, res) => {
  const out = { status: 'ok', engine: db.ENGINE, database: 'unknown' };
  try { await db.ping(); out.database = 'connected'; }
  catch (e) { out.status = 'degraded'; out.database = e && e.name === 'DbConfigError' ? 'not_configured' : 'unreachable'; }
  return send(res, out.status === 'ok' ? 200 : 503, out);
};
