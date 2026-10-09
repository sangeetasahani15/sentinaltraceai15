'use strict';
const db = require('../lib/db');
const { send, cors, owner, dbError } = require('../lib/http');

module.exports = async (req, res) => {
  if (cors(req, res)) return;
  const own = owner(req);
  if (!own) return send(res, 401, { error: 'Missing or invalid X-Client-Key header' });
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'GET') {
      const limit = Math.min(Math.max(parseInt(url.searchParams.get('limit') || '50', 10) || 50, 1), 200);
      const offset = Math.max(parseInt(url.searchParams.get('offset') || '0', 10) || 0, 0);
      const rows = await db.listDetections(own, limit, offset);
      return send(res, 200, { items: rows.map(r => ({ ...r, id: String(r.id) })), limit, offset });
    }
    if (req.method === 'DELETE') {
      const id = url.searchParams.get('id') || '';
      if (!/^\d{1,18}$/.test(id)) return send(res, 400, { error: 'Query parameter "id" must be a numeric record id' });
      const ok = await db.deleteDetection(own, id);
      return ok ? send(res, 200, { deleted: id }) : send(res, 404, { error: 'Record not found' });
    }
    return send(res, 405, { error: 'Use GET or DELETE' });
  } catch (e) { return dbError(res, e); }
};
