'use strict';
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

let pool = null;
class DbConfigError extends Error { constructor(m) { super(m); this.name = 'DbConfigError'; } }

function getPool() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new DbConfigError('DATABASE_URL is not set');
  if (!pool) {
    const local = /@(localhost|127\.0\.0\.1)(:|\/|$)/.test(url);
    const ssl = process.env.DATABASE_SSL === 'false' || local ? false : { rejectUnauthorized: true };
    pool = new Pool({
      connectionString: url, ssl,
      max: Number(process.env.DB_POOL_MAX || 3),   // small pool: suited to serverless functions
      connectionTimeoutMillis: 5000, idleTimeoutMillis: 10000,
    });
    pool.on('error', () => {});                     // idle-client errors must not crash the process
  }
  return pool;
}
async function closePool() { if (pool) { const p = pool; pool = null; await p.end(); } }

async function initSchema() {
  const sql = fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8');
  await getPool().query(sql);
}

const ENGINE = { name: 'sentinel-rules', version: '1.0.0' };

async function saveDetection(ownerHash, a, contentSha) {
  const classScores = a.probs.map(p => ({ label: p[0], percent: p[1] }));
  const { rows } = await getPool().query(
    `INSERT INTO detections (owner_hash, content_sha256, message_id, sender, subject, risk_score, risk_label,
       origin_confidence, threat_type, classification, class_scores, indicators, auth_results, engine_name, engine_version)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13::jsonb,$14,$15)
     RETURNING id, created_at`,
    [ownerHash, contentSha, (a.id || '').slice(0, 512), (a.from.addr || '').slice(0, 320), (a.subject || '').slice(0, 998),
      a.risk, a.label, a.oc, (a.threatType || '').slice(0, 128), (a.cls || '').slice(0, 128),
      JSON.stringify(classScores), JSON.stringify(a.sig.map(s => s.t)), JSON.stringify(a.auth), ENGINE.name, ENGINE.version]);
  return rows[0];
}

async function listDetections(ownerHash, limit = 50, offset = 0) {
  const { rows } = await getPool().query(
    `SELECT id, created_at, message_id, sender, subject, risk_score, risk_label, origin_confidence, threat_type,
            classification, class_scores, indicators, auth_results, engine_name, engine_version, content_sha256
       FROM detections WHERE owner_hash = $1 ORDER BY created_at DESC, id DESC LIMIT $2 OFFSET $3`,
    [ownerHash, limit, offset]);
  return rows;
}

async function deleteDetection(ownerHash, id) {
  const r = await getPool().query('DELETE FROM detections WHERE id = $1 AND owner_hash = $2', [id, ownerHash]);
  return r.rowCount > 0;
}

async function ping() { await getPool().query('SELECT 1'); return true; }

module.exports = { getPool, closePool, initSchema, saveDetection, listDetections, deleteDetection, ping, DbConfigError, ENGINE };
