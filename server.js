'use strict';
// Local dev / generic Node host server. On Vercel, /api/*.js are served as Functions and public/ as static files.
try { process.loadEnvFile && process.loadEnvFile(); } catch (_) { /* .env optional */ }
const http = require('http');
const fs = require('fs');
const path = require('path');
const { MAX_EMAIL_BYTES } = require('./lib/http');

const routes = { '/api/analyze': require('./api/analyze'), '/api/history': require('./api/history'), '/api/health': require('./api/health') };
const PUB = path.join(__dirname, 'public');
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_EMAIL_BYTES * 2) { reject(Object.assign(new Error('too large'), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname;
  if (routes[p]) {
    if (req.method === 'POST') {
      try { const t = await readBody(req); req.body = t ? JSON.parse(t) : undefined; }
      catch (e) { res.statusCode = e.code === 413 ? 413 : 400; res.setHeader('Content-Type', 'application/json'); return res.end(JSON.stringify({ error: e.code === 413 ? 'Payload too large' : 'Invalid JSON body' })); }
    }
    return routes[p](req, res);
  }
  const file = p === '/' ? 'index.html' : p.slice(1);
  const full = path.join(PUB, file);
  if (!full.startsWith(PUB + path.sep) || !fs.existsSync(full) || !fs.statSync(full).isFile()) { res.statusCode = 404; return res.end('Not found'); }
  res.setHeader('Content-Type', TYPES[path.extname(full)] || 'application/octet-stream');
  fs.createReadStream(full).pipe(res);
});
if (require.main === module) {
  const port = Number(process.env.PORT || 3000);
  server.listen(port, () => console.log(`SentinelTrace AI on http://localhost:${port}`));
}
module.exports = server;
