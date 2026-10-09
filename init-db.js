'use strict';
try { process.loadEnvFile && process.loadEnvFile(); } catch (_) { /* .env optional */ }
const db = require('../lib/db');
db.initSchema()
  .then(() => { console.log('Schema initialised.'); return db.closePool(); })
  .catch(e => { console.error('Schema init failed:', e.name === 'DbConfigError' ? e.message : (e.code || e.message)); process.exit(1); });
