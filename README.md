# SentinelTrace AI – Email Forensic Intelligence

Paste or upload a raw email (`.eml`) and get a forensic analysis: SPF/DKIM/DMARC results, delivery path, lookalike-domain and impersonation checks, IOCs, relationship graph and a **0–100 risk score**. Every analysis is saved to PostgreSQL and shown in a per-browser **Detection History**.

## Important: what the "detection" actually is
The uploaded project contained **no machine-learning model, no trained artifacts and no datasets**. Scoring is the original **rule-based engine** (weighted indicators → `risk = 100·(1−e^(−sum/50))`), moved unchanged into `lib/engine.js`. A test (`tests/engine.test.js`) runs the original `app.js` analysis code and asserts identical output. No accuracy/precision/recall has been measured, so none is claimed.

Score meanings: `risk` = heuristic fraud-risk score (not a calibrated probability); the class breakdown (`probs`) is that risk split across categories by indicator weight; `origin confidence` = how reliable the technical evidence is. LOW < 40 ≤ MEDIUM < 75 ≤ HIGH.

## Architecture
```
Browser (public/: HTML+JS)  --HTTPS-->  Vercel Functions (api/*.js, Node)  -->  PostgreSQL (Neon / Supabase / Vercel Postgres)
                                          └ lib/engine.js (rule engine)         └ table: detections
```
Everything except the database runs on Vercel (static files + Node Functions). The database is an external managed PostgreSQL service. Chosen because the data is relational/time-ordered and Vercel Functions connect to hosted Postgres over TLS; no Python/ML runtime is needed since there is no model.

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze` `{raw}` | validate → analyse → save → return result |
| `GET /api/history?limit&offset` | this browser's saved detections |
| `DELETE /api/history?id=` | delete own record |
| `GET /api/health` | API + DB status (200 / 503) |

Folder layout: `api/` functions · `lib/` engine, DB layer, HTTP helpers · `db/schema.sql` · `public/` frontend · `scripts/init-db.js` · `server.js` local server · `tests/`.

## Prerequisites
Node.js ≥ 20 and a PostgreSQL database (local or hosted).

## Setup
```bash
npm install
cp .env.example .env          # then set DATABASE_URL
npm run db:init               # creates the table (idempotent)
npm start                     # http://localhost:3000
```
Local Postgres example: `DATABASE_URL=postgresql://user:pass@localhost:5432/sentinel` and `DATABASE_SSL=false`.

## Environment variables
`DATABASE_URL` (required) · `DATABASE_SSL` (`false` only for non-TLS local DB) · `ALLOWED_ORIGINS` (only needed if the UI is served from a different origin) · `MAX_EMAIL_BYTES` (default 200000) · `PORT` (local only).

## Tests
```bash
TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/testdb npm test
```
Without `TEST_DATABASE_URL` the DB integration tests are skipped (engine and DB-failure tests still run). Use a throwaway database: the tests `TRUNCATE detections`.

## Deploy
1. **Database:** create a free PostgreSQL project (e.g. Neon) and copy its connection string.
2. **Init schema once** from your machine: `DATABASE_URL="<conn string>" npm run db:init`.
3. **GitHub:** create an empty repo `email-detection-scoring` in the browser, then
   ```bash
   git remote add origin https://github.com/<you>/email-detection-scoring.git
   git branch -M main && git push -u origin main
   ```
4. **Vercel:** *Add New → Project → import the repo*. Framework preset: *Other*; no build command; output directory is read from `vercel.json` (`public`). Add environment variable `DATABASE_URL` (Production + Preview). Deploy.
5. Verify: open `https://<project>.vercel.app/api/health` → `{"status":"ok","database":"connected"}`, then analyse the demo email.

After editing `lib/engine.js`, copy it to `public/engine.js` (a test enforces they match).

## Troubleshooting
- `/api/health` → `not_configured`: `DATABASE_URL` missing in Vercel env (redeploy after adding it).
- `unreachable`: wrong host/password, DB paused, or provider requires a pooled connection string.
- 401 from API: browser blocked `localStorage` (the per-browser key can't persist).
- Self-signed TLS errors with a local DB: set `DATABASE_SSL=false`.

## Security & privacy
- The raw email is processed in memory and **not stored**; saved fields: sender, subject, message-ID, scores, indicators, auth results, SHA-256 of the email, engine version. Subject/sender can still be personal data: don't use real private mail on a public demo.
- Access control is an anonymous 256-bit per-browser key (only its hash is stored). This isolates records between browsers but is **not user authentication**; anyone with the key can read that history, and clearing browser storage loses access.
- No rate limiting is implemented; add one (e.g. Vercel Firewall) before real public use.
- Parameterized queries only; credentials only via environment variables; error responses never include connection details.

## Known limitations
Rule-based heuristics (can miss novel attacks and flag legitimate mail); GeoIP is a tiny demo table; Overview KPIs, Campaigns and seeded cases are demo data; Cases and Evidence live in browser `localStorage`, not the database.
