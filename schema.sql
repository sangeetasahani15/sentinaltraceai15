-- SentinelTrace AI schema (PostgreSQL). Idempotent: safe to run repeatedly.
CREATE TABLE IF NOT EXISTS detections (
  id            BIGSERIAL PRIMARY KEY,
  owner_hash    CHAR(64)      NOT NULL,              -- SHA-256 of the per-browser client key (never the key itself)
  content_sha256 CHAR(64)     NOT NULL,              -- hash of the raw email; the email body itself is NOT stored
  message_id    VARCHAR(512),
  sender        VARCHAR(320),
  subject       VARCHAR(998),
  risk_score    SMALLINT      NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  risk_label    VARCHAR(8)    NOT NULL CHECK (risk_label IN ('LOW','MEDIUM','HIGH')),
  origin_confidence SMALLINT  NOT NULL CHECK (origin_confidence BETWEEN 0 AND 100),
  threat_type   VARCHAR(128)  NOT NULL,
  classification VARCHAR(128) NOT NULL,
  class_scores  JSONB         NOT NULL,              -- [{label, percent}] as produced by the engine
  indicators    JSONB         NOT NULL,              -- triggered rule descriptions
  auth_results  JSONB         NOT NULL,              -- spf / dkim / dmarc
  engine_name   VARCHAR(64)   NOT NULL,
  engine_version VARCHAR(32)  NOT NULL,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_detections_owner_created ON detections (owner_hash, created_at DESC, id DESC);
