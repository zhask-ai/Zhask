-- Feature #3 — Threat Intel Fusion.

CREATE TABLE IF NOT EXISTS intel_cve (
  cve_id TEXT PRIMARY KEY,
  kev BOOLEAN NOT NULL DEFAULT FALSE,
  kev_added_at TIMESTAMPTZ,
  epss NUMERIC(5,4),
  epss_percentile NUMERIC(5,4),
  cvss NUMERIC(3,1),
  summary TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_intel_cve_kev ON intel_cve (kev) WHERE kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_intel_cve_epss ON intel_cve (epss DESC);

CREATE TABLE IF NOT EXISTS intel_ip (
  ip INET PRIMARY KEY,
  abuse_score INTEGER,
  categories JSONB,
  sources JSONB,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS intel_sap_notes (
  note_id TEXT PRIMARY KEY,
  title TEXT,
  priority TEXT,
  cve_refs JSONB,
  published_at DATE,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS intel_sources (
  name TEXT PRIMARY KEY,
  last_pulled_at TIMESTAMPTZ,
  last_success BOOLEAN,
  last_error TEXT,
  etag TEXT
);
