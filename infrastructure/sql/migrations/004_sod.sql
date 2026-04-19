-- Feature #1 — SAP SoD Violation Graph.

CREATE TABLE IF NOT EXISTS sod_risks (
  risk_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  description TEXT,
  conflicting_tcodes JSONB NOT NULL,
  control_ref TEXT
);

CREATE TABLE IF NOT EXISTS sod_role_tcode_map (
  tenant_id TEXT NOT NULL,
  role TEXT NOT NULL,
  tcode TEXT NOT NULL,
  PRIMARY KEY (tenant_id, role, tcode)
);

CREATE TABLE IF NOT EXISTS sod_user_role_snapshot (
  tenant_id TEXT NOT NULL,
  sap_user TEXT NOT NULL,
  role TEXT NOT NULL,
  captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, sap_user, role)
);

CREATE TABLE IF NOT EXISTS sod_violations (
  violation_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  sap_user TEXT NOT NULL,
  risk_id TEXT NOT NULL REFERENCES sod_risks(risk_id),
  severity TEXT NOT NULL,
  conflicting_tcodes JSONB NOT NULL,
  roles_involved JSONB NOT NULL,
  first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'open'
);

CREATE INDEX IF NOT EXISTS idx_sod_violations_tenant_user ON sod_violations (tenant_id, sap_user);
CREATE INDEX IF NOT EXISTS idx_sod_violations_status ON sod_violations (status);
