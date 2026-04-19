-- Tenant isolation hardening: add tenant_id + Row-Level Security to audit_events.
-- Feature #5 — Multi-Tenant Isolation Hardening.

ALTER TABLE audit_events
  ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT 'poc-default';

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant ON audit_events (tenant_id);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_events_tenant_isolation ON audit_events;
CREATE POLICY audit_events_tenant_isolation ON audit_events
  USING (tenant_id = current_setting('app.current_tenant', true));

-- Helper for the FastAPI dependency — call once per request/transaction.
-- Python usage:  cur.execute("SELECT set_config('app.current_tenant', %s, true)", [tid])
