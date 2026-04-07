CREATE TABLE IF NOT EXISTS audit_events (
  id BIGSERIAL PRIMARY KEY,
  event_id UUID NOT NULL UNIQUE,
  timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  module_name TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical', 'medium', 'low')),
  scenario TEXT NOT NULL,
  source_ip INET,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp_utc DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events (severity);
CREATE INDEX IF NOT EXISTS idx_audit_events_scenario ON audit_events (scenario);
