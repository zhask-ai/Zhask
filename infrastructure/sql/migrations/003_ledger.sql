-- Feature #2 — Tamper-Evident Audit Ledger.
-- Append-only hash-chained log with periodic Merkle anchors.

CREATE TABLE IF NOT EXISTS ledger_entries (
  seq BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  timestamp_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  prev_hash CHAR(64) NOT NULL,
  entry_hash CHAR(64) NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_ledger_tenant_seq ON ledger_entries (tenant_id, seq);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_ts  ON ledger_entries (tenant_id, timestamp_utc);

-- Block UPDATE/DELETE on the ledger at the DB level.
CREATE OR REPLACE FUNCTION ledger_block_mutation() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'ledger_entries is append-only';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ledger_no_update ON ledger_entries;
CREATE TRIGGER ledger_no_update BEFORE UPDATE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION ledger_block_mutation();
DROP TRIGGER IF EXISTS ledger_no_delete ON ledger_entries;
CREATE TRIGGER ledger_no_delete BEFORE DELETE ON ledger_entries
  FOR EACH ROW EXECUTE FUNCTION ledger_block_mutation();

CREATE TABLE IF NOT EXISTS ledger_anchors (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL,
  window_end   TIMESTAMPTZ NOT NULL,
  first_seq BIGINT NOT NULL,
  last_seq  BIGINT NOT NULL,
  entry_count INTEGER NOT NULL,
  merkle_root CHAR(64) NOT NULL,
  signed_by TEXT,
  signature TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anchors_tenant_window ON ledger_anchors (tenant_id, window_end DESC);
