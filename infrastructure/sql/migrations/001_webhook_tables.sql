-- Migration 001: Webhook Gateway tables (M14)
-- Applies to: PostgreSQL (production) and SQLite (dev/test via m14's db.py)

-- Webhook subscription registry
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id           TEXT        PRIMARY KEY,
    url          TEXT        NOT NULL,
    secret       TEXT        NOT NULL DEFAULT '',
    event_filter JSONB       NOT NULL DEFAULT '[]',
    active       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ws_active ON webhook_subscriptions (active);

-- Delivery log
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id               TEXT        PRIMARY KEY,
    subscription_id  TEXT        NOT NULL REFERENCES webhook_subscriptions(id),
    event_id         TEXT        NOT NULL,
    event_type       TEXT        NOT NULL,
    payload          JSONB       NOT NULL DEFAULT '{}',
    status           TEXT        NOT NULL DEFAULT 'pending'
                                 CHECK (status IN ('pending','delivered','failed','dlq')),
    attempt_count    INTEGER     NOT NULL DEFAULT 0,
    last_attempt_at  TIMESTAMPTZ,
    delivered_at     TIMESTAMPTZ,
    error_message    TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_wd_subscription ON webhook_deliveries (subscription_id);
CREATE INDEX IF NOT EXISTS idx_wd_status       ON webhook_deliveries (status);
CREATE INDEX IF NOT EXISTS idx_wd_event        ON webhook_deliveries (event_id);
