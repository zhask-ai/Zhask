# M18 — Tamper-Evident Audit Ledger

Per-tenant hash-chained append-only log with periodic Merkle anchors.

## Run

```bash
PYTHONPATH=modules/m18-ledger/src:shared \
  uvicorn integrishield.m18.main:app --reload --port 8018
```

## Endpoints

- `POST /ledger/append` — append event `{event_type, payload}`
- `GET  /ledger/entries?start=&end=` — list chain entries
- `POST /ledger/anchor` — compute + persist Merkle root for the current chain
- `GET  /ledger/anchors` — list anchors
- `POST /ledger/verify` — verify chain integrity end-to-end

All endpoints scoped to the caller's tenant (`X-Tenant-ID`).

## Guarantees

- `entry_hash = SHA256(prev_hash || canonical_json(payload) || timestamp)`
- Postgres table has `BEFORE UPDATE/DELETE` triggers that raise — append only.
- Anchors can be externally witnessed by committing `ledger_anchors` rows to git.
