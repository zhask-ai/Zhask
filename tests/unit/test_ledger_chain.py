"""Hash-chain + Merkle + tenant-stream unit tests (Feature #2 & #5)."""

from __future__ import annotations

import pytest

from shared.audit.ledger import (
    GENESIS_HASH,
    LedgerEntry,
    entry_hash,
    merkle_root,
    verify_chain,
)
from shared.event_bus.streams import parse_stream_name, stream_name


def _chain(n: int) -> list[LedgerEntry]:
    entries: list[LedgerEntry] = []
    prev = GENESIS_HASH
    for i in range(n):
        payload = {"i": i, "data": f"event-{i}"}
        ts = f"2026-04-19T00:00:{i:02d}+00:00"
        h = entry_hash(prev, payload, ts)
        entries.append(
            LedgerEntry(
                seq=i + 1,
                tenant_id="acme",
                event_type="test",
                payload=payload,
                timestamp=ts,
                prev_hash=prev,
                hash=h,
            )
        )
        prev = h
    return entries


def test_chain_verifies_clean():
    ok, bad = verify_chain(_chain(25))
    assert ok is True
    assert bad is None


def test_chain_detects_payload_tamper():
    chain = _chain(10)
    tampered = chain[4]
    chain[4] = LedgerEntry(
        seq=tampered.seq,
        tenant_id=tampered.tenant_id,
        event_type=tampered.event_type,
        payload={"i": 999, "data": "evil"},
        timestamp=tampered.timestamp,
        prev_hash=tampered.prev_hash,
        hash=tampered.hash,
    )
    ok, bad = verify_chain(chain)
    assert ok is False
    assert bad == 4


def test_merkle_root_is_deterministic_and_reacts_to_change():
    c1 = [e.hash for e in _chain(8)]
    r1 = merkle_root(c1)
    r2 = merkle_root(c1)
    assert r1 == r2
    c1[3] = "ff" * 32
    assert merkle_root(c1) != r1


def test_stream_naming_is_tenant_scoped():
    assert stream_name("acme", "anomaly_events") == "integrishield:acme:anomaly_events"
    tid, family = parse_stream_name("integrishield:acme:anomaly_events")
    assert tid == "acme" and family == "anomaly_events"


def test_stream_naming_rejects_bad_tenants():
    with pytest.raises(Exception):
        stream_name("../evil", "foo")
    with pytest.raises(ValueError):
        stream_name("acme", "bad:family")
