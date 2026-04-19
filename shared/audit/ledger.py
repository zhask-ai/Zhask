"""Hash-chained ledger primitives.

Each entry commits to its predecessor via SHA-256, producing a tamper-evident
log. Periodic Merkle roots are computed by the m18-ledger service and
persisted as external witnesses.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

GENESIS_HASH = "0" * 64


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def entry_hash(prev_hash: str, payload: Any, timestamp: str) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("ascii"))
    h.update(b"\x1f")
    h.update(canonical_json(payload))
    h.update(b"\x1f")
    h.update(timestamp.encode("ascii"))
    return h.hexdigest()


def merkle_root(leaves: Iterable[str]) -> str:
    level = [bytes.fromhex(leaf) for leaf in leaves]
    if not level:
        return GENESIS_HASH
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()


@dataclass(frozen=True)
class LedgerEntry:
    seq: int
    tenant_id: str
    event_type: str
    payload: dict[str, Any]
    timestamp: str
    prev_hash: str
    hash: str = field(default="")

    def compute_hash(self) -> str:
        return entry_hash(self.prev_hash, self.payload, self.timestamp)


def verify_chain(entries: list[LedgerEntry]) -> tuple[bool, int | None]:
    prev = GENESIS_HASH
    for idx, e in enumerate(entries):
        if e.prev_hash != prev:
            return False, idx
        if e.compute_hash() != e.hash:
            return False, idx
        prev = e.hash
    return True, None
