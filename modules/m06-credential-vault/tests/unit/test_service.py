"""Unit tests for M06 Credential Vault secret lifecycle."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from integrishield.m06.models import RotationUrgency, SecretStatus
from integrishield.m06.services import get_stats, list_secrets, needs_rotation, rotate_secret, store_secret


def test_store_and_list():
    store_secret("test-key-1", "val1", owner_module="m01")
    secrets = list_secrets()
    assert any(s.key == "test-key-1" for s in secrets)


def test_rotate_updates_secret():
    store_secret("rotate-key", "old_val")
    result = rotate_secret("rotate-key", "new_val")
    assert result.rotated is True
    assert result.new_status == SecretStatus.ACTIVE


def test_rotate_nonexistent_returns_false():
    result = rotate_secret("nonexistent", "val")
    assert result.rotated is False


def test_fresh_secret_does_not_need_rotation():
    store_secret("fresh-key", "val")
    urgency = needs_rotation("fresh-key")
    assert urgency == RotationUrgency.OK


def test_nonexistent_secret_is_critical():
    urgency = needs_rotation("does-not-exist")
    assert urgency == RotationUrgency.CRITICAL


def test_stats_counts():
    # Clear and recreate for deterministic test
    store_secret("stats-key-1", "v1")
    store_secret("stats-key-2", "v2")
    stats = get_stats()
    assert stats["total_secrets"] >= 2
    assert stats["active"] >= 2
