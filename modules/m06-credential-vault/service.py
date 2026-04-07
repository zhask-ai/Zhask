from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


@dataclass
class VaultSecret:
    key: str
    value: str
    rotated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def rotate_secret(secret: VaultSecret, new_value: str) -> VaultSecret:
    secret.value = new_value
    secret.rotated_at = datetime.now(timezone.utc)
    return secret


def needs_rotation(secret: VaultSecret, max_age_days: int = 30) -> bool:
    return datetime.now(timezone.utc) - secret.rotated_at > timedelta(days=max_age_days)
