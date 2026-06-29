from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class AccessGrant:
    id: str
    user: str
    resource: str
    granted_at: str
    expires_at: Optional[str] = None
    justification: Optional[str] = None
    approver: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_webhook(cls, payload: Dict[str, Any]) -> "AccessGrant":
        return cls(
            id=payload["id"],
            user=payload["user"],
            resource=payload["resource"],
            granted_at=payload.get("granted_at") or _utcnow().isoformat(),
            expires_at=payload.get("expires_at"),
            justification=payload.get("justification"),
            approver=payload.get("approver"),
            raw_data=dict(payload),
        )

    def is_active(self, now: Optional[datetime] = None) -> bool:
        now = now or _utcnow()
        expiry = _parse_ts(self.expires_at)
        return True if expiry is None else expiry > now

    def matches_user(self, user: str) -> bool:
        return self.user.lower() == user.lower()

    def matches_resource(self, resource: str) -> bool:
        return resource.lower() in self.resource.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_store_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccessGrant":
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})
