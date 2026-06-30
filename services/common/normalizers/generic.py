from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_normalizer import BaseNormalizer


class GenericNormalizer(BaseNormalizer):
    """Best-effort fallback for unknown sources. Never raises so the 'unknown'
    route always produces an alert."""

    @staticmethod
    def _first(raw: Dict[str, Any], keys: Iterable[str], default: Optional[str] = None) -> Optional[str]:
        for key in keys:
            value = raw.get(key)
            if value:
                return str(value)
        return default

    @staticmethod
    def _synthesized_id(raw: Dict[str, Any]) -> str:
        canonical = json.dumps(raw, sort_keys=True, default=str)
        return "gen-" + hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]

    def normalize(self, raw: Dict[str, Any]) -> List[NormalizedAlert]:
        alert = NormalizedAlert(
            id=self._first(raw, ("id", "alert_id", "_id", "uuid")) or self._synthesized_id(raw),
            source=self._first(raw, ("source",)) or "unknown",
            title=self._first(raw, ("title", "name", "summary", "message")) or "Unclassified alert",
            severity=self._first(raw, ("severity", "level", "priority")) or "unknown",
            description=self._first(raw, ("description", "details", "message"), "") or "",
            timestamp=self._first(raw, ("timestamp", "time", "@timestamp")),
            hostname=self._first(raw, ("hostname", "host", "device", "instance")),
            raw_data=raw,
        )
        return [alert]
