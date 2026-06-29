from __future__ import annotations

from typing import Any, Dict, List

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_normalizer import BaseNormalizer


class EdrNormalizer(BaseNormalizer):
    """Reference normalizer for an endpoint/EDR detection source."""

    REQUIRED = ("detection_id", "rule_name", "severity")

    def normalize(self, raw: Dict[str, Any]) -> List[NormalizedAlert]:
        self.validate_required_fields(raw, self.REQUIRED)
        alert = NormalizedAlert(
            id=str(raw["detection_id"]),
            source="edr",
            title=str(raw["rule_name"]),
            severity=str(raw["severity"]),
            description=self.safe_get(raw, "description", "") or "",
            timestamp=self.safe_get(raw, "timestamp"),
            link=self.safe_get(raw, "link"),
            hostname=self.safe_get(raw, "device.hostname"),
            code=self.safe_get(raw, "rule_code"),
            score=self.safe_get(raw, "confidence"),
            raw_data=raw,
        )
        return [alert]
