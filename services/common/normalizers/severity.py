from __future__ import annotations

from typing import Any, Dict, Optional

from common.models.normalized_alert import SEVERITY_BANDS

_DEFAULT_BAND = "medium"


def _to_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def normalize_severity(value: Any, severity_map: Optional[Dict[str, Any]] = None) -> str:
    severity_map = severity_map or {}

    if value is not None:
        key = str(value).strip().lower()
        exact = {str(k).strip().lower(): band for k, band in severity_map.get("exact", {}).items()}
        if key in exact:
            return exact[key]
        if key in SEVERITY_BANDS:
            return key

    number = _to_float(value)
    if number is not None:
        for rule in severity_map.get("ranges", []):
            low = rule.get("min", float("-inf"))
            high = rule.get("max", float("inf"))
            if low <= number <= high:
                return rule["band"]

    return severity_map.get("default", _DEFAULT_BAND)
