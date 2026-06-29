from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List

from common.models.normalized_alert import NormalizedAlert


class BaseNormalizer(ABC):
    """Turns one raw source payload into zero or more NormalizedAlerts."""

    @abstractmethod
    def normalize(self, raw: Dict[str, Any]) -> List[NormalizedAlert]:
        raise NotImplementedError

    @staticmethod
    def validate_required_fields(raw: Dict[str, Any], required: Iterable[str]) -> None:
        missing = [key for key in required if not raw.get(key)]
        if missing:
            raise ValueError(f"raw payload missing required fields: {missing}")

    @staticmethod
    def safe_get(data: Dict[str, Any], path: str, default: Any = None) -> Any:
        current: Any = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current
