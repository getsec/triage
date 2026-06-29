from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class NormalizerSpec:
    source: str
    field_map: Dict[str, Any] = field(default_factory=dict)
    required: List[str] = field(default_factory=list)
    alerts_path: Optional[str] = None
    defaults: Dict[str, Any] = field(default_factory=dict)
    finding_class: Optional[str] = None
    delivery_method: Optional[str] = None
    severity_field: str = "severity"
    severity_map: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> NormalizerSpec:
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})

    @classmethod
    def from_yaml(cls, path: str) -> NormalizerSpec:
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_dict(yaml.safe_load(handle) or {})
