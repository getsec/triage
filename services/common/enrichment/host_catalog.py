from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional


@dataclass
class HostCatalogEntry:
    type: str
    hostname_patterns: List[str] = field(default_factory=list)
    routing_project: Optional[str] = None
    routing_channel: Optional[str] = None
    standard_operations: Optional[str] = None
    alerting_context: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HostCatalogEntry":
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})

    def to_context(self) -> Dict[str, Any]:
        context = {
            "type": self.type,
            "routing_project": self.routing_project,
            "routing_channel": self.routing_channel,
            "standard_operations": self.standard_operations,
            "alerting_context": self.alerting_context,
        }
        return {key: value for key, value in context.items() if value is not None}


class HostCatalog:
    """Configurable host topology. Operators supply their own; matching is by
    longest hostname prefix. No company-specific data ships in source.
    """

    def __init__(self, entries: List[HostCatalogEntry]) -> None:
        self.entries = entries

    @classmethod
    def from_entries(cls, items: List[Dict[str, Any]]) -> "HostCatalog":
        return cls([HostCatalogEntry.from_dict(item) for item in items])

    @classmethod
    def from_json_file(cls, path: str) -> "HostCatalog":
        with open(path, "r", encoding="utf-8") as handle:
            return cls.from_entries(json.load(handle))

    @classmethod
    def from_env(cls, var_name: str) -> "HostCatalog":
        value = os.environ.get(var_name, "").strip()
        if not value:
            return cls([])
        if value.startswith("[") or value.startswith("{"):
            data = json.loads(value)
            return cls.from_entries(data if isinstance(data, list) else [data])
        return cls.from_json_file(value)

    def lookup(self, hostname: Optional[str]) -> Optional[HostCatalogEntry]:
        if not hostname:
            return None
        target = hostname.lower()
        best: Optional[HostCatalogEntry] = None
        best_len = -1
        for entry in self.entries:
            for pattern in entry.hostname_patterns:
                lowered = pattern.lower()
                if target.startswith(lowered) and len(lowered) > best_len:
                    best = entry
                    best_len = len(lowered)
        return best

    def context_for(self, hostname: Optional[str]) -> Optional[Dict[str, Any]]:
        entry = self.lookup(hostname)
        return entry.to_context() if entry is not None else None
