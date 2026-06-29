from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class TableSchema:
    name: str
    columns: List[Dict[str, Any]] = field(default_factory=list)
    requires_partition_filter: bool = False


class TelemetryClient(ABC):
    """Read-only telemetry/EDR backend for the investigator agent."""

    @abstractmethod
    def list_tables(self, substr: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def describe_table(self, table: str) -> TableSchema:
        raise NotImplementedError

    @abstractmethod
    def query(self, sql: str) -> List[Dict[str, Any]]:
        """Run one row-capped SELECT and return rows as dicts."""
        raise NotImplementedError
