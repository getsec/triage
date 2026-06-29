from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DuplicateMatch:
    alert_id: str
    ticket_id: str
    ticket_url: Optional[str] = None
    similarity: Optional[float] = None
    match_type: str = "unknown"
