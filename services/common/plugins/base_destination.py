from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from common.models.normalized_alert import NormalizedAlert


class BaseDestination(ABC):
    """A place alerts are sent: a ticketing system, a chat channel, etc."""

    @abstractmethod
    def send_alert(
        self, alert: NormalizedAlert, ai_analysis: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Create the ticket/message; return its id, or None on failure."""
        raise NotImplementedError

    @abstractmethod
    def is_configured(self) -> bool:
        raise NotImplementedError

    def enrich_alert(self, alert: NormalizedAlert, ticket_id: str) -> bool:
        """Optional post-creation enrichment hook. No-op by default."""
        return False
