from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from common.models.access_grant import AccessGrant
from common.models.normalized_alert import NormalizedAlert


class DocumentStore(ABC):
    """Shared state: alerts (+ vector index), ticket index, JIT grants.

    Default impl: Postgres + pgvector.
    """

    @abstractmethod
    def save_alert(self, alert: NormalizedAlert) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_alert(self, alert_id: str) -> Optional[NormalizedAlert]:
        raise NotImplementedError

    @abstractmethod
    def vector_search(
        self,
        embedding: List[float],
        limit: int,
        threshold: float,
        lookback_seconds: int,
    ) -> List[NormalizedAlert]:
        """Return open-ticket alerts within the lookback window above the similarity threshold."""
        raise NotImplementedError

    @abstractmethod
    def find_open_ticket_by_host_code(self, hostname: str, code: str) -> Optional[NormalizedAlert]:
        raise NotImplementedError

    @abstractmethod
    def save_grant(self, grant: AccessGrant) -> None:
        raise NotImplementedError

    @abstractmethod
    def find_active_grants(
        self, user: Optional[str] = None, resource: Optional[str] = None
    ) -> List[AccessGrant]:
        raise NotImplementedError
