from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from common.models.duplicate_match import DuplicateMatch
from common.models.normalized_alert import NormalizedAlert


class Deduplicator(ABC):
    """Finds a prior open-ticket alert that duplicates this one.

    Implementations MUST fail open: on any internal error, return None
    (do not suppress the alert).
    """

    @abstractmethod
    def find_duplicate(
        self, alert: NormalizedAlert, embedding: Optional[List[float]] = None
    ) -> Optional[DuplicateMatch]:
        raise NotImplementedError
