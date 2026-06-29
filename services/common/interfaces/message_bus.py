from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class MessageBus(ABC):
    """Decouples ingest from processing. Default impl: Redis Streams."""

    @abstractmethod
    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
        """Publish a payload to a topic; return the message id."""
        raise NotImplementedError
