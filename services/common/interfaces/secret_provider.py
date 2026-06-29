from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class SecretProvider(ABC):
    """Resolves named secrets. Default impl: env / Docker secrets (Vault later)."""

    @abstractmethod
    def get_secret(self, name: str) -> Optional[str]:
        raise NotImplementedError
