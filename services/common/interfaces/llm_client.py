from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class LLMResponse:
    text: str
    function_call: Optional[Dict[str, Any]]
    input_tokens: int
    output_tokens: int
    model: str


class LLMClient(ABC):
    """Function-calling-capable LLM behind a thin, provider-agnostic interface."""

    @abstractmethod
    def generate(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> LLMResponse:
        raise NotImplementedError
