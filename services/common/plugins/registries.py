from __future__ import annotations

from typing import Dict

from common.plugins.base_normalizer import BaseNormalizer

FALLBACK_KEY = "unknown"

NORMALIZERS: Dict[str, BaseNormalizer] = {}


def register_normalizer(key: str, normalizer: BaseNormalizer) -> None:
    NORMALIZERS[key] = normalizer


def get_normalizer(source: str) -> BaseNormalizer:
    if source in NORMALIZERS:
        return NORMALIZERS[source]
    return NORMALIZERS[FALLBACK_KEY]
