from __future__ import annotations

import glob
import os
from typing import List, Optional

from common.normalizers.declarative import DeclarativeNormalizer
from common.normalizers.generic import GenericNormalizer
from common.normalizers.spec import NormalizerSpec
from common.plugins.registries import FALLBACK_KEY, register_normalizer


def load_specs_from_dir(directory: str) -> List[DeclarativeNormalizer]:
    paths: List[str] = []
    for pattern in ("*.yaml", "*.yml"):
        paths.extend(glob.glob(os.path.join(directory, pattern)))
    return [DeclarativeNormalizer(NormalizerSpec.from_yaml(path)) for path in sorted(paths)]


def register_default_normalizers(specs_dir: Optional[str] = None) -> None:
    """Register a DeclarativeNormalizer per YAML spec in specs_dir (if any),
    plus the GenericNormalizer fallback. No import-time side effects."""
    if specs_dir and os.path.isdir(specs_dir):
        for normalizer in load_specs_from_dir(specs_dir):
            register_normalizer(normalizer.spec.source, normalizer)
    register_normalizer(FALLBACK_KEY, GenericNormalizer())
