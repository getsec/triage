from __future__ import annotations

from typing import Any, Dict, List

from common.models.normalized_alert import NormalizedAlert
from common.normalizers.severity import normalize_severity
from common.normalizers.spec import NormalizerSpec
from common.plugins.base_normalizer import BaseNormalizer

_EMPTY = (None, "", [], {})


class DeclarativeNormalizer(BaseNormalizer):
    """A normalizer driven entirely by a YAML-defined NormalizerSpec."""

    def __init__(self, spec: NormalizerSpec) -> None:
        self.spec = spec

    def normalize(self, raw: Dict[str, Any]) -> List[NormalizedAlert]:
        spec = self.spec
        if spec.alerts_path:
            elements = self.safe_get(raw, spec.alerts_path)
            if not isinstance(elements, list):
                return []
            batched = True
        else:
            elements = [raw]
            batched = False

        alerts: List[NormalizedAlert] = []
        for element in elements:
            try:
                alerts.append(self._build(element))
            except ValueError:
                if batched:
                    continue
                raise
        return alerts

    def _resolve(self, element: Dict[str, Any], mapping: Any) -> Any:
        paths = mapping if isinstance(mapping, list) else [mapping]
        for path in paths:
            value = self.safe_get(element, path)
            if value not in _EMPTY:
                return value
        return None

    def _build(self, element: Dict[str, Any]) -> NormalizedAlert:
        spec = self.spec
        values: Dict[str, Any] = {}
        for field_name, mapping in spec.field_map.items():
            values[field_name] = self._resolve(element, mapping)
        for key, default in spec.defaults.items():
            if values.get(key) in _EMPTY:
                values[key] = default

        # Validate required fields against resolved values (not raw keys),
        # so fallback-chain mappings count toward satisfying requirements.
        self.validate_required_fields(values, spec.required)

        values["severity"] = normalize_severity(values.get(spec.severity_field), spec.severity_map)
        values["source"] = spec.source
        values["raw_data"] = element
        if spec.finding_class is not None:
            values["finding_class"] = spec.finding_class
        if spec.delivery_method is not None:
            values["delivery_method"] = spec.delivery_method
        return NormalizedAlert.from_dict(values)
