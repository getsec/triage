from __future__ import annotations

from typing import Any, Dict, List

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_normalizer import BaseNormalizer


class GrafanaNormalizer(BaseNormalizer):
    """Reference normalizer for a metrics/observability source (Grafana-style
    alerting webhook that batches multiple alerts)."""

    def normalize(self, raw: Dict[str, Any]) -> List[NormalizedAlert]:
        elements = raw.get("alerts")
        if not isinstance(elements, list):
            return []
        alerts: List[NormalizedAlert] = []
        for element in elements:
            fingerprint = self.safe_get(element, "fingerprint")
            severity = self.safe_get(element, "labels.severity")
            if not fingerprint or not severity:
                continue
            title = self.safe_get(element, "labels.alertname") or self.safe_get(
                element, "annotations.summary"
            ) or "grafana alert"
            alerts.append(
                NormalizedAlert(
                    id=str(fingerprint),
                    source="grafana",
                    title=str(title),
                    severity=str(severity),
                    description=self.safe_get(element, "annotations.description", "") or "",
                    timestamp=self.safe_get(element, "startsAt"),
                    link=self.safe_get(element, "generatorURL"),
                    hostname=self.safe_get(element, "labels.instance"),
                    code=self.safe_get(element, "labels.grafana_code"),
                    raw_data=element,
                )
            )
        return alerts
