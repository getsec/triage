import json
import pathlib

import pytest

from common.models.normalized_alert import NormalizedAlert
from common.normalizers.edr import EdrNormalizer

FIXTURE = pathlib.Path(__file__).parents[3] / "sample_alerts" / "edr.json"


def _raw():
    return json.loads(FIXTURE.read_text())


def test_normalize_returns_single_alert():
    alerts = EdrNormalizer().normalize(_raw())
    assert len(alerts) == 1
    assert isinstance(alerts[0], NormalizedAlert)


def test_field_mapping():
    alert = EdrNormalizer().normalize(_raw())[0]
    assert alert.id == "edr-2026-0001"
    assert alert.source == "edr"
    assert alert.title == "Suspicious PowerShell Execution"
    assert alert.severity == "high"
    assert alert.hostname == "web-prod-01"
    assert alert.code == "T1059.001"
    assert alert.score == 0.92
    assert alert.timestamp == "2026-06-29T10:00:00Z"
    assert alert.link == "https://edr.example/detections/edr-2026-0001"
    assert alert.raw_data == _raw()


def test_missing_required_field_raises():
    raw = _raw()
    del raw["rule_name"]
    with pytest.raises(ValueError):
        EdrNormalizer().normalize(raw)
