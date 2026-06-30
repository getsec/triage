import json
import pathlib

import pytest

from common.normalizers.declarative import DeclarativeNormalizer
from common.normalizers.spec import NormalizerSpec

ROOT = pathlib.Path(__file__).parents[3]
SPECS = ROOT / "config" / "normalizers"
FIXTURES = ROOT / "sample_alerts"


def _run(source):
    spec = NormalizerSpec.from_yaml(str(SPECS / f"{source}.yaml"))
    raw = json.loads((FIXTURES / f"{source}.json").read_text())
    return DeclarativeNormalizer(spec).normalize(raw)


def test_edr_spec():
    alerts = _run("edr")
    assert len(alerts) == 1
    a = alerts[0]
    assert a.id == "edr-2026-0001"
    assert a.source == "edr"
    assert a.severity == "high"            # passthrough
    assert a.finding_class == "threat_detection"
    assert a.hostname == "web-prod-01"
    assert a.code == "T1059.001"
    assert a.score == 0.92


def test_grafana_spec():
    alerts = _run("grafana")
    assert [a.id for a in alerts] == ["graf-cpu-001", "graf-mem-002"]
    assert alerts[0].source == "grafana"
    assert alerts[0].severity == "medium"  # "warning" -> medium via exact map
    assert alerts[1].severity == "critical"  # passthrough
    assert alerts[0].finding_class == "threat_detection"
    assert alerts[0].hostname == "db-prod-02"


def test_guardduty_spec():
    a = _run("guardduty")[0]
    assert a.id == "gd-finding-1"
    assert a.source == "guardduty"
    assert a.severity == "medium"          # 5.0 -> medium
    assert a.finding_class == "threat_detection"
    assert a.cloud_provider == "aws"       # literal default
    assert a.cloud_account_id == "111122223333"
    assert a.resource_id == "i-0abcd1234ef567890"


def test_crowdstrike_spec():
    a = _run("crowdstrike")[0]
    assert a.id == "cs-alert-1"
    assert a.severity == "critical"        # 85 -> critical (CPS)
    assert a.finding_class == "threat_detection"
    assert a.hostname == "win-ep-01"
    assert a.code == "T1059.001"
