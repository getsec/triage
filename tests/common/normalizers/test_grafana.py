import json
import pathlib

from common.normalizers.grafana import GrafanaNormalizer

FIXTURE = pathlib.Path(__file__).parents[3] / "sample_alerts" / "grafana.json"


def _raw():
    return json.loads(FIXTURE.read_text())


def test_normalize_returns_one_alert_per_element():
    alerts = GrafanaNormalizer().normalize(_raw())
    assert len(alerts) == 2
    assert [a.id for a in alerts] == ["graf-cpu-001", "graf-mem-002"]


def test_field_mapping():
    first = GrafanaNormalizer().normalize(_raw())[0]
    assert first.source == "grafana"
    assert first.title == "HighCPU"
    assert first.severity == "warning"
    assert first.hostname == "db-prod-02"
    assert first.code == "CPU-001"
    assert first.timestamp == "2026-06-29T11:00:00Z"
    assert first.link == "https://grafana.example/alerting/graf-cpu-001"
    assert first.description == "CPU usage sustained above 90% for 5m."
    assert first.raw_data == _raw()["alerts"][0]


def test_title_falls_back_to_annotations_summary():
    raw = {"alerts": [
        {"fingerprint": "x", "labels": {"severity": "info"},
         "annotations": {"summary": "Fallback title"}},
    ]}
    alert = GrafanaNormalizer().normalize(raw)[0]
    assert alert.title == "Fallback title"


def test_empty_or_missing_alerts_returns_empty_list():
    assert GrafanaNormalizer().normalize({"status": "firing", "alerts": []}) == []
    assert GrafanaNormalizer().normalize({"status": "ok"}) == []


def test_elements_missing_required_fields_are_skipped():
    raw = {"alerts": [
        {"fingerprint": "ok-1", "labels": {"alertname": "A", "severity": "high"}},
        {"labels": {"alertname": "NoFingerprint", "severity": "high"}},
        {"fingerprint": "no-sev", "labels": {"alertname": "B"}},
    ]}
    alerts = GrafanaNormalizer().normalize(raw)
    assert [a.id for a in alerts] == ["ok-1"]
