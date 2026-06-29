import json
import pathlib

from common.normalizers.generic import GenericNormalizer

FIXTURE = pathlib.Path(__file__).parents[3] / "sample_alerts" / "generic.json"


def _raw():
    return json.loads(FIXTURE.read_text())


def test_maps_common_aliases():
    alert = GenericNormalizer().normalize(_raw())[0]
    assert alert.source == "custom_scanner"
    assert alert.title == "Port scan detected"
    assert alert.severity == "medium"
    assert alert.hostname == "k8s-worker-07"
    assert alert.description == "Sequential connection attempts across 1024 ports."
    assert alert.timestamp == "2026-06-29T12:00:00Z"


def test_never_raises_on_empty_payload():
    alert = GenericNormalizer().normalize({})[0]
    assert alert.source == "unknown"
    assert alert.title
    assert alert.severity
    assert alert.id.startswith("gen-")


def test_synthesized_id_is_deterministic():
    a = GenericNormalizer().normalize({"foo": "bar"})[0]
    b = GenericNormalizer().normalize({"foo": "bar"})[0]
    assert a.id == b.id


def test_explicit_id_is_used():
    alert = GenericNormalizer().normalize({"id": "explicit-1", "title": "t"})[0]
    assert alert.id == "explicit-1"
