import pytest

from common.normalizers.declarative import DeclarativeNormalizer
from common.normalizers.spec import NormalizerSpec

SINGLE = NormalizerSpec.from_dict({
    "source": "guardduty",
    "finding_class": "threat_detection",
    "delivery_method": "eventbridge",
    "required": ["id", "title"],
    "field_map": {
        "id": "id",
        "title": ["title", "type"],
        "severity": "severity",
        "hostname": "resource.instanceId",
        "resource_id": "resource.arn",
    },
    "defaults": {"description": ""},
    "severity_map": {"ranges": [{"min": 0, "max": 3.9, "band": "low"},
                                {"min": 4, "max": 6.9, "band": "medium"},
                                {"min": 7, "max": 8.9, "band": "high"},
                                {"min": 9, "max": 10, "band": "critical"}], "default": "low"},
})

BATCHED = NormalizerSpec.from_dict({
    "source": "wiz",
    "finding_class": "posture_finding",
    "alerts_path": "issues",
    "required": ["id"],
    "field_map": {"id": "id", "title": ["name", "rule.name"], "severity": "severity",
                  "resource_id": "resource.id", "cloud_provider": "resource.cloud"},
    "severity_map": {"exact": {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium"}, "default": "low"},
})


def test_single_source_maps_and_normalizes_severity():
    raw = {"id": "gd-1", "type": "Recon:EC2", "severity": 8.0,
           "resource": {"instanceId": "i-123", "arn": "arn:aws:ec2:::i-123"}}
    alerts = DeclarativeNormalizer(SINGLE).normalize(raw)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.id == "gd-1"
    assert alert.source == "guardduty"
    assert alert.finding_class == "threat_detection"
    assert alert.delivery_method == "eventbridge"
    assert alert.severity == "high"             # 8.0 -> high
    assert alert.hostname == "i-123"
    assert alert.resource_id == "arn:aws:ec2:::i-123"


def test_title_fallback_chain():
    raw = {"id": "gd-2", "type": "Recon:EC2", "severity": 2}
    alert = DeclarativeNormalizer(SINGLE).normalize(raw)[0]
    assert alert.title == "Recon:EC2"            # title absent -> falls back to type


def test_single_source_missing_required_raises():
    with pytest.raises(ValueError):
        DeclarativeNormalizer(SINGLE).normalize({"type": "x", "severity": 5})  # no id


def test_batched_source_one_alert_per_element():
    raw = {"issues": [
        {"id": "w-1", "name": "Public bucket", "severity": "CRITICAL",
         "resource": {"id": "arn:bucket", "cloud": "aws"}},
        {"id": "w-2", "name": "Open SG", "severity": "MEDIUM",
         "resource": {"id": "arn:sg", "cloud": "aws"}},
    ]}
    alerts = DeclarativeNormalizer(BATCHED).normalize(raw)
    assert [a.id for a in alerts] == ["w-1", "w-2"]
    assert alerts[0].severity == "critical"
    assert alerts[0].cloud_provider == "aws"
    assert alerts[0].finding_class == "posture_finding"


def test_batched_skips_invalid_elements():
    raw = {"issues": [{"id": "w-1", "name": "ok", "severity": "HIGH"}, {"name": "no-id"}]}
    alerts = DeclarativeNormalizer(BATCHED).normalize(raw)
    assert [a.id for a in alerts] == ["w-1"]


def test_batched_missing_or_nonlist_path_returns_empty():
    assert DeclarativeNormalizer(BATCHED).normalize({}) == []
    assert DeclarativeNormalizer(BATCHED).normalize({"issues": "nope"}) == []


def test_batched_skips_element_that_cannot_build_even_with_empty_required():
    # `required` is empty, but an element missing a core field (id) still
    # cannot form a valid NormalizedAlert; batched mode skips it best-effort.
    spec = NormalizerSpec.from_dict({
        "source": "vendorx",
        "alerts_path": "items",
        "field_map": {"id": "id", "title": "title", "severity": "severity"},
    })
    raw = {"items": [
        {"id": "ok-1", "title": "t", "severity": "high"},
        {"title": "no-id", "severity": "low"},
    ]}
    alerts = DeclarativeNormalizer(spec).normalize(raw)
    assert [a.id for a in alerts] == ["ok-1"]
