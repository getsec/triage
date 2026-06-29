import pytest

from common.models.normalized_alert import NormalizedAlert


def _valid() -> NormalizedAlert:
    return NormalizedAlert(id="a1", source="edr", title="Suspicious process", severity="high")


def test_construct_with_required_fields():
    alert = _valid()
    assert alert.id == "a1"
    assert alert.ai_analyzed is False
    assert alert.raw_data == {}
    assert alert.ai_questions_for_soc == []


@pytest.mark.parametrize("missing", ["id", "source", "title", "severity"])
def test_missing_required_field_raises(missing):
    kwargs = dict(id="a1", source="edr", title="t", severity="high")
    kwargs[missing] = ""
    with pytest.raises(ValueError):
        NormalizedAlert(**kwargs)


def test_to_store_dict_drops_none_values():
    alert = _valid()
    stored = alert.to_store_dict()
    assert "link" not in stored          # default None dropped
    assert stored["id"] == "a1"
    assert stored["raw_data"] == {}      # empty dict is kept (not None)


def test_to_dict_keeps_none_values():
    alert = _valid()
    assert alert.to_dict()["link"] is None


def test_from_dict_ignores_unknown_keys():
    alert = NormalizedAlert.from_dict(
        {"id": "a1", "source": "edr", "title": "t", "severity": "high", "totally_new_field": 42}
    )
    assert alert.id == "a1"
    assert not hasattr(alert, "totally_new_field")


def test_enrich_with_playbook_returns_self_for_chaining():
    alert = _valid()
    result = alert.enrich_with_playbook("https://runbooks.example/p1")
    assert result is alert
    assert alert.playbook_url == "https://runbooks.example/p1"


def test_enrich_with_playbook_noop_on_empty():
    alert = _valid()
    alert.enrich_with_playbook(None)
    assert alert.playbook_url is None


from common.models.normalized_alert import SEVERITY_BANDS


def test_severity_bands_constant():
    assert SEVERITY_BANDS == ("informational", "low", "medium", "high", "critical")


def test_cnapp_fields_default_empty_and_optional():
    alert = NormalizedAlert(id="a1", source="wiz", title="t", severity="high")
    assert alert.finding_class is None
    assert alert.finding_status is None
    assert alert.cloud_provider is None
    assert alert.resource_id is None
    assert alert.cvss_score is None
    assert alert.cve_ids == []
    assert alert.compliance_frameworks == []
    assert alert.mitre_techniques == []
    assert alert.attack_path is False
    assert alert.delivery_method is None


def test_cnapp_fields_roundtrip_through_store_and_from_dict():
    alert = NormalizedAlert(
        id="a1", source="wiz", title="t", severity="high",
        finding_class="posture_finding", cloud_provider="aws",
        resource_id="arn:aws:s3:::ex", cve_ids=["CVE-2026-1"], attack_path=True,
    )
    restored = NormalizedAlert.from_dict(alert.to_store_dict())
    assert restored.finding_class == "posture_finding"
    assert restored.cloud_provider == "aws"
    assert restored.cve_ids == ["CVE-2026-1"]
    assert restored.attack_path is True


def test_from_dict_still_tolerant_of_pre_extension_docs():
    # an older stored doc with none of the new fields still loads
    restored = NormalizedAlert.from_dict({"id": "a1", "source": "edr", "title": "t", "severity": "low"})
    assert restored.finding_class is None
