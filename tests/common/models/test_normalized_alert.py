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
