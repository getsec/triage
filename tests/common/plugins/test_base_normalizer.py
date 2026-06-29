import pytest

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_normalizer import BaseNormalizer


class _Dummy(BaseNormalizer):
    def normalize(self, raw):
        return [NormalizedAlert(id=raw["id"], source="dummy", title=raw["title"], severity="low")]


def test_base_normalizer_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseNormalizer()


def test_subclass_normalize_returns_list():
    alerts = _Dummy().normalize({"id": "x", "title": "t"})
    assert [a.id for a in alerts] == ["x"]


def test_validate_required_fields_raises_on_missing():
    with pytest.raises(ValueError):
        BaseNormalizer.validate_required_fields({"a": 1, "b": ""}, ["a", "b", "c"])


def test_validate_required_fields_passes_when_present():
    BaseNormalizer.validate_required_fields({"a": 1, "b": 2}, ["a", "b"])  # no raise


def test_safe_get_traverses_dotted_path():
    data = {"outer": {"inner": {"value": 7}}}
    assert BaseNormalizer.safe_get(data, "outer.inner.value") == 7


def test_safe_get_returns_default_on_missing():
    assert BaseNormalizer.safe_get({"a": {}}, "a.b.c", default="fallback") == "fallback"
    assert BaseNormalizer.safe_get({"a": 5}, "a.b", default=None) is None


from common.enrichment.host_catalog import HostCatalog


def _catalog_for_enrich():
    return HostCatalog.from_entries(
        [{"type": "web", "hostname_patterns": ["web-prod-"], "routing_channel": "web-alerts"}]
    )


def test_enrich_with_host_context_sets_context_on_match():
    alert = NormalizedAlert(id="a1", source="edr", title="t", severity="high", hostname="web-prod-01")
    result = BaseNormalizer.enrich_with_host_context(alert, _catalog_for_enrich())
    assert result is alert
    assert alert.host_context == {"type": "web", "routing_channel": "web-alerts"}


def test_enrich_with_host_context_noop_on_no_match():
    alert = NormalizedAlert(id="a1", source="edr", title="t", severity="high", hostname="other-1")
    BaseNormalizer.enrich_with_host_context(alert, _catalog_for_enrich())
    assert alert.host_context is None


def test_enrich_with_host_context_noop_on_missing_hostname():
    alert = NormalizedAlert(id="a1", source="edr", title="t", severity="high")
    BaseNormalizer.enrich_with_host_context(alert, _catalog_for_enrich())
    assert alert.host_context is None


def test_enrich_with_host_context_noop_on_none_catalog():
    alert = NormalizedAlert(id="a1", source="edr", title="t", severity="high", hostname="web-prod-01")
    result = BaseNormalizer.enrich_with_host_context(alert, None)
    assert result is alert
    assert alert.host_context is None
