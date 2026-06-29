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
