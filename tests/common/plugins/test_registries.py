import pytest

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_normalizer import BaseNormalizer
from common.plugins import registries


class _N(BaseNormalizer):
    def __init__(self, tag):
        self.tag = tag

    def normalize(self, raw):
        return [NormalizedAlert(id="x", source=self.tag, title="t", severity="low")]


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(registries.NORMALIZERS)
    registries.NORMALIZERS.clear()
    yield
    registries.NORMALIZERS.clear()
    registries.NORMALIZERS.update(saved)


def test_register_and_get_returns_exact_match():
    edr = _N("edr")
    registries.register_normalizer("edr", edr)
    assert registries.get_normalizer("edr") is edr


def test_get_falls_back_to_unknown():
    fallback = _N("unknown")
    registries.register_normalizer(registries.FALLBACK_KEY, fallback)
    assert registries.get_normalizer("never-seen-source") is fallback


def test_get_raises_when_no_fallback_registered():
    with pytest.raises(KeyError):
        registries.get_normalizer("never-seen-source")
