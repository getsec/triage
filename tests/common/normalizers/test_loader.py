import pytest

from common.normalizers.declarative import DeclarativeNormalizer
from common.normalizers.generic import GenericNormalizer
from common.normalizers.loader import load_specs_from_dir, register_default_normalizers
from common.plugins import registries

SPEC_A = """
source: vendora
field_map: {id: id, title: title, severity: severity}
"""
SPEC_B = """
source: vendorb
alerts_path: items
field_map: {id: id, title: title, severity: severity}
"""


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(registries.NORMALIZERS)
    registries.NORMALIZERS.clear()
    yield
    registries.NORMALIZERS.clear()
    registries.NORMALIZERS.update(saved)


def _write_specs(tmp_path):
    (tmp_path / "a.yaml").write_text(SPEC_A)
    (tmp_path / "b.yaml").write_text(SPEC_B)
    (tmp_path / "notes.txt").write_text("ignored")


def test_load_specs_from_dir_builds_declarative_normalizers(tmp_path):
    _write_specs(tmp_path)
    normalizers = load_specs_from_dir(str(tmp_path))
    assert len(normalizers) == 2
    assert all(isinstance(n, DeclarativeNormalizer) for n in normalizers)
    assert sorted(n.spec.source for n in normalizers) == ["vendora", "vendorb"]


def test_register_default_normalizers_registers_specs_and_generic(tmp_path):
    _write_specs(tmp_path)
    register_default_normalizers(str(tmp_path))
    assert registries.get_normalizer("vendora").spec.source == "vendora"
    assert isinstance(registries.get_normalizer("unknown"), GenericNormalizer)
    assert isinstance(registries.get_normalizer("never-seen"), GenericNormalizer)  # fallback


def test_register_default_normalizers_without_dir_still_registers_generic():
    register_default_normalizers(None)
    assert isinstance(registries.get_normalizer("anything"), GenericNormalizer)
