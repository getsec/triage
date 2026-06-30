import json
import pathlib

import pytest

from common.normalizers.generic import GenericNormalizer
from common.normalizers.loader import register_default_normalizers
from common.plugins import registries

ROOT = pathlib.Path(__file__).parents[3]
SPECS_DIR = ROOT / "config" / "normalizers"
FIXTURES = ROOT / "sample_alerts"

VENDORS = ["edr", "grafana", "guardduty", "crowdstrike", "sentinelone", "wiz", "orca", "prisma"]


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(registries.NORMALIZERS)
    registries.NORMALIZERS.clear()
    yield
    registries.NORMALIZERS.clear()
    registries.NORMALIZERS.update(saved)


def test_all_vendor_specs_register():
    register_default_normalizers(str(SPECS_DIR))
    for source in VENDORS:
        assert registries.get_normalizer(source).spec.source == source


def test_unknown_source_falls_back_to_generic():
    register_default_normalizers(str(SPECS_DIR))
    assert isinstance(registries.get_normalizer("never-seen-vendor"), GenericNormalizer)


@pytest.mark.parametrize("source", VENDORS)
def test_each_registered_vendor_normalizes_its_fixture(source):
    register_default_normalizers(str(SPECS_DIR))
    raw = json.loads((FIXTURES / f"{source}.json").read_text())
    alerts = registries.get_normalizer(source).normalize(raw)
    assert len(alerts) >= 1
    assert alerts[0].source == source
    assert alerts[0].severity in ("informational", "low", "medium", "high", "critical")
