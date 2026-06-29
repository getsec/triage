import pytest

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_destination import BaseDestination


class _Dest(BaseDestination):
    def send_alert(self, alert, ai_analysis=None):
        return "TKT-1"

    def is_configured(self):
        return True


def _alert():
    return NormalizedAlert(id="a1", source="edr", title="t", severity="high")


def test_base_destination_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseDestination()


def test_subclass_send_alert_returns_id():
    assert _Dest().send_alert(_alert()) == "TKT-1"


def test_enrich_alert_defaults_to_noop_false():
    assert _Dest().enrich_alert(_alert(), "TKT-1") is False
