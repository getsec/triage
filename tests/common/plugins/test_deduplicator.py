import pytest

from common.models.duplicate_match import DuplicateMatch
from common.models.normalized_alert import NormalizedAlert
from common.plugins.deduplicator import Deduplicator


class _Dedup(Deduplicator):
    def find_duplicate(self, alert, embedding=None):
        return DuplicateMatch(alert_id="orig", ticket_id="TKT-9", match_type="host_alert")


def test_deduplicator_cannot_be_instantiated():
    with pytest.raises(TypeError):
        Deduplicator()


def test_subclass_find_duplicate_returns_match():
    alert = NormalizedAlert(id="a1", source="edr", title="t", severity="high")
    match = _Dedup().find_duplicate(alert)
    assert match.ticket_id == "TKT-9"
