from common.models.duplicate_match import DuplicateMatch


def test_minimal_construction_has_defaults():
    match = DuplicateMatch(alert_id="orig-1", ticket_id="TKT-1")
    assert match.alert_id == "orig-1"
    assert match.ticket_id == "TKT-1"
    assert match.ticket_url is None
    assert match.similarity is None
    assert match.match_type == "unknown"


def test_full_construction():
    match = DuplicateMatch(
        alert_id="orig-1",
        ticket_id="TKT-1",
        ticket_url="https://tickets.example/TKT-1",
        similarity=0.97,
        match_type="embedding",
    )
    assert match.match_type == "embedding"
    assert match.similarity == 0.97
