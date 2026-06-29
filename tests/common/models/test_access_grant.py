from datetime import datetime, timedelta, timezone

from common.models.access_grant import AccessGrant


def _payload(**overrides):
    base = {
        "id": "g1",
        "user": "Alice",
        "resource": "prod-db-cluster",
        "justification": "incident response",
        "approver": "Bob",
    }
    base.update(overrides)
    return base


def test_from_webhook_populates_fields_and_keeps_raw():
    grant = AccessGrant.from_webhook(_payload(extra="kept-in-raw"))
    assert grant.id == "g1"
    assert grant.user == "Alice"
    assert grant.granted_at  # defaulted to now when absent
    assert grant.raw_data["extra"] == "kept-in-raw"


def test_is_active_true_when_no_expiry():
    grant = AccessGrant.from_webhook(_payload())
    assert grant.is_active() is True


def test_is_active_respects_expiry():
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    assert AccessGrant.from_webhook(_payload(expires_at=past)).is_active() is False
    assert AccessGrant.from_webhook(_payload(expires_at=future)).is_active() is True


def test_matches_user_is_case_insensitive():
    grant = AccessGrant.from_webhook(_payload())
    assert grant.matches_user("alice") is True
    assert grant.matches_user("carol") is False


def test_matches_resource_is_case_insensitive_substring():
    grant = AccessGrant.from_webhook(_payload())
    assert grant.matches_resource("PROD-DB") is True
    assert grant.matches_resource("staging") is False


def test_from_dict_ignores_unknown_keys():
    grant = AccessGrant.from_dict(
        {"id": "g1", "user": "a", "resource": "r", "granted_at": "x", "junk": 1}
    )
    assert grant.id == "g1"
