import json

from common.enrichment.host_catalog import HostCatalog, HostCatalogEntry

ENTRIES = [
    {
        "type": "web",
        "hostname_patterns": ["web-prod-"],
        "routing_project": "WEBOPS",
        "routing_channel": "web-alerts",
        "standard_operations": "nginx, gunicorn",
        "alerting_context": "public-facing tier",
    },
    {
        "type": "web-canary",
        "hostname_patterns": ["web-prod-canary-"],
        "routing_project": "WEBOPS",
        "routing_channel": "web-canary",
    },
    {
        "type": "db",
        "hostname_patterns": ["db-prod-", "db-stg-"],
        "routing_project": "DBA",
        "routing_channel": "db-alerts",
    },
]


def _catalog():
    return HostCatalog.from_entries(ENTRIES)


def test_lookup_matches_by_prefix():
    entry = _catalog().lookup("db-prod-02")
    assert entry is not None
    assert entry.type == "db"


def test_lookup_longest_prefix_wins():
    entry = _catalog().lookup("web-prod-canary-7")
    assert entry.type == "web-canary"  # more specific pattern beats "web-prod-"


def test_lookup_is_case_insensitive():
    assert _catalog().lookup("WEB-PROD-01").type == "web"


def test_lookup_returns_none_for_no_match_or_missing_hostname():
    assert _catalog().lookup("unknown-host-1") is None
    assert _catalog().lookup(None) is None
    assert _catalog().lookup("") is None


def test_context_for_returns_context_dict_without_patterns():
    ctx = _catalog().context_for("web-prod-01")
    assert ctx == {
        "type": "web",
        "routing_project": "WEBOPS",
        "routing_channel": "web-alerts",
        "standard_operations": "nginx, gunicorn",
        "alerting_context": "public-facing tier",
    }
    assert "hostname_patterns" not in ctx


def test_to_context_drops_none_fields():
    ctx = _catalog().context_for("db-prod-02")
    assert ctx == {"type": "db", "routing_project": "DBA", "routing_channel": "db-alerts"}


def test_context_for_returns_none_when_no_match():
    assert _catalog().context_for("nope-1") is None


def test_from_entries_is_tolerant_of_unknown_keys():
    cat = HostCatalog.from_entries([{"type": "x", "hostname_patterns": ["x-"], "future_field": 1}])
    assert cat.lookup("x-1").type == "x"


def test_from_json_file(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(ENTRIES))
    assert HostCatalog.from_json_file(str(path)).lookup("db-prod-1").type == "db"


def test_from_env_with_inline_json(monkeypatch):
    monkeypatch.setenv("HOST_CATALOG", json.dumps(ENTRIES))
    assert HostCatalog.from_env("HOST_CATALOG").lookup("web-prod-1").type == "web"


def test_from_env_with_file_path(monkeypatch, tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps(ENTRIES))
    monkeypatch.setenv("HOST_CATALOG", str(path))
    assert HostCatalog.from_env("HOST_CATALOG").lookup("db-stg-9").type == "db"


def test_from_env_missing_returns_empty_catalog(monkeypatch):
    monkeypatch.delenv("HOST_CATALOG", raising=False)
    assert HostCatalog.from_env("HOST_CATALOG").lookup("web-prod-1") is None


def test_from_yaml_loads_entries(tmp_path):
    path = tmp_path / "catalog.yaml"
    path.write_text("- type: web\n  hostname_patterns: [web-prod-]\n  routing_channel: web-alerts\n")
    catalog = HostCatalog.from_yaml(str(path))
    assert catalog.lookup("web-prod-9").type == "web"
