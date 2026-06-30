from common.normalizers.severity import normalize_severity

CROWDSTRIKE = {
    "ranges": [
        {"min": 1, "max": 19, "band": "informational"},
        {"min": 20, "max": 39, "band": "low"},
        {"min": 40, "max": 59, "band": "medium"},
        {"min": 60, "max": 79, "band": "high"},
        {"min": 80, "max": 100, "band": "critical"},
    ],
    "default": "medium",
}

GRAFANA = {"exact": {"warning": "medium", "critical": "critical", "info": "informational"}, "default": "low"}


def test_exact_string_mapping_case_insensitive():
    assert normalize_severity("WARNING", GRAFANA) == "medium"
    assert normalize_severity("critical", GRAFANA) == "critical"


def test_numeric_range_mapping():
    assert normalize_severity(15, CROWDSTRIKE) == "informational"
    assert normalize_severity(50, CROWDSTRIKE) == "medium"
    assert normalize_severity(95, CROWDSTRIKE) == "critical"


def test_numeric_string_is_parsed_into_range():
    assert normalize_severity("72", CROWDSTRIKE) == "high"


def test_unmapped_value_uses_map_default():
    assert normalize_severity("nonsense", GRAFANA) == "low"
    assert normalize_severity(None, CROWDSTRIKE) == "medium"


def test_no_map_falls_back_to_medium():
    assert normalize_severity("whatever") == "medium"


def test_exact_takes_precedence_over_range():
    smap = {"exact": {"5": "critical"}, "ranges": [{"min": 0, "max": 10, "band": "low"}]}
    assert normalize_severity("5", smap) == "critical"
