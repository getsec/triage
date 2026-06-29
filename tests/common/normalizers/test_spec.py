import pytest

from common.normalizers.spec import NormalizerSpec

SPEC_YAML = """
source: examplevendor
finding_class: posture_finding
delivery_method: webhook
required: [id, title]
alerts_path: data.findings
field_map:
  id: finding_id
  title: [title, summary]
  severity: severity
  resource_id: resource.id
defaults:
  description: ""
severity_field: severity
severity_map:
  exact:
    high: high
  default: medium
unknown_future_key: ignored
"""


def test_from_dict_requires_source_and_is_tolerant():
    spec = NormalizerSpec.from_dict({"source": "x", "field_map": {"id": "i"}, "junk": 1})
    assert spec.source == "x"
    assert spec.field_map == {"id": "i"}
    assert spec.required == []
    assert spec.alerts_path is None


def test_from_yaml_parses_all_fields(tmp_path):
    path = tmp_path / "spec.yaml"
    path.write_text(SPEC_YAML)
    spec = NormalizerSpec.from_yaml(str(path))
    assert spec.source == "examplevendor"
    assert spec.finding_class == "posture_finding"
    assert spec.delivery_method == "webhook"
    assert spec.required == ["id", "title"]
    assert spec.alerts_path == "data.findings"
    assert spec.field_map["title"] == ["title", "summary"]
    assert spec.defaults == {"description": ""}
    assert spec.severity_map["default"] == "medium"


def test_from_dict_missing_source_raises():
    with pytest.raises((KeyError, TypeError)):
        NormalizerSpec.from_dict({"field_map": {}})
