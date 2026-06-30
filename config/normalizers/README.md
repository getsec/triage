# Normalizer Specs

Each `*.yaml` here declares how one alert source maps to the platform's
`NormalizedAlert`. Adding a source is **config, not code** — drop a new YAML
file in this directory and it is auto-registered by `register_default_normalizers`.

## Spec fields

| Field | Meaning |
|-------|---------|
| `source` | registry key (and the alert's `source`) |
| `finding_class` | `threat_detection` \| `posture_finding` \| `vulnerability` \| `compliance` |
| `delivery_method` | free-text provenance (e.g. `webhook`, `eventbridge`, `api`) |
| `alerts_path` | dotted path to a list, if the source batches alerts (else omit) |
| `required` | resolved `NormalizedAlert` field names that must be present (validated AFTER mapping) |
| `field_map` | `<alert_field>: <raw.path>` or `<alert_field>: [path1, path2]` (first non-empty wins) |
| `defaults` | literal fallbacks applied when a mapped field resolves empty |
| `severity_field` | which mapped field carries severity (default `severity`) |
| `severity_map` | `{exact: {raw: band}, ranges: [{min, max, band}], default: band}` |

Severity resolves: exact map → already-a-valid-band passthrough → numeric range
→ map default → `medium`. Bands: `informational`, `low`, `medium`, `high`, `critical`.

## Adding a vendor

1. Copy an existing spec (`wiz.yaml` for posture/CNAPP, `edr.yaml` for EDR).
2. Set `source`, `finding_class`, and the `field_map` dotted paths for your payload.
3. Add a `severity_map` only if the source's severity isn't already a band string.
4. Drop a sample payload in `sample_alerts/<source>.json` and add a case to
   `tests/common/normalizers/test_vendor_specs.py`.

Complex sources whose mapping can't be expressed declaratively (e.g. dual-schema
or per-rule variable payloads) can still ship a code `BaseNormalizer` subclass.
