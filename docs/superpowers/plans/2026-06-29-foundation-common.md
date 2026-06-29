# Foundation (`common/`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the dependency-free `common/` package — the shared data contract, the swap-points (interfaces), and the plugin base classes + registry — that every other service in the SOC platform builds on.

**Architecture:** Pure-Python, zero-infrastructure layer. Two DTOs (`NormalizedAlert`, `AccessGrant`) plus a small `DuplicateMatch` value object form the data contract. Five abstract interfaces (`MessageBus`, `DocumentStore`, `SecretProvider`, `LLMClient`, `TelemetryClient`) are the seams that keep the platform vendor-neutral — Redis/Temporal/Postgres/cloud-LLM impls land in later plans behind these. Three plugin ABCs (`BaseNormalizer`, `BaseDestination`, `Deduplicator`) + a normalizer registry establish the registry+strategy pattern. Everything is unit-tested with no running services.

**Tech Stack:** Python 3.9+, `dataclasses`, `abc.ABC`, `pytest`. No third-party runtime deps in this plan.

## Global Constraints

- Python **3.9+**, fully type-hinted (use `from __future__ import annotations`; prefer `Optional[X]`/`List[X]` from `typing` for 3.9 compatibility).
- DTOs use `dataclasses`; every plugin/seam interface uses `abc.ABC` with `@abstractmethod`.
- **Absolute imports only**, rooted at the `common` package (pytest is configured with `pythonpath = ["services"]` so `import common...` resolves). Late imports only to break cycles.
- `NormalizedAlert` must depend on **nothing else in the system**.
- `from_dict` on every DTO is **tolerant** — unknown keys are ignored so the schema can evolve without breaking older stored docs.
- Store serializer is named **`to_store_dict`** (renamed from the spec's `to_firestore_dict` for vendor-neutrality) and **drops `None` values**.
- Deduplicators **fail open** (contract documented here; enforced in the dedup plan).
- No real company hostnames, projects, vendor SaaS, or workspace URLs anywhere in source.
- Structured `key=value` logging is the house style (no logging code in this plan, but keep it in mind).

---

## File Structure

```
pyproject.toml                                   # project metadata + pytest config (pythonpath=services)
services/
  common/
    __init__.py
    models/
      __init__.py
      normalized_alert.py     # NormalizedAlert — the single data contract
      access_grant.py         # AccessGrant — the JIT-access route DTO
      duplicate_match.py      # DuplicateMatch — dedup result value object
    interfaces/
      __init__.py
      message_bus.py          # MessageBus ABC
      document_store.py       # DocumentStore ABC
      secret_provider.py      # SecretProvider ABC
      llm_client.py           # LLMClient ABC + LLMResponse
      telemetry_client.py     # TelemetryClient ABC + TableSchema
    plugins/
      __init__.py
      base_normalizer.py      # BaseNormalizer ABC + safe_get/validate helpers
      base_destination.py     # BaseDestination ABC
      deduplicator.py         # Deduplicator ABC
      registries.py           # NORMALIZERS registry + register/get + "unknown" fallback
tests/
  common/
    __init__.py
    models/
      test_normalized_alert.py
      test_access_grant.py
      test_duplicate_match.py
    interfaces/
      test_interfaces.py
    plugins/
      test_base_normalizer.py
      test_base_destination.py
      test_deduplicator.py
      test_registries.py
```

**Responsibility notes:**
- `models/` holds only data + (de)serialization + tiny self-contained predicates. No I/O.
- `interfaces/` holds only ABCs and the small value/response dataclasses their methods exchange. No concrete impls.
- `plugins/` holds the strategy ABCs and the registry. `enrich_with_host_context` (needs the host catalog) is **deferred to the Plugins plan**, not here.

---

### Task 1: Project scaffold + `NormalizedAlert`

**Files:**
- Create: `pyproject.toml`
- Create: `services/common/__init__.py`
- Create: `services/common/models/__init__.py`
- Create: `services/common/models/normalized_alert.py`
- Create: `tests/common/__init__.py`
- Create: `tests/common/models/test_normalized_alert.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `NormalizedAlert` dataclass with fields per spec §2 and methods `__post_init__` (validates `id`, `source`, `title`, `severity`), `to_dict() -> Dict[str, Any]`, `to_store_dict() -> Dict[str, Any]` (drops `None`), `from_dict(data: Dict[str, Any]) -> NormalizedAlert` (tolerant), `enrich_with_playbook(playbook_url: Optional[str]) -> NormalizedAlert` (returns `self`). Module-level `REQUIRED_FIELDS = ("id", "source", "title", "severity")`.

- [ ] **Step 1: Create the project scaffold**

`pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"

[project]
name = "soc-platform"
version = "0.1.0"
description = "Vendor-neutral, open-source SOC alert automation platform"
requires-python = ">=3.9"
dependencies = []

[project.optional-dependencies]
dev = ["pytest>=7.0"]

[tool.pytest.ini_options]
pythonpath = ["services"]
testpaths = ["tests"]
```

Create the empty package markers (each file contains a single newline):

- `services/common/__init__.py`
- `services/common/models/__init__.py`
- `tests/common/__init__.py`
- `tests/common/models/__init__.py`

- [ ] **Step 2: Write the failing test**

`tests/common/models/test_normalized_alert.py`:

```python
import pytest

from common.models.normalized_alert import NormalizedAlert


def _valid() -> NormalizedAlert:
    return NormalizedAlert(id="a1", source="edr", title="Suspicious process", severity="high")


def test_construct_with_required_fields():
    alert = _valid()
    assert alert.id == "a1"
    assert alert.ai_analyzed is False
    assert alert.raw_data == {}
    assert alert.ai_questions_for_soc == []


@pytest.mark.parametrize("missing", ["id", "source", "title", "severity"])
def test_missing_required_field_raises(missing):
    kwargs = dict(id="a1", source="edr", title="t", severity="high")
    kwargs[missing] = ""
    with pytest.raises(ValueError):
        NormalizedAlert(**kwargs)


def test_to_store_dict_drops_none_values():
    alert = _valid()
    stored = alert.to_store_dict()
    assert "link" not in stored          # default None dropped
    assert stored["id"] == "a1"
    assert stored["raw_data"] == {}      # empty dict is kept (not None)


def test_to_dict_keeps_none_values():
    alert = _valid()
    assert alert.to_dict()["link"] is None


def test_from_dict_ignores_unknown_keys():
    alert = NormalizedAlert.from_dict(
        {"id": "a1", "source": "edr", "title": "t", "severity": "high", "totally_new_field": 42}
    )
    assert alert.id == "a1"
    assert not hasattr(alert, "totally_new_field")


def test_enrich_with_playbook_returns_self_for_chaining():
    alert = _valid()
    result = alert.enrich_with_playbook("https://runbooks.example/p1")
    assert result is alert
    assert alert.playbook_url == "https://runbooks.example/p1"


def test_enrich_with_playbook_noop_on_empty():
    alert = _valid()
    alert.enrich_with_playbook(None)
    assert alert.playbook_url is None
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/common/models/test_normalized_alert.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'common.models.normalized_alert'`

- [ ] **Step 4: Write minimal implementation**

`services/common/models/normalized_alert.py`:

```python
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List, Optional

REQUIRED_FIELDS = ("id", "source", "title", "severity")


@dataclass
class NormalizedAlert:
    # Identity & core
    id: str
    source: str
    title: str
    severity: str
    description: str = ""
    timestamp: Optional[str] = None
    link: Optional[str] = None
    hostname: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    # Source extras
    code: Optional[str] = None
    score: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Enrichment
    playbook_url: Optional[str] = None
    host_context: Optional[Dict[str, Any]] = None
    enrichment_context: Optional[Dict[str, Any]] = None

    # Ticket tracking
    ticket_id: Optional[str] = None
    ticket_url: Optional[str] = None
    assignee: Optional[str] = None
    enriched: bool = False
    enrichment_attempted_at: Optional[str] = None

    # AI analysis
    ai_analyzed: bool = False
    ai_severity: Optional[str] = None
    ai_false_positive_score: Optional[float] = None
    ai_recommendation: Optional[str] = None
    ai_summary: Optional[str] = None
    ai_questions_for_soc: List[str] = field(default_factory=list)
    ai_iocs: List[str] = field(default_factory=list)
    ai_model: Optional[str] = None
    ai_cost_usd: Optional[float] = None

    # Investigation agent
    investigation_attempted: bool = False
    investigation_disposition: Optional[str] = None
    investigation_confidence: Optional[float] = None
    investigation_summary: Optional[str] = None
    investigation_recommendation: Optional[str] = None
    investigation_evidence: List[str] = field(default_factory=list)
    investigation_iocs: List[str] = field(default_factory=list)
    investigation_tools_used: List[str] = field(default_factory=list)
    investigation_cost_usd: Optional[float] = None
    investigation_iterations: Optional[int] = None

    def __post_init__(self) -> None:
        missing = [name for name in REQUIRED_FIELDS if not getattr(self, name)]
        if missing:
            raise ValueError(f"NormalizedAlert missing required fields: {missing}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_store_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NormalizedAlert":
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})

    def enrich_with_playbook(self, playbook_url: Optional[str]) -> "NormalizedAlert":
        if playbook_url:
            self.playbook_url = playbook_url
        return self
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/common/models/test_normalized_alert.py -v`
Expected: PASS (all cases green)

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml services/common tests/common
git commit -m "feat(common): NormalizedAlert data contract + project scaffold"
```

---

### Task 2: `AccessGrant`

**Files:**
- Create: `services/common/models/access_grant.py`
- Create: `tests/common/models/test_access_grant.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `AccessGrant` dataclass with fields `id`, `user`, `resource`, `granted_at`, `expires_at`, `justification`, `approver`, `raw_data`; classmethods `from_webhook(payload: Dict[str, Any]) -> AccessGrant` and `from_dict(data) -> AccessGrant` (tolerant); methods `is_active(now: Optional[datetime] = None) -> bool`, `matches_user(user: str) -> bool` (case-insensitive equality), `matches_resource(resource: str) -> bool` (case-insensitive substring), `to_dict()`, `to_store_dict()`.

- [ ] **Step 1: Write the failing test**

`tests/common/models/test_access_grant.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/common/models/test_access_grant.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'common.models.access_grant'`

- [ ] **Step 3: Write minimal implementation**

`services/common/models/access_grant.py`:

```python
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class AccessGrant:
    id: str
    user: str
    resource: str
    granted_at: str
    expires_at: Optional[str] = None
    justification: Optional[str] = None
    approver: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_webhook(cls, payload: Dict[str, Any]) -> "AccessGrant":
        return cls(
            id=payload["id"],
            user=payload["user"],
            resource=payload["resource"],
            granted_at=payload.get("granted_at") or _utcnow().isoformat(),
            expires_at=payload.get("expires_at"),
            justification=payload.get("justification"),
            approver=payload.get("approver"),
            raw_data=dict(payload),
        )

    def is_active(self, now: Optional[datetime] = None) -> bool:
        now = now or _utcnow()
        expiry = _parse_ts(self.expires_at)
        return True if expiry is None else expiry > now

    def matches_user(self, user: str) -> bool:
        return self.user.lower() == user.lower()

    def matches_resource(self, resource: str) -> bool:
        return resource.lower() in self.resource.lower()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_store_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in asdict(self).items() if value is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AccessGrant":
        known = {f.name for f in fields(cls)}
        return cls(**{key: value for key, value in data.items() if key in known})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/common/models/test_access_grant.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/common/models/access_grant.py tests/common/models/test_access_grant.py
git commit -m "feat(common): AccessGrant DTO for the JIT-access route"
```

---

### Task 3: `DuplicateMatch`

**Files:**
- Create: `services/common/models/duplicate_match.py`
- Create: `tests/common/models/test_duplicate_match.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `DuplicateMatch` dataclass — `alert_id: str` (the existing alert that opened the ticket), `ticket_id: str`, `ticket_url: Optional[str] = None`, `similarity: Optional[float] = None`, `match_type: str = "unknown"`. Consumed by `Deduplicator.find_duplicate` (Task 7).

- [ ] **Step 1: Write the failing test**

`tests/common/models/test_duplicate_match.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/common/models/test_duplicate_match.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'common.models.duplicate_match'`

- [ ] **Step 3: Write minimal implementation**

`services/common/models/duplicate_match.py`:

```python
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DuplicateMatch:
    alert_id: str
    ticket_id: str
    ticket_url: Optional[str] = None
    similarity: Optional[float] = None
    match_type: str = "unknown"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/common/models/test_duplicate_match.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/common/models/duplicate_match.py tests/common/models/test_duplicate_match.py
git commit -m "feat(common): DuplicateMatch dedup-result value object"
```

---

### Task 4: Core interfaces (the five seams)

**Files:**
- Create: `services/common/interfaces/__init__.py`
- Create: `services/common/interfaces/message_bus.py`
- Create: `services/common/interfaces/document_store.py`
- Create: `services/common/interfaces/secret_provider.py`
- Create: `services/common/interfaces/llm_client.py`
- Create: `services/common/interfaces/telemetry_client.py`
- Create: `tests/common/interfaces/__init__.py`
- Create: `tests/common/interfaces/test_interfaces.py`

**Interfaces:**
- Consumes: `NormalizedAlert` (Task 1), `AccessGrant` (Task 2).
- Produces:
  - `MessageBus(ABC)`: `publish(topic: str, payload: Dict[str, Any]) -> str` (returns message id).
  - `DocumentStore(ABC)`: `save_alert(alert: NormalizedAlert) -> None`; `get_alert(alert_id: str) -> Optional[NormalizedAlert]`; `vector_search(embedding: List[float], limit: int, threshold: float, lookback_seconds: int) -> List[NormalizedAlert]`; `find_open_ticket_by_host_code(hostname: str, code: str) -> Optional[NormalizedAlert]`; `save_grant(grant: AccessGrant) -> None`; `find_active_grants(user: Optional[str] = None, resource: Optional[str] = None) -> List[AccessGrant]`.
  - `SecretProvider(ABC)`: `get_secret(name: str) -> Optional[str]`.
  - `LLMResponse` dataclass: `text: str`, `function_call: Optional[Dict[str, Any]]`, `input_tokens: int`, `output_tokens: int`, `model: str`. `LLMClient(ABC)`: `generate(system: str, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> LLMResponse`.
  - `TableSchema` dataclass: `name: str`, `columns: List[Dict[str, Any]]`, `requires_partition_filter: bool = False`. `TelemetryClient(ABC)`: `list_tables(substr: str) -> List[str]`; `describe_table(table: str) -> TableSchema`; `query(sql: str) -> List[Dict[str, Any]]`.

- [ ] **Step 1: Write the failing test**

`tests/common/interfaces/test_interfaces.py`:

```python
import pytest

from common.interfaces.message_bus import MessageBus
from common.interfaces.document_store import DocumentStore
from common.interfaces.secret_provider import SecretProvider
from common.interfaces.llm_client import LLMClient, LLMResponse
from common.interfaces.telemetry_client import TelemetryClient, TableSchema


@pytest.mark.parametrize("cls", [MessageBus, DocumentStore, SecretProvider, LLMClient, TelemetryClient])
def test_interfaces_cannot_be_instantiated(cls):
    with pytest.raises(TypeError):
        cls()


def test_minimal_subclass_satisfies_message_bus():
    class FakeBus(MessageBus):
        def publish(self, topic, payload):
            return f"{topic}:1"

    assert FakeBus().publish("alerts", {"a": 1}) == "alerts:1"


def test_minimal_subclass_satisfies_secret_provider():
    class FakeSecrets(SecretProvider):
        def get_secret(self, name):
            return None

    assert FakeSecrets().get_secret("missing") is None


def test_llm_response_dataclass_shape():
    resp = LLMResponse(text="hi", function_call=None, input_tokens=10, output_tokens=2, model="m")
    assert resp.input_tokens == 10
    assert resp.function_call is None


def test_table_schema_defaults():
    schema = TableSchema(name="auth_events", columns=[{"name": "ts", "type": "timestamp"}])
    assert schema.requires_partition_filter is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/common/interfaces/test_interfaces.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'common.interfaces.message_bus'`

- [ ] **Step 3: Write minimal implementations**

`services/common/interfaces/__init__.py` — single newline.

`services/common/interfaces/message_bus.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict


class MessageBus(ABC):
    """Decouples ingest from processing. Default impl: Redis Streams."""

    @abstractmethod
    def publish(self, topic: str, payload: Dict[str, Any]) -> str:
        """Publish a payload to a topic; return the message id."""
        raise NotImplementedError
```

`services/common/interfaces/document_store.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from common.models.access_grant import AccessGrant
from common.models.normalized_alert import NormalizedAlert


class DocumentStore(ABC):
    """Shared state: alerts (+ vector index), ticket index, JIT grants.

    Default impl: Postgres + pgvector.
    """

    @abstractmethod
    def save_alert(self, alert: NormalizedAlert) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_alert(self, alert_id: str) -> Optional[NormalizedAlert]:
        raise NotImplementedError

    @abstractmethod
    def vector_search(
        self,
        embedding: List[float],
        limit: int,
        threshold: float,
        lookback_seconds: int,
    ) -> List[NormalizedAlert]:
        """Return open-ticket alerts within the lookback window above the similarity threshold."""
        raise NotImplementedError

    @abstractmethod
    def find_open_ticket_by_host_code(self, hostname: str, code: str) -> Optional[NormalizedAlert]:
        raise NotImplementedError

    @abstractmethod
    def save_grant(self, grant: AccessGrant) -> None:
        raise NotImplementedError

    @abstractmethod
    def find_active_grants(
        self, user: Optional[str] = None, resource: Optional[str] = None
    ) -> List[AccessGrant]:
        raise NotImplementedError
```

`services/common/interfaces/secret_provider.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class SecretProvider(ABC):
    """Resolves named secrets. Default impl: env / Docker secrets (Vault later)."""

    @abstractmethod
    def get_secret(self, name: str) -> Optional[str]:
        raise NotImplementedError
```

`services/common/interfaces/llm_client.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class LLMResponse:
    text: str
    function_call: Optional[Dict[str, Any]]
    input_tokens: int
    output_tokens: int
    model: str


class LLMClient(ABC):
    """Function-calling-capable LLM behind a thin, provider-agnostic interface."""

    @abstractmethod
    def generate(
        self,
        system: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> LLMResponse:
        raise NotImplementedError
```

`services/common/interfaces/telemetry_client.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class TableSchema:
    name: str
    columns: List[Dict[str, Any]] = field(default_factory=list)
    requires_partition_filter: bool = False


class TelemetryClient(ABC):
    """Read-only telemetry/EDR backend for the investigator agent."""

    @abstractmethod
    def list_tables(self, substr: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def describe_table(self, table: str) -> TableSchema:
        raise NotImplementedError

    @abstractmethod
    def query(self, sql: str) -> List[Dict[str, Any]]:
        """Run one row-capped SELECT and return rows as dicts."""
        raise NotImplementedError
```

`tests/common/interfaces/__init__.py` — single newline.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/common/interfaces/test_interfaces.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/common/interfaces tests/common/interfaces
git commit -m "feat(common): core swap-point interfaces (bus, store, secrets, llm, telemetry)"
```

---

### Task 5: Plugin base classes

**Files:**
- Create: `services/common/plugins/__init__.py`
- Create: `services/common/plugins/base_normalizer.py`
- Create: `services/common/plugins/base_destination.py`
- Create: `services/common/plugins/deduplicator.py`
- Create: `tests/common/plugins/__init__.py`
- Create: `tests/common/plugins/test_base_normalizer.py`
- Create: `tests/common/plugins/test_base_destination.py`
- Create: `tests/common/plugins/test_deduplicator.py`

**Interfaces:**
- Consumes: `NormalizedAlert` (Task 1), `DuplicateMatch` (Task 3).
- Produces:
  - `BaseNormalizer(ABC)`: abstract `normalize(raw: Dict[str, Any]) -> List[NormalizedAlert]`; static helpers `validate_required_fields(raw: Dict[str, Any], required: Iterable[str]) -> None` (raises `ValueError` listing missing/falsy keys) and `safe_get(data: Dict[str, Any], path: str, default: Any = None) -> Any` (dotted-path traversal). NOTE: `enrich_with_host_context` is intentionally deferred to the Plugins plan (needs the host catalog).
  - `BaseDestination(ABC)`: abstract `send_alert(alert: NormalizedAlert, ai_analysis: Optional[Dict[str, Any]] = None) -> Optional[str]`; abstract `is_configured() -> bool`; concrete default `enrich_alert(alert: NormalizedAlert, ticket_id: str) -> bool` returning `False`.
  - `Deduplicator(ABC)`: abstract `find_duplicate(alert: NormalizedAlert, embedding: Optional[List[float]] = None) -> Optional[DuplicateMatch]`. Docstring states the fail-open contract.

- [ ] **Step 1: Write the failing tests**

`tests/common/plugins/test_base_normalizer.py`:

```python
import pytest

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_normalizer import BaseNormalizer


class _Dummy(BaseNormalizer):
    def normalize(self, raw):
        return [NormalizedAlert(id=raw["id"], source="dummy", title=raw["title"], severity="low")]


def test_base_normalizer_cannot_be_instantiated():
    with pytest.raises(TypeError):
        BaseNormalizer()


def test_subclass_normalize_returns_list():
    alerts = _Dummy().normalize({"id": "x", "title": "t"})
    assert [a.id for a in alerts] == ["x"]


def test_validate_required_fields_raises_on_missing():
    with pytest.raises(ValueError):
        BaseNormalizer.validate_required_fields({"a": 1, "b": ""}, ["a", "b", "c"])


def test_validate_required_fields_passes_when_present():
    BaseNormalizer.validate_required_fields({"a": 1, "b": 2}, ["a", "b"])  # no raise


def test_safe_get_traverses_dotted_path():
    data = {"outer": {"inner": {"value": 7}}}
    assert BaseNormalizer.safe_get(data, "outer.inner.value") == 7


def test_safe_get_returns_default_on_missing():
    assert BaseNormalizer.safe_get({"a": {}}, "a.b.c", default="fallback") == "fallback"
    assert BaseNormalizer.safe_get({"a": 5}, "a.b", default=None) is None
```

`tests/common/plugins/test_base_destination.py`:

```python
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
```

`tests/common/plugins/test_deduplicator.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/common/plugins -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'common.plugins.base_normalizer'`

- [ ] **Step 3: Write minimal implementations**

`services/common/plugins/__init__.py` — single newline.
`tests/common/plugins/__init__.py` — single newline.

`services/common/plugins/base_normalizer.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List

from common.models.normalized_alert import NormalizedAlert


class BaseNormalizer(ABC):
    """Turns one raw source payload into zero or more NormalizedAlerts."""

    @abstractmethod
    def normalize(self, raw: Dict[str, Any]) -> List[NormalizedAlert]:
        raise NotImplementedError

    @staticmethod
    def validate_required_fields(raw: Dict[str, Any], required: Iterable[str]) -> None:
        missing = [key for key in required if not raw.get(key)]
        if missing:
            raise ValueError(f"raw payload missing required fields: {missing}")

    @staticmethod
    def safe_get(data: Dict[str, Any], path: str, default: Any = None) -> Any:
        current: Any = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
        return current
```

`services/common/plugins/base_destination.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from common.models.normalized_alert import NormalizedAlert


class BaseDestination(ABC):
    """A place alerts are sent: a ticketing system, a chat channel, etc."""

    @abstractmethod
    def send_alert(
        self, alert: NormalizedAlert, ai_analysis: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """Create the ticket/message; return its id, or None on failure."""
        raise NotImplementedError

    @abstractmethod
    def is_configured(self) -> bool:
        raise NotImplementedError

    def enrich_alert(self, alert: NormalizedAlert, ticket_id: str) -> bool:
        """Optional post-creation enrichment hook. No-op by default."""
        return False
```

`services/common/plugins/deduplicator.py`:

```python
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional

from common.models.duplicate_match import DuplicateMatch
from common.models.normalized_alert import NormalizedAlert


class Deduplicator(ABC):
    """Finds a prior open-ticket alert that duplicates this one.

    Implementations MUST fail open: on any internal error, return None
    (do not suppress the alert).
    """

    @abstractmethod
    def find_duplicate(
        self, alert: NormalizedAlert, embedding: Optional[List[float]] = None
    ) -> Optional[DuplicateMatch]:
        raise NotImplementedError
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/common/plugins -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add services/common/plugins tests/common/plugins
git commit -m "feat(common): plugin base classes (normalizer, destination, deduplicator)"
```

---

### Task 6: Normalizer registry

**Files:**
- Create: `services/common/plugins/registries.py`
- Create: `tests/common/plugins/test_registries.py`

**Interfaces:**
- Consumes: `BaseNormalizer` (Task 5).
- Produces: module-level `NORMALIZERS: Dict[str, BaseNormalizer]` (starts empty; concrete entries registered in the Plugins plan), `FALLBACK_KEY = "unknown"`, `register_normalizer(key: str, normalizer: BaseNormalizer) -> None`, `get_normalizer(source: str) -> BaseNormalizer` (returns the registered normalizer for `source`, else the `"unknown"` fallback; raises `KeyError` if no fallback is registered).

- [ ] **Step 1: Write the failing test**

`tests/common/plugins/test_registries.py`:

```python
import pytest

from common.models.normalized_alert import NormalizedAlert
from common.plugins.base_normalizer import BaseNormalizer
from common.plugins import registries


class _N(BaseNormalizer):
    def __init__(self, tag):
        self.tag = tag

    def normalize(self, raw):
        return [NormalizedAlert(id="x", source=self.tag, title="t", severity="low")]


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(registries.NORMALIZERS)
    registries.NORMALIZERS.clear()
    yield
    registries.NORMALIZERS.clear()
    registries.NORMALIZERS.update(saved)


def test_register_and_get_returns_exact_match():
    edr = _N("edr")
    registries.register_normalizer("edr", edr)
    assert registries.get_normalizer("edr") is edr


def test_get_falls_back_to_unknown():
    fallback = _N("unknown")
    registries.register_normalizer(registries.FALLBACK_KEY, fallback)
    assert registries.get_normalizer("never-seen-source") is fallback


def test_get_raises_when_no_fallback_registered():
    with pytest.raises(KeyError):
        registries.get_normalizer("never-seen-source")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/common/plugins/test_registries.py -v`
Expected: FAIL — `AttributeError: module 'common.plugins.registries' has no attribute ...` (or import error)

- [ ] **Step 3: Write minimal implementation**

`services/common/plugins/registries.py`:

```python
from __future__ import annotations

from typing import Dict

from common.plugins.base_normalizer import BaseNormalizer

FALLBACK_KEY = "unknown"

NORMALIZERS: Dict[str, BaseNormalizer] = {}


def register_normalizer(key: str, normalizer: BaseNormalizer) -> None:
    NORMALIZERS[key] = normalizer


def get_normalizer(source: str) -> BaseNormalizer:
    if source in NORMALIZERS:
        return NORMALIZERS[source]
    return NORMALIZERS[FALLBACK_KEY]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/common/plugins/test_registries.py -v`
Expected: PASS

- [ ] **Step 5: Run the whole suite + commit**

Run: `pytest -v`
Expected: PASS (all tasks green)

```bash
git add services/common/plugins/registries.py tests/common/plugins/test_registries.py
git commit -m "feat(common): normalizer registry with unknown-source fallback"
```

---

## Self-Review

**1. Spec coverage (for this plan's scope — the `common/` foundation):**
- §2 `NormalizedAlert` (all field groups, `__post_init__` validation, `to_dict`, `to_store_dict`/drop-None, tolerant `from_dict`, `enrich_with_playbook` chaining) → Task 1. ✅
- §2 `AccessGrant` (`from_webhook`, `is_active`, `matches_user`, `matches_resource`) → Task 2. ✅
- §3 `BaseNormalizer` (+ `validate_required_fields`, `safe_get`) → Task 5; `enrich_with_host_context` explicitly deferred to the Plugins plan (host catalog dependency). ✅ (noted deferral)
- §3 `BaseDestination` (`send_alert`, `is_configured`, default `enrich_alert`) → Task 5. ✅
- §3 `Deduplicator` (`find_duplicate`, fail-open contract) + `DuplicateMatch` → Tasks 5 & 3. ✅
- §3 registry pattern (`NORMALIZERS`, register/get, `"unknown"` fallback) → Task 6. ✅
- §5/§6/§8 seams used by later plans (`MessageBus`, `DocumentStore`, `SecretProvider`, `LLMClient`, `TelemetryClient`) → Task 4. ✅
- Out of scope here (later plans): concrete normalizers/destinations/dedup, host catalog, stages, Temporal workflow, investigator loop, AI analyzer, gateway, Compose/k8s, Terraform, scripts.

**2. Placeholder scan:** No "TBD"/"add error handling"/"similar to"/"write tests for the above" — every code and test step contains real content. ✅

**3. Type consistency:** `to_store_dict` (not `to_firestore_dict`) used consistently; `DuplicateMatch.alert_id`/`ticket_id`/`match_type` match between Task 3 def and Tasks 5/dedup usage; `vector_search` signature `(embedding, limit, threshold, lookback_seconds)` and `find_open_ticket_by_host_code(hostname, code)` are the names later dedup strategies will call; `LLMResponse`/`TableSchema` field names consistent with their tests. ✅

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-06-29-foundation-common.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
