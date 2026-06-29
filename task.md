
You are a senior platform engineer. Build a **cloud-native SOC (Security
Operations Center) alert automation platform** from scratch. The system ingests
security alerts from many heterogeneous sources, normalizes them to one common
schema, deduplicates them, enriches them with AI, files tickets, notifies
responders, and runs a bounded AI "L1 analyst" agent that investigates each
alert against live telemetry before a human makes the final call.

Build it generically: **do not hard-code any specific company, product line,
host topology, vendor SaaS, or internal Slack/Jira identifiers.** Every
integration must be a swappable plugin selected by configuration. Ship sensible
reference implementations for the common cases and make adding a new one a
matter of dropping in a class and registering it.

## 1. Guiding architecture

A **decoupled, single-responsibility pipeline orchestrated by a workflow
engine.** One HTTP ingress accepts alerts; a message bus decouples ingest from
processing; a workflow orchestrator fans out per-alert work across small,
independently deployable stage functions; a document store holds shared state.

```
External sources ──HTTPS POST (bearer auth)──▶ API Gateway (stateless HTTP)
                                                   │ publish
                                                   ▼
                              Message bus ──event trigger──▶ Workflow orchestrator
                                                                │ authenticated HTTP calls
   source == "jit_access" ─▶ grant stage (store JIT grant), return
   else                   ─▶ normalize stage ─▶ returns alert_ids[]
                              per alert_id (in parallel):
                                dedup     → duplicate? comment on existing ticket & stop
                                ai        → LLM severity / false-positive score / IOCs
                                deliver   → create ticket → ticket_id
                                notify    → chat notification
                                investigate → bounded LLM agent → verdict
                                enrich    → ticketing enrichment comment

   Shared state: document store (alerts + dedup/TTL, ticket index, JIT grants)
```

Target stack (reference implementation — keep each layer behind an interface so
it can be swapped):

- **API gateway:** a stateless container (e.g. Cloud Run / any container host)
  running a small HTTP app (Flask/FastAPI).
- **Message bus:** a pub/sub topic (e.g. GCP Pub/Sub, SNS/SQS, Kafka).
- **Orchestrator:** a managed workflow engine (e.g. GCP Workflows, AWS Step
  Functions, Temporal) that decodes the event, routes by `source`, and runs the
  per-alert stages with per-stage retry / graceful-degradation policy.
- **Stage functions:** serverless functions (Cloud Functions / Lambda),
  **all deployed from one shared source bundle** with an entry-point selector
  per stage.
- **Document store:** a serverless document DB with TTL and vector search (e.g.
  Firestore, DynamoDB, MongoDB) for alerts, a ticket index, and JIT grants.
- **Secrets:** a managed secret store; the gateway caches fetched tokens with a
  short TTL.
- **LLM:** a function-calling-capable model (Gemini, or any equivalent) behind a
  thin client with cost tracking and retries.
- **IaC:** Terraform for all infrastructure.
- **Language:** Python 3.9+, fully type-hinted, dataclasses for DTOs, `abc.ABC`
  for every plugin interface.

## 2. The single data contract

Define **one** dataclass, `NormalizedAlert`, that every source produces and
every consumer reads — a funnel of *many producers → one shared DTO → many
consumers*. It must depend on nothing else in the system. Include:

- Identity & core: `id`, `source`, `title`, `severity`, `description`,
  `timestamp`, `link`, `hostname`, `raw_data`.
- Source-extras: `code` (rule/detection code), `score`, `metadata`.
- Enrichment: `playbook_url`, `host_context` (resolved from a host catalog),
  `enrichment_context` (e.g. recent JIT grants, related alerts).
- Ticket tracking: `ticket_id`, `ticket_url`, `assignee`, `enriched`,
  `enrichment_attempted_at`.
- AI analysis: `ai_analyzed`, `ai_severity`, `ai_false_positive_score`,
  `ai_recommendation`, `ai_summary`, `ai_questions_for_soc`, `ai_iocs`,
  `ai_model`, `ai_cost_usd`.
- Investigation agent: `investigation_attempted`, `investigation_disposition`
  (`likely_false_positive` | `confirmed_suspicious` | `inconclusive`),
  `investigation_confidence` (0–1), `investigation_summary`,
  `investigation_recommendation`, `investigation_evidence`,
  `investigation_iocs`, `investigation_tools_used`, `investigation_cost_usd`,
  `investigation_iterations`.

Methods: `__post_init__` validates required fields (`id`, `source`, `title`,
`severity`); `to_dict`; `to_firestore_dict` (drop `None`s);
`from_dict` (tolerant — ignore unknown keys so the schema can evolve without
breaking older docs); `enrich_with_playbook` returns `self` for chaining.

Treat this DTO as a **change-amplifier**: keep `from_dict` tolerant and rely on
model + per-plugin test suites as the safety net.

Also define a second DTO for the JIT-access route (e.g. `AccessGrant`): who got
access to what resource, when it was granted/expires, justification, approver,
with `from_webhook(...)`, `is_active()`, `matches_user()`, `matches_resource()`.

## 3. Plugin systems (registry + strategy pattern)

**Normalizers** — `BaseNormalizer(ABC)` with `normalize(raw: dict) ->
List[NormalizedAlert]` (a source may emit several alerts). Provide helpers on the
base: `validate_required_fields`, `safe_get`, and `enrich_with_host_context`
(looks up a **configurable host catalog** to attach operational/alerting context
and a routing project/channel by hostname prefix — see §4). Ship reference
normalizers for: an endpoint/EDR source, a metrics/observability source
(Grafana-style), and a `GenericNormalizer` fallback. Register in a dict:

```python
NORMALIZERS = {"edr": EdrNormalizer(), "grafana": GrafanaNormalizer(), "unknown": GenericNormalizer()}
```

**Destinations** — `BaseDestination(ABC)` with `send_alert(alert, ai_analysis=None)
-> Optional[str]` (returns ticket/message id, `None` on failure),
`is_configured() -> bool`, and an optional `enrich_alert(alert, ticket_id) ->
bool` hook (default no-op). Ship: a ticketing destination (Jira-style, both
on-prem REST and cloud variants) and a chat destination (Slack-style) that uses
rich message blocks with dynamic action buttons keyed on whichever URLs are
present (`link`, `ticket_url`, `playbook_url`).

**Deduplicators** — `Deduplicator(ABC)` with `find_duplicate(alert, embedding) ->
Optional[DuplicateMatch]`. Build a **chain** from env flags:
- `EmbeddingDeduplicator`: semantic vector similarity (configurable threshold
  ~0.95, lookback window, candidate limit) for cloud/CSPM-style alerts that vary
  textually. Only links to **open** tickets.
- `HostAlertDeduplicator`: exact hostname + alert-code open-ticket lookup for
  endpoint alerts.
Each strategy depends only on the store + ticket index, never a concrete
destination. Fail **open** (on error, don't suppress the alert).

Selection by configuration, never by `if vendor == ...`. Adding an integration =
write a class + register it in a single composition root.

## 4. Configurable enrichment catalogs (de-Menlo-ed)

The original hard-coded a company-specific host topology and Slack channel map.
**Generalize this**: load a **host catalog** from config (YAML/JSON, env, or the
document store) — a list of `{type, hostname_patterns[], routing_project,
routing_channel, standard_operations, alerting_context}` entries. Matching is by
hostname prefix. Ship a tiny example catalog (2–3 fictional host types) and
document that operators supply their own. Same for any channel→URL map: config,
not code. **No real company hostnames, projects, or workspace URLs in source.**

## 5. Stage functions (one responsibility each)

All stages deploy from one bundle; an `entry_points` module re-exports each.
Shared singletons live in one composition root (`_components`); shared HTTP
plumbing (JSON parsing, `alert_id` extraction, alert load, an exception→HTTP
status decorator, duplicate-linking helper) in `_common`. Each stage is an HTTP
handler taking `{alert_id}` (except normalize/grant, which take the raw payload).

| Stage | Responsibility | Failure policy |
|-------|----------------|----------------|
| `normalize` | parse → `NormalizedAlert`, embed, store; return `alert_ids[]` | required |
| `dedup` | run the deduplicator chain; if matched, comment on the existing ticket + reply in its chat thread, bump a recurrence counter, and short-circuit | short-circuits |
| `ai` | LLM analysis (severity / FP score / IOCs) + context enrichment, persist | graceful (non-fatal) |
| `deliver` | create the ticket, return `ticket_id` | retryable |
| `notify` | chat notification | graceful |
| `investigate` | bounded LLM agent investigation → verdict (see §6) | graceful |
| `enrich` | ticketing enrichment comment | graceful |
| `grant` | store a JIT access grant (the `jit_access` route) | route |

The orchestrator template: decode event → route `jit_access` to `grant` and
return → else `normalize` → **parallel for each `alert_id`**: `dedup` (skip rest
if duplicate) → `ai` (try/except) → `deliver` (retry) → `notify` (try/except) →
`investigate` (try/except, long timeout) → `enrich` (try/except). Graceful stages
log and continue; only `deliver` blocks the ticket-dependent work.

Carry-over detail to preserve: AI assessment lives only on the original alert
that opened a ticket; when a duplicate re-fires, copy the AI fields + ticket URL
onto the duplicate so the rebuilt parent chat card keeps its assessment as the
recurrence count ticks up.

## 6. The L1 investigator agent (the centerpiece)

A **bounded function-calling agent loop** that actively checks live state in a
telemetry/EDR backend (**read-only**) to reach an evidence-backed verdict, then
reports it. Generalize the backend behind a `TelemetryClient` interface; ship one
reference implementation (PrestoDB/SQL-over-EDR style).

- **Tools (all read-only):** `list_tables(substr)` → `describe_table(table)`
  (validate columns; flag partition-filter requirements) → `query(sql)` (one
  SELECT, row-capped) → `submit_verdict(...)` (ends the loop). Ship a distilled
  schema catalog of the backend's tables **in the bundle** so the agent never
  guesses column names; carry a curated catalog of high-value tables + a rule of
  thumb (posture/config → `*_current` tables; who-did-what → `*_events` activity
  tables) in the system prompt, with discovery tools for the long tail.
- **Bounded:** `MAX_ITERATIONS` (default 12) and a per-investigation
  `COST_CEILING_USD` (default 0.5). Always returns a verdict —
  `inconclusive` if a cap is hit. Query polling has its own timeout budget; the
  stage's function timeout is raised (e.g. 540s) to cover the loop.
- **Verdict DTO** (`InvestigationVerdict`): `disposition`, `confidence`,
  `summary`, `recommendation`, `evidence[]`, `iocs`, `tools_used`, `cost_usd`,
  `iterations`, with `from_function_args(...)`. Provide the JSON-schema for the
  `submit_verdict` tool parameters.
- **Outputs:** a structured verdict comment on the ticket + a reply in the
  ticket's chat thread. When `disposition == likely_false_positive` and
  `confidence ≥ CLOSE_CONFIDENCE` (default 0.8), the reply includes an
  **"Approve close"** button. The agent **never closes tickets itself.**
- **Human-gated close:** the button POSTs to a `/chat/interactivity` endpoint on
  the API gateway, which **verifies the chat platform's request signature** (HMAC
  over `version:timestamp:body`, 5-minute replay window) and then transitions the
  ticket to a Done-category status via the ticketing REST API. Security boundary
  = the read-only telemetry credential's scope + the function's IAM, **not the
  prompt.**

Isolate the LLM-response parsing (extract function call, token usage) into static
helpers so the loop is unit-testable without live API calls.

## 7. API gateway

Stateless HTTP app. Endpoints:
- `POST /ingest` — bearer-token auth (token from secret store, cached ~5 min);
  parse JSON **defensively** with `get_json(force=True, silent=True)` because
  sources send unpredictable `Content-Type` headers and occasionally
  multi-encoded bodies (loop while the parsed value is still a string). Stamp
  `received_at`/`environment`, publish to the bus, return `202` with the
  message id. On parse failure, write the raw payload to a "failed payloads"
  bucket for debugging and return `400`.
- `GET /health` — liveness.
- `POST /chat/interactivity` — signature-verified human-gated ticket close (§6).

## 8. AI analysis stage

`InlineAIAnalyzer` wrapping the LLM client. Enabled iff an API key is present
(graceful no-op otherwise). Sends a curated subset of the alert (title,
description, severity, source, hostname, code, score, host_context, metadata,
enrichment_context) under an "L1 analyst" system prompt; returns
`{severity, false_positive_score, recommendation, summary, questions_for_soc,
iocs, model, cost_usd}` and writes them back onto the alert. Include a cost
tracker (per-model input/output token pricing) and retries with backoff.

## 9. Testing & ops

- A broad `pytest` suite: one test module per normalizer, destination, dedup
  strategy, the model, each stage function, the investigator loop (mock the LLM),
  API gateway (load the module via `importlib` without polluting `sys.path`),
  and integration tests. Provide sample alert fixtures per source.
- A `Makefile`: `test`, `logs`, `plan`/`apply` Terraform, `deploy-api`,
  `deploy-all`.
- Terraform for: the container service, pub/sub topic + event trigger, the
  workflow, the stage functions (with per-stage VPC/egress + secret wiring —
  ticketing-facing stages may need a stable egress IP via NAT to reach a private
  ticketing datacenter), the document store + indexes (incl. vector index),
  secrets (containers created by IaC, **versions populated out-of-band** — design
  for a two-step first apply), monitoring/alerting.
- Helper scripts: send a test alert, send a batch, query/export alerts, backfill
  & analyze embeddings.

## 10. Conventions

Absolute imports (the function runtime sets the package root); late imports only
to break cycles; type hints everywhere; structured key=value logging
(`event=... alert_id=...`); every external call wrapped so a non-critical stage
degrades gracefully rather than failing the pipeline.

## Deliverables

1. Repo layout: `services/{api_gateway,alert_processor,common}/`,
   `terraform/`, `tests/`, `docs/`, `scripts/`, `sample_alerts/`.
2. The `NormalizedAlert`/`AccessGrant` models, all three plugin base classes +
   registries, the dedup chain, the seven+ stage functions + shared bundle, the
   investigator agent + tools + verdict, the API gateway, the AI analyzer.
3. Terraform for the full topology.
4. The test suite + fixtures.
5. A `README` + `docs/architecture.md` with the topology diagram and a stage
   table, and a short "add a normalizer/destination" guide.

Keep everything **vendor-neutral and config-driven**. Where the reference uses a
specific product (Gemini, Jira, Slack, an EDR, a JIT-access SaaS), state the
generic role it plays and put the concrete choice behind the interface so it can
be replaced without touching the pipeline.
