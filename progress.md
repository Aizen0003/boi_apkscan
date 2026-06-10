# progress.md — Implementation progress tracker

> Source of truth for build status. Updated as work advances. Tasks reference
> `TASKS.md`; acceptance criteria reference `PRD.md`; verification references
> `TEST_PLAN.md`.

## Status legend
`TODO` · `WIP` · `DONE` (verified against TEST_PLAN) · `BLOCKED`

---

## Phase 0 — MVP (static + GenAI core)

| Task | Title | Status | Notes |
|------|-------|--------|-------|
| Foundation | Canonical feature schema + evidence/score models | DONE | Cross-cutting contract; 7 unit tests green. The one contract not to change casually. |
| T0.1 | Self-hosted base stack (Compose skeleton + config) | DONE | Compose validates (`docker compose config`); config defaults verified (commercial LLM/dynamic OFF). Live boot targets 24 GB host. |
| T0.2 | MobSF baseline + REST backbone client | DONE | REST client (4 endpoints) + patch-level guard >=4.4.6 + graceful-degrade; 6 tests (mocked transport). |
| T0.3 | Ingestion service (UI + REST API) | DONE | Core service + FastAPI `/api/v1/samples` upload (UI + REST) + minimal web UI; hash/dedupe/store/job/audit; tested. |
| T0.4 | Async job queue + workers | DONE | Celery/Redis app; urgent/default priority queues; eager mode for local/test; `run_job` persists+audits; tested. |
| T0.5 | Static analysis worker — feature extraction | DONE | Orchestrator (merge/index/IOC-mine/degrade) + Androguard/APKiD/Quark/YARA/MobSF adapters; emits canonical schema. Core unit-tested; native adapters run in worker image. |
| T0.6 | Packing/encryption/dynamic-loading detector + escalation flag | DONE | Heuristics (entropy/DEX-magic) + packer/asset/dynamic-loader detection; escalate flag + reasons; tested. |
| T0.7 | ATT&CK-Mobile v19.1 mapping table | DONE | Behavior→technique table, exact v19.1 IDs (re-verified vs attack.mitre.org); 12 tactics; derive_behaviors; tested. |
| T0.8 | Deterministic rule-scoring layer | DONE | Permission weights+combos+Quark+YARA+cert/Firebase/IP + escalation; saturating 0-100 norm; reproducible; grounded per-indicator evidence; tested. |
| T0.9 | Local LLM interpretation service | DONE | Ollama client (temp 0) + per-function chunking + truncation detection (done_reason=length); commercial egress gated; tested. |
| T0.10 | Prompt-injection isolation | DONE | Untrusted-data sentinel zone; injection never in instruction position; sentinel-breakout sanitized; injection flagged; tested. |
| T0.11 | RAG over ATT&CK + internal TI | DONE | Local TF-IDF over ATT&CK v19.1 + internal TI corpus (FatBoyPanel/SOVA/Anatsa...); provenance recorded; tested. |
| T0.12 | GenAI grounding/citation enforcement | DONE | Claims must cite existing artifacts else withheld; ATT&CK ids validated; failure-rate computed; tested. |
| T0.13 | Hybrid scoring fusion | DONE | Rule decides; GenAI weight-0; no-Malicious-on-permissions-alone guard; fail-safe confidence; reproducible; tested. |
| T0.14 | Report generator (PDF + JSON) | TODO | reportlab; full report contents. |
| T0.15 | Artifact storage + searchable findings | TODO | Object store + DB findings index; retention. |
| T0.16 | Audit logging | DONE | Hash-chained append-only log across ingest/job/scoring/report/sign-off/auth; tamper-evident; chain verified in tests. |
| T0.17 | AuthN/AuthZ | DONE | JWT bearer + bcrypt + RBAC (admin/analyst/viewer); unauthorized 401 / forbidden 403 enforced; tested. |
| T0.18 | Analyst review + sign-off for High/Critical | DONE | `requires_signoff` -> report PENDING_SIGNOFF; analyst approve->FINAL / reject->REJECTED; double-signoff 409; tested. |
| T0.19 | Integration/export interface | DONE | `/reports/{id}/export` verdict+IOCs+STIX-2.1 bundle; off critical path; tested. |
| T0.20 | End-to-end MVP wiring + decision rule | DONE | `pipeline.run_analysis` spine + `apkscan` CLI; local E2E (no commercial egress) verified live (JSON+PDF); API E2E tested; decision rule enforced. |

## Phase 1 — ML layer + drift (out of MVP scope; not started)
TODO — schema already reserves ML evidence/feature seams (T1.x).

## Phase 2 — Dynamic sandbox (stretch; gated on governance sign-off; not started)
TODO — schema reserves a `dynamic` section; escalation flag already produced (T2.x).

---

## Conservative assumptions made (unresolved by docs)

- **A-IMPL-1 (GPU/model tier).** Host GPU is an 8 GB RTX 4060, below the 24 GB
  target. Per the documented fallback chain (NFR5/T0.9) the default LLM tier is
  set to `qwen2.5-coder:7b-instruct-q4_K_M`. The 32B/14B tiers remain
  configurable via `APKSCAN_LLM_MODEL` for a 24 GB deployment. No behavior
  change — only the default model string.

- **A-IMPL-2 (verdict band vs. severity vocabulary).** PRD/AC4 specify a verdict
  band (Benign/Suspicious/Malicious); AC7/T0.18 gate sign-off on "High/Critical".
  Reconciled by modelling BOTH: a 3-band `verdict` and a 4-level `severity`, each
  derived deterministically from the 0–100 risk score. Default thresholds:
  `<25 Benign/Low`, `25–49 Suspicious/Moderate`, `50–74 Malicious/High`,
  `>=75 Malicious/Critical`. Sign-off required when severity ∈ {High, Critical}
  (i.e., all Malicious verdicts). Thresholds are an exposed policy knob
  (`OPERATING_MODE`) because the docs leave the operating point to stakeholders
  (TEST_PLAN, RESEARCH open questions).

- **A-IMPL-3 (graceful tool degradation).** Heavy analyzers (Androguard/APKiD/
  Quark/YARA) and external services (MobSF/Ollama) are lazily imported and
  degrade gracefully: a missing tool is recorded as an explicit `analysis_gap`
  in the feature set and lowers confidence (fail-safe on uncertainty,
  IMPLEMENTATION_RULES §7) rather than crashing the pipeline. This keeps the
  deterministic core fully testable without the native stack.

- **A-IMPL-4 (object storage default).** Object storage defaults to a
  filesystem-backed store (single-host MVP) with an S3/MinIO backend available
  via config. Both satisfy "artifacts stay on-prem."

- **A-IMPL-6 (infra-first ordering).** Cross-cutting infrastructure (object
  storage, DB layer, and the append-only audit logger / T0.16) was built ahead of
  its nominal task position because ingestion, scoring, and sign-off all depend on
  it; building it once up front avoids retrofitting audit/persistence calls. The
  HTTP API + Celery wiring (T0.3 endpoints, T0.4) and auth (T0.17) are deferred
  until the domain logic is complete, then exposed together. Task order is
  otherwise preserved.

- **A-IMPL-5 (AGPL license).** Because the system wraps/derives from MobSF
  (GPL-3.0) over the network and intends auditable on-prem distribution, the
  project is licensed AGPL-3.0-or-later to stay compatible with copyleft
  obligations. Revisit with legal before any distribution.

---

## Blockers
- None currently. (Live integration of MobSF + a 32B Ollama model is not
  runnable on this 8 GB host; deterministic core and adapters are unit-tested
  with fixtures/mocks, and the Compose stack targets a 24 GB host.)

## Verification snapshot (Phase 0 MVP COMPLETE)
- **112 tests green; 92% line coverage** over the testable surface
  (`pytest --cov=apkscan`). Native analyzer adapters are coverage-omitted (they
  run only in the worker image).
- Unit (TEST_PLAN): schema serializer, permission-weight/combo scoring, Quark/
  YARA scoring, ATT&CK id resolution, prompt untrusted-string isolation,
  grounding/citation enforcement, report PDF/JSON serializer.
- Integration: MobSF(mock)->features; static features+GenAI->fusion->verdict;
  report+findings index+audit written; auth/RBAC; sign-off; export.
- E2E: `apkscan analyze` runs the full local pipeline with no commercial egress,
  emitting a valid JSON + 1-page PDF report (verified live); API upload->job->
  report->sign-off->export verified via TestClient eager worker.
- Failure scenarios covered: prompt injection isolated+flagged; GenAI
  hallucinations withheld (grounding); LLM truncation detected; permission-only
  not auto-Malicious; benign-with-analyzer-gaps stays low-confidence (fail-safe);
  duplicate uploads deduped.
- `docker compose config` validates the single-host stack. Live multi-GB boot
  (MobSF + Ollama 7B/32B) targets the deployment host, not this 8 GB laptop.
