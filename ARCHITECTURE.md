# ARCHITECTURE.md

## System Architecture — GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System (Self-Hosted)

> Design follows the patterns and tooling chosen in `RESEARCH.md`. Tasks to build it are in `TASKS.md`. Non-negotiable design rules are in `IMPLEMENTATION_RULES.md`.

### Proposed system architecture
A self-hosted, asynchronous analysis pipeline. The MVP is a single-host **Docker Compose** stack; the dynamic sandbox is added later as an isolated module. The 10-stage pipeline (from production malware-pipeline patterns: OSSF Package Analysis, CAPE-based pipelines, Aleph, message-bus + Celery):

1. **Ingestion/upload** — web UI + REST API; hash, dedupe, store.
2. **Queue** — Celery/Redis (or message bus) for async processing; priority for urgent samples.
3. **Static analysis workers** — Androguard / jadx / apktool / APKiD / Quark-Engine / YARA / certificate parsing → structured JSON features.
4. **Optional dynamic sandbox** — isolated VM/gVisor; Frida / MobSF analyzer / CuckooDroid; PCAP + API trace — modular, triggered when packing/encryption is detected.
5. **Feature extraction** — normalize into a feature store.
6. **GenAI interpretation layer** — local LLM via Ollama/vLLM; RAG over ATT&CK + internal threat intel; strict prompt isolation of untrusted strings.
7. **Scoring engine** — hybrid rule + ML + GenAI fusion; explainable evidence log.
8. **Report generation** — PDF/JSON; ATT&CK mapping; IOCs; verdict + confidence.
9. **Artifact storage** — object store for APKs/reports; Elasticsearch/DB for searchable findings; strict isolation and retention policy.
10. **Integration API** — for SOC/case-management (interfaces present in MVP; integration optional).

**Standalone MVP layout:** single-host Docker Compose — web app + worker(s) + Redis + Postgres + MobSF container + Ollama container + object storage; dynamic sandbox added as an isolated module later.

### Major modules/components
- **Web UI** — analyst upload/analyze/report interface; review and sign-off for High/Critical.
- **REST API service** — ingestion, job status, report retrieval, integration/exports.
- **Job queue + workers** — Celery/Redis; orchestrates static (and optional dynamic) analysis.
- **Static analysis worker(s)** — wraps MobSF (baseline scanner + REST backbone) plus Androguard, APKiD, Quark-Engine, jadx, YARA, and certificate parsing; emits structured JSON features and sets the packing/encryption escalation flag.
- **Dynamic sandbox module (modular/stretch)** — isolated, no-egress environment running Frida/MobSF analyzer (later CuckooDroid); captures API trace, network/PCAP (mitmproxy), SMS/file behavior.
- **Feature store** — normalized features (permissions, APIs, opcodes, components, certificate data, strings, detected packers, IOCs, behavior matches).
- **GenAI interpretation service** — local LLM (Qwen2.5-Coder 32B Q4 on 24 GB GPU; fallback 14B/7B) via Ollama/vLLM; RAG over MITRE ATT&CK + internal TI; per-function chunking; untrusted-string isolation; produces code summaries, behavior explanations, ATT&CK mapping, IOC extraction, report drafts.
- **Hybrid scoring engine** — the four-layer scorer (deterministic rule layer → ML layer → GenAI explanation → fusion) producing score, verdict band, confidence, and the evidence log. (Method: `RESEARCH.md`.)
- **ATT&CK mapping table** — behavior→technique mapping using ATT&CK for Mobile v19.1 IDs.
- **Report generator** — PDF + JSON with verdict, confidence, risk score, evidence log, ATT&CK mapping, IOCs, recommendations.
- **Artifact storage + search** — object store (APKs/reports) + DB/index (findings); retention/chain-of-custody.
- **Audit log** — records every indicator, score contribution, and decision.
- **AuthN/AuthZ** — authenticated, role-based access.

### Data flow
1. Analyst uploads APK (UI/API) → service hashes, dedupes, stores in object storage, creates a job.
2. Job enqueued (priority-aware) → static analysis worker runs MobSF + Androguard/APKiD/Quark/jadx/YARA/cert parsing → structured JSON features written to the feature store; escalation flag set if packed/encrypted/dynamic-loading.
3. (If enabled and flagged) dynamic sandbox runs the sample in isolation → API trace, PCAP, SMS/file behavior → appended to features.
4. GenAI interpretation service consumes features + decompiled code (chunked) with RAG context → code summaries, behavior explanations, ATT&CK mapping, IOCs, report draft (APK strings isolated as untrusted data).
5. Hybrid scoring engine fuses rule-layer evidence + ML probability + GenAI explanation → final score, verdict band, confidence, evidence log.
6. Report generator emits PDF + JSON; findings indexed; audit log written.
7. High/Critical verdicts routed to analyst for sign-off before final.
8. (Optional) report/IOCs exported/pushed via integration API to SOC/case-management.

### Interfaces between components
- **MobSF REST API:** `/api/v1/upload`, `/scan`, `/report_json`, `/download_pdf` (baseline scan + report backbone).
- **Internal job API:** submit sample, query job status, fetch features, fetch report.
- **Feature contract:** structured JSON feature schema shared by static workers, dynamic module, GenAI service, and scoring engine (single canonical schema — see `IMPLEMENTATION_RULES.md`).
- **GenAI service interface:** request = features + chunked code + RAG context; response = grounded explanation, ATT&CK mapping, IOCs, report draft (each material claim cites an artifact).
- **Scoring engine interface:** request = full feature/evidence set + ML output + GenAI explanation; response = score, verdict band, confidence, evidence log.
- **LLM backend:** Ollama/vLLM local inference endpoint (no commercial API by default).
- **Integration/export API:** report and IOC export to downstream SOC/case-management/alerting.

### Design rationale
- **MobSF as baseline + REST backbone** because it is GPL-3.0, fully self-hostable via Docker, integrates APKiD/Quark, and keeps everything on-prem (nothing leaves the network). Wrapped with Androguard/APKiD/Quark/jadx/YARA for richer, scriptable feature extraction.
- **Local-model-first GenAI** (Qwen2.5-Coder 32B Q4 on a single 24 GB GPU; 14B/7B fallback) satisfies the on-prem/privacy constraint; commercial APIs optional and off by default.
- **Hybrid, layered scoring** keeps the verdict deterministic and auditable: rule layer is primary/traceable evidence, ML adds probability with feature-importance, and **GenAI explains but never decides** the verdict. This directly answers banking auditability and the documented GenAI hallucination/false-confidence risk.
- **Escalation flag + modular dynamic sandbox** addresses static-analysis defeat (runtime-decrypted payloads, asset-hidden DEX, dynamic loading) without making a fragile, compute-heavy sandbox an MVP dependency.
- **Untrusted-string isolation + RAG grounding** mitigate prompt injection and hallucination.
- **Async queue + workers** match production malware-pipeline patterns and allow priority handling of urgent samples.

### Scalability and reliability considerations
- **Async, queue-based** processing decouples ingestion from heavy analysis; workers scale horizontally; urgent samples get priority.
- **GPU sizing:** GenAI tier targets a single 24 GB GPU (32B Q4_K_M); degrade to 14B/7B on smaller GPUs. Q4_K_M roughly halves VRAM with <1% benchmark loss.
- **Dynamic sandbox capacity:** research sandboxes commonly run ~10 parallel VMs at 2 cores/2 GB each; size accordingly when enabled.
- **Isolation/reliability for live malware:** dynamic sandbox runs with no egress / dedicated VLAN / gVisor-style isolation, with snapshot and teardown to ensure clean, repeatable runs and prevent contamination or accidental execution. (Operational risk: `RISKS.md`.)
- **Modularity:** the system must remain fully functional with the dynamic module disabled.
- **Patch posture:** keep MobSF patched (v4.4.6 fixed a SQLite-viewer SQL-injection).
- **Auditability/retention:** durable storage of artifacts, findings, and audit logs with a defined retention/chain-of-custody policy.
