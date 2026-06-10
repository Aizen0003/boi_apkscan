# APKScan — Self-Hosted Android Banking-Malware Analysis & Risk-Scoring

A self-hosted system that analyzes suspicious Android APKs with **deterministic
static analysis** and a **local LLM interpretation layer**, producing
explainable, auditable risk verdicts and SOC-ready reports. Built for the Indian
banking-fraud threat model (overlay / accessibility / SMS-OTP / RAT / ATS).

> **Governance posture (binding):** everything runs on-prem; commercial LLM APIs
> are **off by default**; **GenAI explains, the deterministic rule layer
> decides**; all APK-derived strings are treated as **untrusted data**; every
> verdict carries a complete, logged evidence list. See `IMPLEMENTATION_RULES.md`.

## Status
MVP / Phase 0 (static + GenAI core) under active implementation. See
`progress.md` for task-by-task status and `TASKS.md` for the build order.

## Architecture (MVP)
Single-host Docker Compose stack: FastAPI web/API + Celery workers + Redis +
Postgres + object storage + MobSF (baseline scanner & REST backbone) + Ollama
(local LLM). The hybrid scorer is layered — deterministic rule layer (primary,
reproducible evidence) → GenAI explanation (grounded, never decides) → fusion →
verdict + confidence + evidence log. The ML layer (Phase 1) and dynamic sandbox
(Phase 2) are modular seams, not MVP dependencies. Full design in
`ARCHITECTURE.md`.

## The canonical feature schema
Every component (static workers, GenAI service, scoring engine, report
generator, and the future dynamic module) exchanges data through **one canonical
JSON feature schema** defined in `apkscan/schema/`. It is the central contract
and is not changed casually.

## Quick start

### Local deterministic core (no GPU / no Docker needed)
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest                       # runs the deterministic-core unit tests
```

### Full stack
```bash
cp .env.example .env         # defaults keep commercial LLM egress OFF
docker compose up -d         # web, worker, redis, postgres, storage, mobsf, ollama
# pull the local model (7B fallback tier shown; use 32B on a 24 GB GPU):
docker compose exec ollama ollama pull qwen2.5-coder:7b-instruct-q4_K_M
```

### Analyze a sample (CLI)
```bash
apkscan analyze /path/to/sample.apk --out report.json --pdf report.pdf
```

## Safety
Samples may be **live malware**. They are stored hashed and isolated and are
**never executed** in the MVP. Dynamic analysis (Phase 2) is disabled until a
security/compliance/legal review and runs only in a no-egress isolated sandbox.

## License
AGPL-3.0-or-later (the system wraps MobSF / GPL-3.0). See `progress.md` A-IMPL-5.
