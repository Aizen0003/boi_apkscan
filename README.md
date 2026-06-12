# APKScan

**Self-Hosted Android Banking-Malware Analysis & Risk-Scoring System**

A fully on-premises system that automatically analyzes suspicious Android APKs using **deterministic static analysis**, a **local GenAI interpretation layer**, a **machine learning classifier**, and an **isolated dynamic sandbox** — producing explainable, auditable risk scores and SOC-ready reports. Built specifically for the Indian banking-fraud threat model (overlay attacks, accessibility-service abuse, SMS-OTP interception, keylogging, screen capture, RATs, droppers, and ATS).

> **Governance posture:** everything runs on-prem; commercial LLM APIs are
> **off by default**; **GenAI explains, the deterministic rule layer decides**;
> all APK-derived strings are treated as **untrusted data**; every verdict
> carries a complete, logged evidence trail.

---

## Features

### Static Analysis (Phase 0 — MVP)
- **Multi-tool feature extraction** — MobSF + Androguard + APKiD + Quark-Engine + YARA + certificate parsing
- **Deterministic rule scoring** — permission weights, dangerous combos, Quark behavior scores, YARA hits, cert/Firebase/domain checks
- **Local GenAI interpretation** — Qwen2.5-Coder via Ollama; per-function code chunking; RAG over MITRE ATT&CK v19.1 + internal threat intel
- **Grounding & citation enforcement** — every GenAI claim must cite a concrete artifact; ungrounded claims are withheld
- **Prompt-injection isolation** — APK-derived strings are strictly untrusted data, never instructions
- **Hybrid scoring fusion** — deterministic rules (primary) + GenAI explanation → 0–100 risk score, verdict band (Benign/Suspicious/Malicious), severity, and confidence
- **PDF & JSON reports** — verdict, evidence log, ATT&CK mapping, IOCs, recommendations
- **Analyst sign-off** — High/Critical verdicts gated on analyst review before becoming FINAL
- **STIX 2.1 export** — SOC-ready IOC bundles
- **Tamper-evident audit logging** — hash-chained, append-only audit trail
- **JWT authentication + RBAC** — admin / analyst / viewer roles

### Machine Learning Classifier (Phase 1)
- **RF & XGBoost models** trained on permission/API features
- **SHAP feature-importance explanations** with automatic fallback
- **Blended scoring fusion** — ML probability integrated into the hybrid scorer
- **Temporal validation** — chronological train/test split enforcement
- **Concept-drift monitoring** — F1-based drift detection + PSI & rule-ML divergence monitoring + retraining triggers
- **Policy-driven operating modes** — balanced vs. high-recall

### Dynamic Sandbox (Phase 2)
- **Modular sandbox interface** — pluggable MobSF dynamic analyzer or simulated fallback
- **Auto-trigger on escalation** — packed/encrypted/dynamic-loading APKs automatically route to sandbox
- **API trace & network capture** — Frida instrumentation, PCAP via mitmproxy
- **Anti-evasion detection** — emulator-check signatures + dormancy detection downgrades confidence
- **Scoring integration** — dynamic evidence boosts risk scores with full evidence attribution

---

## Architecture

Single-host Docker Compose stack with a 10-stage async pipeline:

```
Upload → Queue → Static Analysis → [Dynamic Sandbox] → Feature Store
    → GenAI Interpretation → Scoring Engine → Report → Artifact Storage → Export API
```

**Components:** FastAPI web/API · Celery workers · Redis · PostgreSQL · MobSF · Ollama (local LLM) · Object storage

**Scoring layers:** Deterministic rules (primary) → ML classifier → GenAI explanation → Fusion → Verdict + Confidence + Evidence log

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full design.

---

## Project Structure

```
apkscan/
├── api/                  # FastAPI REST endpoints
├── attack/               # MITRE ATT&CK v19.1 mapping table
├── audit/                # Tamper-evident hash-chained audit log
├── auth/                 # JWT + bcrypt + RBAC (admin/analyst/viewer)
├── cli.py                # CLI entry point (analyze, serve, init-db, create-user)
├── config.py             # Pydantic-settings runtime configuration
├── db/                   # SQLAlchemy models & session management
├── dynamic_analysis/     # Phase 2 sandbox (base, simulator, MobSF client, factory)
├── genai/                # Local LLM client, RAG, grounding, prompt isolation
├── ingestion/            # Upload, hash, dedupe, persist
├── integration/          # STIX 2.1 export
├── jobs/                 # Celery app + async workers
├── pipeline.py           # Core analysis orchestrator
├── reporting/            # PDF & JSON report generators
├── schema/               # Canonical feature schema (Pydantic models)
├── scoring/              # Rule scorer, ML encoder/trainer/explainer, fusion engine
├── static_analysis/      # Androguard, APKiD, Quark, YARA, MobSF adapters
└── storage/              # Object store (filesystem / S3)
tests/                    # 197 unit & integration tests
docker/                   # Dockerfiles for web & worker services
docker-compose.yml        # Single-host production stack
```

---

## Requirements

- **Python** ≥ 3.11
- **Docker & Docker Compose** (for the full stack)
- **GPU** (optional) — NVIDIA GPU with ≥ 8 GB VRAM for local LLM inference
  - 24 GB GPU → Qwen2.5-Coder 32B (recommended)
  - 8 GB GPU → Qwen2.5-Coder 7B (default fallback)
  - No GPU → CPU-only inference (slow but functional)

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/aditya-prabhakar-13/boi_apkscan.git
cd boi_apkscan
```

### 2. Local development setup (no Docker / no GPU needed)

Create and activate a virtual environment:

```bash
# Linux / macOS
python3 -m venv .venv && source .venv/bin/activate

# Windows
python -m venv .venv
.venv\Scripts\activate
```

Install the package with dev and ML extras:

```bash
pip install -e ".[dev,ml]"
```

Run the test suite:

```bash
pytest                          # 197 tests, ~16 seconds
pytest --cov=apkscan            # with coverage report
```

### 3. Analyze an APK (CLI)

```bash
# Basic analysis — prints a terminal summary
apkscan analyze /path/to/sample.apk

# Generate JSON and PDF reports
apkscan analyze /path/to/sample.apk --out report.json --pdf report.pdf

# Use high-recall operating mode (lower threshold, catches more threats)
apkscan analyze /path/to/sample.apk --mode high_recall --out report.json

# Skip the GenAI layer (deterministic + ML only, no GPU needed)
apkscan analyze /path/to/sample.apk --no-genai --out report.json

# Exit code 2 if the verdict is Malicious (useful for CI/CD gates)
apkscan analyze /path/to/sample.apk --fail-on-malicious
```

### 4. Run the API server (development)

```bash
# Initialize the database and create a default admin user
apkscan init-db

# Create additional users
apkscan create-user --username analyst1 --password secretpass --role analyst

# Start the FastAPI server
apkscan serve --host 0.0.0.0 --port 8080
```

The API will be available at `http://localhost:8080`. Key endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/samples` | `POST` | Upload an APK for analysis |
| `/api/v1/samples/{id}` | `GET` | Get sample metadata |
| `/api/v1/reports/{id}` | `GET` | Retrieve analysis report |
| `/api/v1/reports/{id}/signoff` | `POST` | Analyst sign-off (High/Critical) |
| `/api/v1/reports/{id}/export` | `GET` | STIX 2.1 IOC export |
| `/api/v1/auth/token` | `POST` | Get JWT access token |
| `/health` | `GET` | Health check |

### 5. Full production stack (Docker Compose)

```bash
# Copy and configure environment variables
cp .env.example .env
# Edit .env — at minimum set APKSCAN_SECRET_KEY and APKSCAN_MOBSF_API_KEY

# Start all services
docker compose up -d
# Services: web (8080), mobsf (8000), ollama (11434), postgres, redis

# Pull the local LLM model (first-time only)
# For 8 GB GPU:
docker compose exec ollama ollama pull qwen2.5-coder:7b-instruct-q4_K_M
# For 24 GB GPU:
docker compose exec ollama ollama pull qwen2.5-coder:32b-instruct-q4_K_M

# Initialize the database
docker compose exec web apkscan init-db

# Optional: enable S3-compatible object storage (MinIO)
docker compose --profile s3 up -d
```

> **No GPU?** Comment out the `deploy:` block under the `ollama` service in
> `docker-compose.yml` to run CPU-only inference.

---

## Configuration

All configuration is via environment variables prefixed with `APKSCAN_`. Copy `.env.example` to `.env` and adjust:

| Variable | Default | Description |
|----------|---------|-------------|
| `APKSCAN_ENV` | `development` | Environment (`development` / `test` / `production`) |
| `APKSCAN_SECRET_KEY` | `dev-insecure...` | JWT signing key — **change in production** |
| `APKSCAN_DATABASE_URL` | `postgresql+psycopg2://...` | PostgreSQL connection string |
| `APKSCAN_REDIS_URL` | `redis://localhost:6379/0` | Redis broker URL |
| `APKSCAN_MOBSF_URL` | `http://localhost:8000` | MobSF instance URL |
| `APKSCAN_MOBSF_API_KEY` | *(empty)* | MobSF REST API key |
| `APKSCAN_LLM_MODEL` | `qwen2.5-coder:7b-...` | Ollama model name |
| `APKSCAN_LLM_ENABLED` | `true` | Enable/disable GenAI layer |
| `APKSCAN_ALLOW_COMMERCIAL_LLM` | `false` | **Off by default** — governance exception only |
| `APKSCAN_OPERATING_MODE` | `balanced` | Scoring mode (`balanced` / `high_recall`) |
| `APKSCAN_ML_ENABLED` | `false` | Enable ML classifier (requires trained model) |
| `APKSCAN_ML_MODEL_PATH` | `data/model.pkl` | Path to serialized ML model |
| `APKSCAN_DYNAMIC_ENABLED` | `false` | Enable dynamic sandbox (requires governance sign-off) |
| `APKSCAN_SANDBOX_BACKEND` | `simulator` | Sandbox provider (`mobsf` / `simulator`) |

---

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=apkscan

# Run specific test files
pytest tests/test_fusion.py              # scoring fusion tests
pytest tests/test_ml_encoder.py          # ML feature encoder tests
pytest tests/test_sandbox_client.py      # dynamic sandbox tests
pytest tests/test_sandbox_pipeline.py    # sandbox pipeline integration tests

# Run tests matching a keyword
pytest -k "test_genai"
```

**Current status:** 197 tests passing, ~93% line coverage over the testable surface.

---

## Safety

Samples may be **live malware**. They are stored hashed and isolated. The dynamic
sandbox runs in a **no-egress, isolated environment** and only triggers when
`APKSCAN_DYNAMIC_ENABLED=true` (requires governance/compliance/legal review).
Anti-evasion detection flags samples that attempt emulator checks or dormancy.

---

## License

AGPL-3.0-or-later (the system wraps MobSF / GPL-3.0). See `progress.md` for details.
