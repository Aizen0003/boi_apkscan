# IMPLEMENTATION_RULES.md

## Implementation Rules — GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System

> Binding rules for the implementation session. These encode the report's decisions, governance, and guardrails. Architecture: `ARCHITECTURE.md`; risks they mitigate: `RISKS.md`; assumptions: `PRD.md`.

### Design principles
1. **GenAI explains, deterministic + ML decides.** GenAI is an interpretation/assist layer only — it must **never be the sole arbiter** of the risk verdict.
2. **Evidence-first and auditable.** Every score and verdict must trace to a logged evidence list. The deterministic rule layer is the primary, reproducible source of truth.
3. **Local-model-first / on-prem.** All samples, artifacts, and inference stay inside the organization. Commercial LLM APIs are optional and **off by default**.
4. **Untrusted input by default.** All APK-derived strings are untrusted data, never instructions, in every prompt path.
5. **Grounded GenAI.** Every material GenAI claim must cite a concrete artifact (function/string/endpoint) that actually exists in the extracted features; otherwise withhold/flag it.
6. **Modularity.** Dynamic analysis is a pluggable module; the system must be fully functional without it.
7. **Fail safe on uncertainty.** When static analysis is defeated (packing/encryption/dynamic loading), flag for escalation and reflect uncertainty — do not under-report.
8. **Human-in-the-loop for severity.** High/Critical verdicts require analyst sign-off before "final."

### Coding constraints
- Use the chosen toolchain: **MobSF** (baseline + REST backbone), **Androguard, jadx, apktool, APKiD, Quark-Engine, YARA**, certificate parsing for static; **Ollama/vLLM** for local LLM; **Celery/Redis, Postgres, object storage** for the pipeline; **Frida/MobSF analyzer** (later CuckooDroid) for the modular dynamic sandbox.
- Default GenAI model: **Qwen2.5-Coder 32B Q4_K_M** on a single 24 GB GPU, with documented fallback to **14B/7B**. Do not introduce a commercial-API dependency.
- **Chunk decompiled code per-function**; never silently truncate LLM input.
- All components exchange features via a **single canonical JSON feature schema** (static workers, dynamic module, GenAI service, scoring engine, report generator must all conform).
- The dynamic sandbox must run with **no egress / dedicated VLAN / gVisor-style isolation**, snapshot/teardown, and accidental-execution safeguards.
- Keep **MobSF patched (≥ v4.4.6)**; respect its **GPL-3.0** license obligations.
- Encode the **ATT&CK for Mobile v19.1** mapping table with the exact technique IDs in `RESEARCH.md`; re-verify against attack.mitre.org at implementation time.
- Implement the hybrid scoring exactly as specified: deterministic rule layer (permission weights + dangerous combos + Quark five-stage + YARA + cert/Firebase/domain) → ML layer (RF/XGBoost + SHAP) → GenAI explanation → fusion with full evidence log.

### Quality standards
- Deterministic rule-layer scores must be **reproducible** for the same input.
- Reports (PDF + JSON) must contain verdict, confidence, risk score, evidence log, ATT&CK mapping, IOCs, and actionable recommendations.
- Detection quality is measured with **precision, recall, F1, FPR, and FNR**; ML predictions ship with **SHAP-style** feature-importance.
- **Audit logging** of every indicator, score contribution, and decision is mandatory.
- **Authenticated, role-based access** to the tool, samples, and reports is mandatory.
- Maintain temporal validation and a **concept-drift monitor**; retraining + YARA/rule refresh on F1 decline.

### Things the coding session must NOT change without checking first
- The principle that **GenAI never solely determines the verdict** (and the human sign-off requirement for High/Critical).
- The **on-prem / local-model-first** posture and **commercial-APIs-off-by-default** default.
- The **untrusted-string isolation** rule for all prompts.
- The **dynamic-sandbox isolation requirements** (no egress, VLAN/gVisor, snapshot/teardown) and the requirement for **security/compliance/legal sign-off before dynamic go-live**.
- The **canonical feature schema** contract (changing it requires coordinated updates across all components).
- The **hybrid four-layer scoring** design and the deterministic rule layer as primary evidence.
- **MVP scope** = static + GenAI core; do not promote dynamic analysis to an MVP dependency.
- **Data governance**: artifact isolation, retention/chain-of-custody, and audit logging.
- The agreed **operating-point policy** (high-recall vs. balanced) and the FNR/FPR thresholds, once set with stakeholders.
- The default **model tier/fallback** chain (changing models requires re-verifying license, benchmarks, and VRAM budget).

---

## Handoff notes (start here)
1. **Read in this order:** `PRD.md` (scope + assumptions) → `RESEARCH.md` (domain truth) → `ARCHITECTURE.md` (system shape) → `TASKS.md` (build order) → `TEST_PLAN.md` (verification) → `RISKS.md` + this file (guardrails).
2. **Build Phase 0 first** (T0.1→T0.20): single-host Docker Compose with MobSF + local LLM, static feature extraction, deterministic rule scoring, GenAI interpretation (grounded + untrusted-string isolation), hybrid fusion, PDF/JSON reporting, audit logging, access control, and High/Critical sign-off. Ship the upload→analyze→report MVP with **no commercial-API egress**.
3. **Then Phase 1** (ML layer + SHAP + temporal validation + drift monitor + operating modes) and **Phase 2** (modular, isolated dynamic sandbox) — Phase 2 only after the security/compliance/legal review.
4. **Honor the guardrails:** GenAI explains, deterministic+ML decides; everything on-prem; all APK strings are untrusted; conform to the canonical feature schema; keep dynamic analysis modular.
5. **Watch the threshold triggers** in `TASKS.md`/`TEST_PLAN.md` (static FNR, GenAI grounding-failure rate, context truncation, drift) — they change build priorities.
6. **Re-verify before coding:** ATT&CK Mobile technique IDs (attack.mitre.org), current model licenses/benchmarks/VRAM, and MobSF patch level. Treat vendor statistics as point-in-time.
