# TASKS.md

## Implementation Tasks — GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System

> Tasks are derived from the roadmap in the source report (Stage 0 MVP, Stage 1 ML + drift, Stage 2 dynamic sandbox). Build order is top-to-bottom. Each task is atomic and testable; see `TEST_PLAN.md` for verification and `IMPLEMENTATION_RULES.md` for constraints. Architecture references: `ARCHITECTURE.md`.

### Phase 0 — MVP: static + GenAI core (target ~weeks 1–8)

- **T0.1 Stand up self-hosted base stack.** Single-host Docker Compose: web app, worker(s), Redis, Postgres, object storage, MobSF container, Ollama container. No outbound calls to commercial APIs.
  - Depends on: none. Test: stack boots; all services healthy; egress to commercial APIs disabled.
- **T0.2 Deploy MobSF as baseline scanner + REST backbone.** Self-host via `opensecurity/mobile-security-framework-mobsf`; verify REST API (`/api/v1/upload`, `/scan`, `/report_json`, `/download_pdf`); ensure patched version (≥ v4.4.6).
  - Depends on: T0.1. Test: a sample APK scans end-to-end through MobSF REST and returns JSON.
- **T0.3 Ingestion service (UI + REST API).** Upload APK, compute hash, dedupe, persist to object storage, create job, return sample/job ID.
  - Depends on: T0.1. Test: AC1 (upload via UI and API; dedupe by hash; ID returned).
- **T0.4 Async job queue + worker orchestration.** Celery/Redis; priority for urgent samples; job status tracking.
  - Depends on: T0.1, T0.3. Test: jobs enqueue/run asynchronously; priority ordering honored; status queryable.
- **T0.5 Static analysis worker — feature extraction.** Wrap MobSF + Androguard + APKiD + Quark-Engine + jadx + YARA + certificate parsing. Parse manifest, DEX, resources, certificates, assets, native libs. Emit canonical structured JSON features (permissions, components, APIs, strings, cert data, packer/obfuscator detection, embedded-payload indicators, Quark behavior matches, YARA hits).
  - Depends on: T0.2, T0.4. Test: AC2; features match the canonical schema.
- **T0.6 Packing/encryption/dynamic-loading detector + escalation flag.** From APKiD/Quark/heuristics, set the "escalate to dynamic" flag.
  - Depends on: T0.5. Test: AC3 on known packed/encrypted samples.
- **T0.7 ATT&CK-Mobile mapping table.** Encode behavior→technique mapping using v19.1 IDs (overlay→T1417.002, accessibility→T1453, SMS→T1636.004/T1582, keylogging→T1417.001, screen capture→T1513, RAT→T1663, hide icon→T1628.001, dynamic load→T1407/T1544, app discovery→T1418, obfuscation→T1406, smishing→T1660; 12 tactics). Re-verify IDs against attack.mitre.org at implementation time.
  - Depends on: none (can run parallel). Test: each supported behavior resolves to the correct technique ID.
- **T0.8 Deterministic rule-scoring layer.** Permission weights + dangerous combinations (e.g., `BIND_ACCESSIBILITY_SERVICE`/`BIND_DEVICE_ADMIN`/`REQUEST_INSTALL_PACKAGES`=10, `READ_SMS`/`RECORD_AUDIO`=9; `INTERNET`+`READ_SMS` bonus) + Quark five-stage behavior scores + YARA hits + cert/Firebase/domain checks. Normalize to 0–100; emit per-indicator evidence.
  - Depends on: T0.5, T0.7. Test: deterministic/reproducible scores; evidence list complete (part of AC4).
- **T0.9 Local LLM interpretation service.** Qwen2.5-Coder 32B Q4_K_M on 24 GB GPU via Ollama/vLLM, with documented fallback to 14B/7B. Per-function chunking of decompiled code to avoid context overflow/truncation.
  - Depends on: T0.1. Test: model serves locally; long inputs are chunked, not truncated; no commercial API used.
- **T0.10 Prompt-injection isolation.** Treat all APK-derived strings strictly as untrusted data, never instructions, in every prompt path.
  - Depends on: T0.9. Test: embedded "ignore previous instructions" strings do not alter model behavior (TEST_PLAN failure scenario).
- **T0.11 RAG over ATT&CK + internal threat intel.** Ground GenAI explanations/mappings in retrieved ATT&CK + internal TI context.
  - Depends on: T0.7, T0.9. Test: explanations cite retrieved context; ATT&CK references correct.
- **T0.12 GenAI grounding/citation enforcement.** Require the LLM to cite the concrete artifact (function/string/endpoint) for each material claim; flag/withhold claims whose cited artifact does not exist.
  - Depends on: T0.9, T0.5. Test: cited artifacts exist in features (TEST_PLAN GenAI-validation).
- **T0.13 Hybrid scoring fusion.** Fuse rule layer (primary) + GenAI explanation into final score, verdict band (Benign/Suspicious/Malicious), and confidence, with the full evidence log. GenAI explains, deterministic layer decides. (ML layer wired in Phase 1.)
  - Depends on: T0.8, T0.12. Test: AC4; verdict reproducible from evidence.
- **T0.14 Report generator (PDF + JSON).** Verdict, confidence, risk score, evidence log, ATT&CK mapping, IOCs, actionable recommendations.
  - Depends on: T0.13. Test: AC5, AC6; reports render in both formats.
- **T0.15 Artifact storage + searchable findings.** Object store for APKs/reports; DB/index for findings; retention/chain-of-custody fields.
  - Depends on: T0.3, T0.14. Test: artifacts retrievable; findings searchable.
- **T0.16 Audit logging.** Log every indicator, score contribution, and decision.
  - Depends on: T0.13. Test: AC9; complete audit trail per analysis.
- **T0.17 AuthN/AuthZ.** Authenticated, role-based access to tool, samples, reports.
  - Depends on: T0.1. Test: unauthorized access blocked; roles enforced.
- **T0.18 Analyst review + sign-off for High/Critical.** Block "final" status until analyst sign-off.
  - Depends on: T0.13, T0.17. Test: AC7.
- **T0.19 Integration/export interface (present, not required).** Clean API/exports for SOC/case-management/alerting; off the critical path.
  - Depends on: T0.14. Test: FR12; report/IOC export works; MVP functions without it.
- **T0.20 End-to-end MVP wiring + decision rule.** Confirm upload→analyze→report on a single-host stack with local models and no commercial API; enforce "GenAI explains, deterministic+ML decides."
  - Depends on: T0.3–T0.18. Test: AC8 + full E2E (TEST_PLAN).

### Phase 1 — ML layer + drift management (target ~weeks 8–16)

- **T1.1 Assemble training corpus.** Drebin + CICMalDroid 2020 + AndroZoo, plus collected India-specific samples (e.g., FatBoyPanel/SOVA families) from MalwareBazaar/VirusTotal. (Resolve sample licensing — `RESEARCH.md` open questions.)
  - Depends on: Phase 0 feature schema (T0.5). Test: corpus loaded; labels verified; class balance documented.
- **T1.2 Feature engineering.** Permission/API/opcode features aligned to the canonical feature schema.
  - Depends on: T1.1, T0.5. Test: feature vectors reproducible from raw APKs.
- **T1.3 Train ML classifier.** RF/XGBoost (per literature). Output malware probability.
  - Depends on: T1.2. Test: precision/recall/F1/FPR/FNR reported on holdout (TEST_PLAN).
- **T1.4 SHAP-style feature-importance explanations.** Attach explanation to each ML prediction.
  - Depends on: T1.3. Test: explanations present and consistent with model.
- **T1.5 Integrate ML layer into scoring fusion.** Wire ML probability + explanation into T0.13 fusion.
  - Depends on: T1.3, T1.4, T0.13. Test: fused verdict reflects all three layers; evidence log includes ML contribution.
- **T1.6 Temporal validation.** Train-on-past / test-on-future evaluation.
  - Depends on: T1.3. Test: temporal split metrics recorded (TEST_PLAN).
- **T1.7 Concept-drift monitor + retraining trigger.** Monitor F1 over time; trigger retraining and YARA/rule refresh on decline.
  - Depends on: T1.6. Test: simulated drift fires the trigger.
- **T1.8 Operating-mode policy.** Expose high-recall vs. balanced modes; track precision/recall/FPR/FNR per mode.
  - Depends on: T1.5. Test: switching modes changes the operating point as specified.

### Phase 2 — Dynamic sandbox (stretch, target ~weeks 16+)

- **T2.1 Isolated sandbox environment.** No-egress / dedicated VLAN / gVisor-style isolation with snapshot/teardown. Security/compliance/legal review completed before go-live.
  - Depends on: governance sign-off (`RISKS.md`). Test: no egress; clean snapshot restore; accidental-execution safeguards verified.
- **T2.2 Frida/MobSF dynamic analyzer.** Capture API trace, network/PCAP (mitmproxy), SMS/file behavior; later evaluate CuckooDroid (treat as research-grade).
  - Depends on: T2.1. Test: AC10; runtime behaviors captured on a known sample.
- **T2.3 Auto-trigger on escalation flag.** Route flagged (packed/encrypted/dynamic-loading) samples to the sandbox.
  - Depends on: T0.6, T2.2. Test: flagged samples auto-route; unflagged do not.
- **T2.4 Feed dynamic results into scoring/reporting.** Append dynamic features to the feature store and fusion/report.
  - Depends on: T2.2, T0.13, T0.14. Test: dynamic signals appear in evidence log and report.
- **T2.5 Anti-emulation handling.** Account for dormant-in-emulator/device-model checks (e.g., Anatsa); document residual gaps.
  - Depends on: T2.2. Test: known evasive sample handled or explicitly flagged as inconclusive.

### Threshold-driven follow-ups (conditional)
- If static FNR on a labeled holdout exceeds the agreed bank threshold (e.g., >2–3%), **prioritize Phase 2** sooner.
- If GenAI factual-grounding checks fail above the agreed rate (cited artifacts don't exist), **add the multi-agent verifier/consensus pattern** before relying on AI text.
- If LLM context truncation degrades summaries, **chunk per-function and/or move to a larger-context model tier**.
- If the drift monitor shows F1 decline, **trigger retraining and refresh YARA/rules** (T1.7).
