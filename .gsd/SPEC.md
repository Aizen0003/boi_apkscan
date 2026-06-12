# SPEC.md — Project Specification

> **Status**: `FINALIZED`
>
> ⚠️ **Planning Lock**: SPEC is FINALIZED.

## Vision

A self-hosted, on-premises system that automatically analyzes suspicious Android APKs for banking-malware patterns, producing explainable, auditable risk scores, and SOC-ready reports. It is designed to tackle the specific Indian banking-fraud threat model (overlay attacks, accessibility-service abuse, SMS-OTP interception, keylogging, screen capture, RATs, droppers, and ATS).

## Goals

1. **Deterministic Static Analysis** — Automatically decompile and extract permissions, API references, components, certificate details, native libraries, strings, detected packers, and run YARA/Quark Engine rules.
2. **Local GenAI Interpretation Layer** — Generate grounded, citation-enforced code summaries and behavior explanations using an offline local LLM via Ollama/vLLM with strict prompt injection sanitization.
3. **Auditable Hybrid Scoring Fusion** — Fuse deterministic rule-scoring (primary) and GenAI explanation into a 0-100 risk score, verdict band (Benign/Suspicious/Malicious), and confidence level, with all indicator contributions logged.
4. **On-Prem Ingestion & Reporting** — Provide web and REST API upload interfaces, async Celery/Redis processing, object storage, append-only tamper-evident audit logs, JWT auth, and PDF/JSON reports.
5. **Analyst Review & Export** — Gate High/Critical severity verdicts on analyst sign-off and support exporting results to SOC-compliant STIX-2.1 format.
6. **Machine Learning Classifier (Phase 1)** — Train an RF/XGBoost model on permission/API features to output threat probabilities with SHAP feature-importance explanations and integrate it into the scoring fusion.
7. **Temporal Validation & Drift Monitoring (Phase 1)** — Enforce temporal training splits, monitor performance over time, and trigger retraining alerts on concept drift.
8. **Isolated Dynamic Sandbox (Phase 2)** — Run packed/encrypted/dynamic-loading APKs in a modular, isolated sandbox capturing API traces and network traffic (PCAP).

## Non-Goals (Out of Scope)

- Real-time on-device endpoint protection or mobile agent app.
- iOS application analysis.
- Defeating advanced packers or commercial VM protectors (handled via sandbox escalation).
- Autonomous final decision maker for critical block actions without human analyst review.

## Constraints

- On-prem / self-hosted execution only: commercial LLM APIs are disabled by default.
- Data residency: no APK samples, decompiled files, or inference strings may leave the private network.
- Licensing compatibility: must be AGPL-3.0-or-later compatible to wrap GPL-3.0 MobSF over the network.
- GPU footprint: LLM must run comfortably on an 8 GB RTX 4060 GPU (defaulting to 7B model) and scale to a 24 GB GPU (32B model).

## Success Criteria

- [x] Static feature extraction emits a canonical JSON matching all test cases.
- [x] Local LLM executes entirely offline, chunking long code and isolating untrusted strings.
- [x] All 112 core unit and integration tests run successfully and pass.
- [ ] ML layer achieves >95% recall on holdout banking malware datasets while maintaining <2% false positive rate (Phase 1).
- [ ] SHAP explanations correctly attribute feature importances to permissions and APIs.
- [ ] Drift monitoring detects performance degradation and triggers retraining.

---

*Last updated: 2026-06-12*
