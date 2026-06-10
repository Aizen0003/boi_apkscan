# PRD.md

## Product Requirements Document — GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System (Self-Hosted)

> Source of truth: the research report "GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System (Self-Hosted)". Detailed domain background lives in `RESEARCH.md`; architecture in `ARCHITECTURE.md`; work breakdown in `TASKS.md`; validation in `TEST_PLAN.md`; risks and governance in `RISKS.md` and `IMPLEMENTATION_RULES.md`.

### Problem summary
Fraudsters distribute malicious Android applications (APKs) via WhatsApp, SMS, email, and phishing links to steal customer credentials, intercept OTPs, and perform unauthorized financial transactions. Manual APK analysis is complex, slow, and dependent on scarce cybersecurity experts.

The threat is acute and India-specific: Indian banking customers are targeted by smishing/WhatsApp-delivered fake-bank APKs, droppers, and accessibility-abusing RATs (e.g., SOVA, and families such as Anatsa/TeaBot, Octo2, Medusa, GoldDigger/GoldPickaxe). Core malicious techniques converge on overlay attacks, Accessibility-service abuse, SMS/OTP interception, keylogging, screen capture, and Automated Transfer Systems (ATS) for on-device fraud. (Family details and statistics: see `RESEARCH.md`.)

The product is a self-hosted system that automatically analyzes suspicious APKs using static analysis plus AI-assisted interpretation, classifies threat severity, generates explainable risk scores, and produces investigation reports with actionable recommendations — to enable faster identification of fraudulent apps and support proactive fraud prevention for banks.

### Goals
- Automatically analyze a suspicious APK and identify malicious behavior with minimal analyst effort.
- Provide a hybrid, explainable risk score and verdict band (Benign / Suspicious / Malicious) with confidence and a full evidence list.
- Use GenAI to summarize decompiled code, explain suspicious behavior, map behaviors to MITRE ATT&CK for Mobile, extract IOCs, and draft SOC-ready reports — as an interpretation/assist layer, never the sole verdict.
- Keep all samples, artifacts, and model inference inside the organization (on-prem / self-hosted); make commercial LLM APIs optional and off by default.
- Be fully auditable: every contributing indicator is logged and traceable.
- Ship a pragmatic MVP (static + GenAI core) first; design dynamic analysis as a modular capability that can be added later.

### Non-goals
- Real-time, on-device protection or an endpoint agent.
- iOS analysis (MobSF dynamic analysis is Android-only; iOS is out of scope).
- Building a production-grade, turnkey dynamic malware sandbox in the MVP (dynamic analysis is a modular stretch capability).
- Acting as the autonomous final arbiter of a malware verdict without analyst sign-off for High/Critical cases.
- Mandatory external SOC/case-management integration as an MVP dependency (clean interfaces are provided, but integration is not required for MVP).
- Unpacking every commercial packer/VM-protector or fully defeating all anti-analysis/anti-emulation evasion.

### Primary user flows
1. **Upload → Analyze → Report (core MVP flow):** A cybersecurity analyst uploads a suspicious APK through a web UI (or REST API). The system hashes/dedupes/stores it, queues it for asynchronous processing, runs static analysis + feature extraction, optionally triggers dynamic analysis, computes a hybrid risk score, generates a GenAI-authored explanation and report, and presents a verdict with evidence, ATT&CK mapping, IOCs, and recommendations (PDF/JSON).
2. **Analyst review and sign-off:** For High/Critical verdicts, the analyst reviews the evidence-grounded report and signs off before the verdict is treated as final.
3. **Escalation to dynamic analysis:** When the static layer detects packing/encryption/dynamic code loading, the sample is flagged and (where the dynamic module is enabled) routed to an isolated sandbox for runtime behavior and network capture.
4. **Downstream consumption (optional, post-MVP):** Reports/IOCs are exported or pushed to a SOC/case-management system via the integration API.

### Functional requirements
- **FR1 Ingestion:** Accept APK upload via web UI and REST API; compute file hash; dedupe; persist sample to object storage.
- **FR2 Async processing:** Queue analysis jobs; support priority for urgent samples; process asynchronously.
- **FR3 Static analysis & feature extraction:** Parse `AndroidManifest.xml`, DEX bytecode, resources, certificates, assets, and native libraries; extract permissions, components, APIs, strings, certificate/signature data, embedded payloads; detect packers/obfuscators. Tools: Androguard, jadx, apktool, APKiD, Quark-Engine, YARA, certificate parsing. Output structured JSON features. (Tool roles: `RESEARCH.md`.)
- **FR4 Packing/encryption detection & escalation flag:** Detect obfuscation/packing/encrypted payloads/dynamic DEX loading and set an "escalate to dynamic" flag.
- **FR5 GenAI interpretation:** Use a local LLM (via Ollama/vLLM) to summarize decompiled/smali code, explain suspicious behavior, map to MITRE ATT&CK for Mobile, extract IOCs, and draft reports. All APK-derived strings must be treated as untrusted data, never instructions. RAG over MITRE ATT&CK + internal threat intel.
- **FR6 Hybrid scoring engine:** Combine (1) deterministic rule layer (permission weights + dangerous combinations + Quark five-stage behaviors + YARA hits + cert/Firebase/domain checks), (2) ML layer (RF/XGBoost on permission/API/opcode features, with feature-importance explanation), and (3) GenAI explanation, into a fused final score, verdict band, and confidence — with every contributing indicator logged.
- **FR7 ATT&CK mapping:** Maintain a behavior→technique mapping table using ATT&CK for Mobile v19.1 technique IDs (see `RESEARCH.md`).
- **FR8 Report generation:** Produce PDF and JSON reports containing verdict, confidence, risk score, evidence log, ATT&CK mapping, IOCs, and actionable recommendations.
- **FR9 Artifact storage & search:** Store APKs and reports in object storage; store searchable findings in a database/index.
- **FR10 Analyst sign-off:** Support human sign-off for High/Critical verdicts.
- **FR11 Dynamic analysis (modular, post-MVP):** Optionally run the APK in an isolated sandbox (Frida/MobSF analyzer, later CuckooDroid) and capture API trace, PCAP/network, SMS/file behavior; feed results back into scoring/reporting.
- **FR12 Integration API (interfaces present in MVP, integration optional):** Expose clean APIs/exports for SOC/case-management/downstream alerting.

### Non-functional requirements
- **NFR1 Data residency / privacy:** All samples, artifacts, and inference stay on-prem. Commercial LLM APIs optional and off by default. (Governance: `RISKS.md`, `IMPLEMENTATION_RULES.md`.)
- **NFR2 Auditability:** Full audit logging of every indicator, score contribution, and decision; defined retention and chain-of-custody.
- **NFR3 Security/isolation:** Safe handling of live malware; prevent accidental execution; the dynamic sandbox runs with no egress / dedicated VLAN / gVisor-style isolation, with snapshot/teardown.
- **NFR4 Explainability:** Scores and verdicts must be traceable to deterministic evidence; ML contributions accompanied by feature-importance (SHAP-style); GenAI claims grounded in cited artifacts.
- **NFR5 Resource footprint:** GenAI tier runs on a single 24 GB GPU (Qwen2.5-Coder 32B Q4_K_M), with fallback to 14B/7B on smaller GPUs. (Model details: `RESEARCH.md`.)
- **NFR6 Access control:** Authenticated, role-based access to the tool, samples, and reports.
- **NFR7 Modularity:** Dynamic analysis is a pluggable module; the system must function fully without it.

### Constraints
- On-prem / self-hosted deployment; nothing sensitive leaves the network (assumption — see Assumptions).
- Local/privately hosted models preferred; commercial APIs optional, not required.
- MVP scope is static analysis + AI-assisted interpretation + reporting; dynamic analysis is modular/stretch.
- Standalone analyst tool is the primary product; external integration is not an MVP hard dependency.
- MobSF is GPL-3.0 (license obligations apply); keep MobSF patched (v4.4.6 fixed a SQLite-viewer SQL-injection).
- Static analysis alone cannot defeat all packing/encryption/anti-emulation (drives FR4 and the dynamic module).
- Live-malware handling must be reviewed by the bank's security/compliance/legal functions before any sandbox goes live.

### Success criteria
- Analysts can go from APK upload to a complete, evidence-grounded report without manual reverse engineering for the common case.
- Verdicts are explainable and auditable: every score is backed by a logged evidence list and ATT&CK mapping.
- GenAI output is grounded (cited functions/strings/endpoints actually exist) and never solely determines High/Critical verdicts.
- Detection quality is measured with precision, recall, F1, and explicitly FPR and FNR, with a deliberately chosen operating point. (Targets/thresholds: `TEST_PLAN.md`.)
- The system runs entirely on-prem with commercial APIs disabled.

### Acceptance criteria
- **AC1:** A user can upload an APK (UI + API), and the system stores it, dedupes by hash, and returns a job/sample identifier.
- **AC2:** Static analysis produces structured JSON features (permissions, components, APIs, certificate data, strings, packer/obfuscator detection, embedded-payload indicators).
- **AC3:** Packed/encrypted/dynamic-loading samples are correctly flagged for escalation.
- **AC4:** The hybrid scoring engine returns a numeric score, a verdict band (Benign/Suspicious/Malicious), a confidence value, and a complete evidence log; rule-layer contributions are deterministic and reproducible.
- **AC5:** Behaviors are mapped to ATT&CK for Mobile v19.1 technique IDs.
- **AC6:** A GenAI report (PDF + JSON) is produced; each material claim cites a concrete artifact; APK-derived strings are isolated as untrusted input.
- **AC7:** High/Critical verdicts require analyst sign-off before being marked final.
- **AC8:** The full pipeline runs on a single-host Docker Compose stack with local models and no outbound calls to commercial APIs.
- **AC9:** All indicators and decisions are written to an audit log.
- **AC10 (post-MVP/dynamic):** When enabled, the dynamic module runs the sample in an isolated, no-egress environment and returns API trace, network capture, and behavior signals that feed scoring/reporting.

### Assumptions
> These were explicit interpretation choices made because the problem statement left them open. They are assumptions, not hard requirements from the brief.
- **A1 Deployment context:** Private, self-hosted / on-prem-style environment by default; sensitive APKs and analysis artifacts stay inside the organization; local or privately hosted model access is preferred; commercial APIs are optional rather than required.
- **A2 Dynamic analysis depth:** Dynamic analysis is included in the architecture but kept pragmatic — the core deliverable works with static analysis plus AI-assisted interpretation and reporting. Dynamic analysis (sandbox/emulator behavior capture, network observation) is a modular capability added if time/infrastructure allow.
- **A3 Output/integration target:** The primary product is a standalone analyst tool with an upload/analyze/report workflow. Clean interfaces are defined for later SOC/pipeline integration (APIs, exports, downstream alerting), but external integration is not an MVP hard dependency.
- **A4 Context:** Indian banking fraud context is assumed (problem statement appears bank-/India-oriented), informing threat-intel and sample-collection priorities.
