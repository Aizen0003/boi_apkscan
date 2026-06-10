# RESEARCH.md

## Domain Research — GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System

> This file preserves the domain findings from the source research report. Product decisions derived from it are in `PRD.md`; system design in `ARCHITECTURE.md`; risks/mitigations in `RISKS.md`. Source-reliability notes are in "Caveats / source reliability."

### Relevant background

#### Android banking malware landscape
Modern Android banking trojans are modular, commercialized (Malware-as-a-Service), and increasingly built on leaked source code.

Key families and traits:
- **Cerberus** (2019 RAT; source leaked) spawned **Alien, ERMAC, Hook, Phoenix, Octo**. Capabilities: keylogging, screen recording, overlay attacks, SMS/2FA interception.
- **Anubis** — screenshots, keylogging, SMS theft; descended into Ginp and others.
- **SharkBot** — distributed via Google Play as fake antivirus; abuses Android "Direct Reply" notification feature to self-propagate; uses **ATS (Automated Transfer System)** to change the destination IBAN during a transfer and bypass MFA/biometrics; overlay injections, keylogging via accessibility events, SMS intercept.
- **TeaBot/Anatsa (aka Toddler)** — overlay attacks, screen streaming, accessibility abuse, app-specific keylogging; hosted payloads on GitHub. Per Zscaler ThreatLabz, recent campaigns expanded scope to **more than 831 financial institutions globally** (up from "over 650"; Bitsight corroborates the 831 figure). In a June 24–30, 2025 infection window, a dropper named **"Document Viewer – File Reader"** (package `com.stellarastra.maintainer.astracontrol_managerreadercleaner`, published May 7, 2025) **accumulated an estimated 90,000 downloads** on Google Play before removal (ThreatFabric, via The Hacker News). Anatsa's installer **decrypts each string at runtime using a dynamically generated DES key**, performs **emulation checks and device-model verification** to bypass dynamic-analysis environments, and conceals the **final DEX payload inside asset files**, decrypted at runtime with a static embedded key — directly relevant to why static-only analysis is insufficient.
- **Octo/Octo2** — descendant of Exobot/Coper; MaaS; Octo2 (Sept 2024) adds a Domain Generation Algorithm (DGA) for C2, stronger obfuscation, and improved remote-control stability for Device Takeover (DTO)/on-device fraud; distributed via **Zombinder** to bypass Android 13+ restrictions; masquerades as Chrome/NordVPN.
- **Medusa** — RAT with VNC real-time screen sharing, accessibility abuse; 2024 variant uses a lightweight permission set, full-screen overlays, and remote uninstall.
- **GoldDigger / GoldDiggerPlus / GoldKefu / GoldPickaxe** (GoldFactory, APAC) — accessibility abuse, web-fake overlays of banks, and notably **biometric face/ID-document harvesting** to create deepfakes for bypassing facial-recognition checks; GoldPickaxe is a rare iOS+Android family.
- **SOVA** — flagged by CERT-In as targeting Indian banking customers; keylogging, cookie theft, MFA interception, screenshots, overlays; distributed via smishing.

**Techniques:** overlay/screen-overlay attacks (fake WebView login over banking app), Accessibility Service abuse (read screen, auto-grant permissions, click on the user's behalf), SMS interception (OTP/2FA), keylogging, screen recording/VNC, RAT/device-takeover, and ATS for automated fraudulent transfers.

**Distribution:** smishing (SMS phishing), WhatsApp-delivered APKs, fake government/utility/bank apps, droppers (sometimes on Play Store), QR codes, SEO/search-engine poisoning, malvertising, Telegram/Discord, GitHub-hosted payloads, and fake update dialogs (`REQUEST_INSTALL_PACKAGES`).

**India context:** Zimperium zLabs' **"Mobile Indian Cyber Heist: FatBoyPanel"** report documented a campaign of **almost 900 malware samples** primarily targeting Indian bank users, spreading via WhatsApp as APKs, forwarding SMS through **~1,000 live phone numbers**, with **over 222 publicly accessible Firebase storage buckets containing 2.5 GB of sensitive data, affecting an estimated 50,000 users**. Primary impersonated banks were ICICI, SBI, PNB, RBL, IndusInd, and Union Bank; 63% of attacker numbers traced to West Bengal, Bihar, and Jharkhand. McAfee, Cyble, and Cyfirma separately document campaigns impersonating Indian banks and government schemes (e.g., PM Surya Ghar electricity subsidy). Permissions abused: `READ_SMS/SEND_SMS/RECEIVE_SMS`, `READ_PHONE_STATE`, `REQUEST_INSTALL_PACKAGES`, `QUERY_ALL_PACKAGES`. Elibomi specifically targets India via smishing. RBI's Annual Report 2024-25 records **13,516 digital-payment frauds in FY25 (56.5% of total fraud cases, involving ₹520 crore)**, out of 23,953 total bank frauds worth ₹36,014 crore (advances accounted for ~92% of value). RBI has introduced **MuleHunter.AI** and the **Digital Payments Intelligence Platform (DPIP)** to counter mule-account fraud.

Threat-scale context: per the BBC (April 30, 2025), nearly 2.5 million people lost about $2.5bn to digital payment fraud in 2025 — a 4,300% rise since 2021 (point-in-time figure; see Caveats).

### Key concepts and terms
- **APK structure to parse:** `AndroidManifest.xml` (binary-encoded), `classes.dex` (DEX bytecode), resources/`resources.arsc`, assets (often hiding embedded payload APKs / encrypted DEX), `META-INF` certificates, and native `.so` libraries.
- **Overlay attack:** fake login UI drawn over a legitimate banking app to capture credentials.
- **Accessibility Service abuse:** using Android accessibility APIs to read screen content, auto-grant permissions, and act on the user's behalf.
- **ATS (Automated Transfer System):** on-device automation that performs fraudulent transfers and can alter transfer destinations to bypass MFA/biometrics.
- **DTO (Device Takeover):** full remote control of the victim device.
- **Dropper / Zombinder:** delivery mechanisms that stage/install the real payload and bypass newer Android restrictions.
- **MITRE ATT&CK for Mobile (v19.1, released April 28, 2026; 12 tactics):** behavior-to-technique taxonomy. Key Android-banking mappings (verified against the live v19.1 matrix):
  - Overlay/fake login → **T1417.002 GUI Input Capture**
  - Accessibility abuse → **T1453 Abuse Accessibility Features**
  - SMS read (OTP) → **T1636.004 Protected User Data: SMS Messages**; SMS suppress/intercept → **T1582 SMS Control**
  - Keylogging → **T1417.001 Keylogging**
  - Screen capture → **T1513 Screen Capture** (camera → T1512 Video Capture)
  - RAT/VNC → **T1663 Remote Access Software**
  - Hide icon → **T1628.001 Suppress Application Icon**
  - Dynamic code load → **T1407 Download New Code at Runtime** (C2 transfer companion **T1544 Ingress Tool Transfer**)
  - Enumerate installed apps → **T1418 Software Discovery** (.001 Security Software Discovery)
  - Obfuscation/packing → **T1406 Obfuscated Files or Information** (.002 Software Packing)
  - Smishing delivery → **T1660 Phishing** (Tactic: Initial Access, TA0027)
  - 12 tactics: Initial Access (TA0027), Execution (TA0041), Persistence (TA0028), Privilege Escalation (TA0029), Defense Evasion (TA0030), Credential Access (TA0031), Discovery (TA0032), Lateral Movement (TA0033), Collection (TA0035), Command and Control (TA0037), Exfiltration (TA0036), Impact (TA0034).

### Comparable approaches or patterns

#### Static analysis tooling
| Tool | Role | Strengths | Limits | Pipeline-friendly |
|---|---|---|---|---|
| **Androguard** | Python library/CLI; parse manifest, DEX, permissions, components, call graphs | Programmatic API, the de-facto backbone | Decompilation imperfect on obfuscated code; maintenance lapsed historically | Yes (native Python) |
| **jadx** | DEX→Java decompiler (jadx-gui) | Best-readable Java output | Defeated by ZIP tricks / `$JADXBLOCK` (GodFather v3), VM-packers (Virbox) | CLI scriptable |
| **apktool** | Decode resources + manifest, baksmali to smali, rebuild | Decodes binary manifest, repacking | Not a Java decompiler | CLI |
| **dex2jar / baksmali** | DEX→JAR; DEX→smali | Feed other tools | Lower-level | CLI |
| **APKiD** | "PEiD for Android" — detect compilers, packers, obfuscators | Triage packing fast | Detects, doesn't unpack | Yes (Python) |
| **Quark-Engine** | Rule-based behavior scoring; Dalvik bytecode loader resists obfuscation | Scriptable, scoring + call graph + radar; integrates with jadx/Ghidra | Rule coverage dependent | Yes (Python) |
| **MobSFScan / mobsfscan** | SAST patterns | CI-friendly | Source/pattern focused | Yes |
| **FlowDroid** | Taint/data-flow analysis | Source→sink tracking | Heavy | Batch |
| **Androwarn / QARK** | Behavior/security smells | Useful features | Deprecated/unmaintained | Limited |
| **DroidLysis** | Property extractor | Triage | — | Python |

Triage best practice (AWAKE/REMnux): run VirusTotal + APKiD + manifest review before deep jadx work. Packed samples lower AV detection because engines scan the stub, not the payload.

#### Dynamic analysis / sandbox infrastructure
- **MobSF Dynamic Analyzer** — Android-only DAST via emulator (Android ARM emulator support, also AVD); uses **Frida** for runtime instrumentation, SSL-pinning bypass, API tracing; captures network traffic and runtime data; Web API Viewer extracts endpoints. No real-device or iOS DAST.
- **CuckooDroid** — extends Cuckoo Sandbox for Android; static + dynamic + traffic analysis, API call trace, some VM-detection evasion, SSL inspection, behavioral signatures; supports KVM/Xen/VirtualBox/VMware/AVD. Caveat: aging (last major work ~2017); needs fixes for modern Android; native-code analysis limited.
- **DroidBox** — older instrumentation (Android 4.1-era images), used inside AndroPyTool.
- **AndroPyTool** — Python framework chaining DroidBox, FlowDroid, Strace, AndroGuard, VirusTotal; outputs JSON/CSV/MongoDB; produced the OmniDroid dataset.
- **Frida-based instrumentation** — the modern foundation: API hooking, gesture/intent inspection, SSL bypass.
- **Emulator approaches** — Android-x86/AVD; mind **anti-emulation evasion** (malware like Anatsa detects emulator artifacts/device models and stays dormant; CuckooDroid only partially evades).
- **Captured behaviors:** API hooking, network capture via mitmproxy, file/system calls (strace), SMS/contact access, dynamically loaded payloads, C2 endpoints/PCAP.
- **Infra challenges/risks:** running live malware needs strong isolation (gVisor containers / dedicated VLAN / no production network), snapshot/teardown, anti-emulation handling, ARM-vs-x86 image fidelity, and significant compute (research sandboxes commonly run ~10 parallel VMs at 2 cores/2 GB each). (Operational risk detail: `RISKS.md`.)

#### Integrated frameworks — MobSF
**MobSF** (Ajin Abraham; GPL-3.0; ~20.7k stars; v4.4.6 March 2026): static + dynamic + malware analysis for APK/IPA/APPX and source; self-hostable via `docker pull opensecurity/mobile-security-framework-mobsf`; REST API (`/api/v1/upload`, `/scan`, `/report_json`, `/download_pdf`) and CLI; integrates APKiD and Quark; checks permissions, certificates, code (CWE/OWASP MASVS/Top-10), trackers (Exodus 428-tracker DB), domain malware checks, Firebase, server geolocation.
- **Scoring:** Security Score 0-100 with grade A-F. Formula: `Score = 100 - ((High + 0.5*Medium - 0.2*Secure) / (High + Medium + Secure) * 100)`. Each issue carries a CVSS-based severity. Grades: 60%+ = A, 40-59% = B, 30-39% = C, <30% = F.
- **Limits:** docs under-explain results; many "dangerous" flags are legitimate-by-design (false positives); emulator-only DAST, no real-device/iOS DAST; v4.4.6 patched an SQL-injection in the SQLite DB viewer (keep patched). Privacy-sensitive on-prem use is an explicit MobSF strength (nothing leaves the network).
- **Other integrated frameworks:** Quark-Engine (scoring), AndroPyTool (feature extraction), FirmwareDroid (selected AndroGuard 3.3.5 + Androwarn 1.6.1 + APKiD 2.2.1 + QARK 4.0.0 for static analysis), Drozer (manual IPC/exported-component probing — complements MobSF).

#### Generative AI in malware analysis
LLMs are used as a reverse-engineering "sidekick": summarizing decompiled/smali code, renaming functions/variables, explaining suspicious behavior, mapping to MITRE ATT&CK, extracting IOCs, and generating SOC-ready reports.
- **Documented patterns:** Ghidra/decompiler output → LLM classification (arXiv decompilation-driven malware detection); Cisco Talos uses Ollama + Devstral:24b locally alongside cloud models for RE; MCP-based agentic setups (o3, Gemini 2.5 Pro) interacting with analysis-in-progress.
- **Local/open models suitable for self-hosting (Ollama/vLLM):**
  - **Qwen2.5-Coder 32B** (Q4_K_M ~24 GB VRAM, RTX 3090/4090; 92.7% HumanEval; Apache-2.0) — the "sweet spot."
  - **Qwen2.5-Coder 14B** (~10-11 GB VRAM), **7B** (~4.7 GB, 8 GB GPU; 88.4% HumanEval pass@1).
  - **DeepSeek-Coder-V2-Lite 16B** (MoE, 2.4B active; ~12-13 GB VRAM Q4).
  - **DeepSeek-R1 distills** (reasoning) and **Llama 3.3 70B** (~40 GB Q4, larger context for big code) for heavier tiers.
  - Quantization Q4_K_M roughly halves VRAM with <1% benchmark loss.
- LLM limitations are critical to design and are summarized in "Risks and pitfalls" below; mitigations in `RISKS.md` and rules in `IMPLEMENTATION_RULES.md`.

#### Risk scoring and classification methodologies
- **Permission-based scoring:** weight dangerous permissions and dangerous *combinations*. Highest-weight indicators: `BIND_ACCESSIBILITY_SERVICE`, `BIND_DEVICE_ADMIN`, `REQUEST_INSTALL_PACKAGES` (weight 10 each in a representative scorer), `READ_SMS` (9), `RECORD_AUDIO` (9), with combination bonuses (e.g., `INTERNET` + `READ_SMS` = exfiltration capability). Normalize to 0-100 → Low/Moderate/High/Critical.
- **Quark-Engine scoring:** "order theory of crime" — five stages (1. permission requested, 2. native API call, 3. combination of native APIs, 4. calling *sequence* of native APIs, 5. APIs handling the same register). Weighted score grows exponentially: `(2^(confidence-1) * score) / 2^4`; obfuscation-resistant via its Dalvik bytecode loader. A 100% confidence match = full five-stage match.
- **MobSF scoring:** CVSS-like per-issue severity feeding the A-F grade (formula above).
- **ML-based classification & datasets:**
  - **Drebin** (5,560 malware / 179 families, 2010-2012; 215-attribute feature vectors; permissions+intents+API calls+network) — the most-used benchmark.
  - **AndroZoo** (24M+ APKs, time-stamped, VirusTotal-verified labels; ~15.7% malware) — best for evolution/temporal studies.
  - **CICMalDroid 2020** (~17,341 samples; Adware/Banking/SMS/Riskware; static+dynamic+network features).
  - **CICAndMal2017** (network traffic), **KronoDroid** (time-based hybrid), **MalGenome/AMD** (largely discontinued), **MalNet**, **OmniDroid**.
  - Best classifiers in literature: Random Forest, SVM, XGBoost, LightGBM, GNNs; permissions/intents rank highest by Information Gain; reported F1 frequently 92-99% (caveat: cross-dataset drops 5-10%, and concept drift degrades F1 — Chen et al. saw F1 fall ~0.99→0.76 within six months).
- **Recommended hybrid scoring (explainable/auditable for a bank):**
  1. **Deterministic rule layer** (permission weights + dangerous combos + Quark behaviors + YARA hits + cert/Firebase/domain checks) → primary, fully traceable evidence.
  2. **ML layer** (RF/XGBoost on permissions/API/opcode features) → probability with feature-importance (SHAP-style explanation).
  3. **GenAI layer** → human-readable explanation + ATT&CK mapping + report; **never the sole verdict**.
  4. **Fusion:** weighted/ensemble final score with every contributing indicator logged for audit; verdict band (Benign/Suspicious/Malicious) with confidence and the exact evidence list.

#### Threat intelligence and IOC sources
- **VirusTotal API** — multi-engine detection ratio; check ESET/Kaspersky/Bitdefender names for most consistent Android family attribution; APKiD packer info in the Details tab.
- **MalwareBazaar (abuse.ch)** — sample sharing, hashes, tags, community YARA rules.
- **AndroZoo** — labeled APK corpus (academic access).
- **YARA** — Android string/byte rules; can be auto-generated from extracted IOCs; community rules referenced via MalwareBazaar.
- **MITRE ATT&CK for Mobile** — behavior→technique mapping (technique IDs above).
- **RAG over threat intel** (MITRE ATT&CK, internal reports) reduces hallucination and keeps the model current without retraining (RAGIntel, CyberRAG patterns).

#### Architecture patterns (summary)
Production malware pipelines (OSSF Package Analysis, CAPE-based dataset pipelines, Aleph, the AWS serverless pattern, message-bus + Celery patterns) converge on a 10-stage pipeline: ingestion/upload → queue → static workers → optional dynamic sandbox → feature extraction → GenAI interpretation → scoring engine → report generation → artifact storage → integration API. Full design and the single-host MVP layout are in `ARCHITECTURE.md`.

### Technical considerations
- Static-only analysis is insufficient against runtime-decrypted payloads, asset-hidden DEX, and dynamic loading (e.g., Anatsa, ClayRat) — hence the packing/encryption escalation flag and the modular dynamic sandbox.
- LLM context-window limits force per-function chunking of decompiled code; local Ollama may truncate prompts and return invalid output.
- All APK-derived strings must be treated as untrusted data, never instructions (prompt-injection defense).
- Banking cost asymmetry makes both false negatives and false positives expensive; the operating point must be a deliberate, exposed policy choice (high-recall vs. balanced). (Evaluation detail: `TEST_PLAN.md`.)
- Concept drift degrades ML classifiers quickly; temporal validation, drift monitoring, and periodic retraining are required. (See `TASKS.md` Stage 1.)

### Risks and pitfalls (summary — full register in `RISKS.md`)
- **Static-analysis defeat:** obfuscation, commercial packers (Virbox VM), `$JADXBLOCK`/ZIP tricks, encrypted payloads in `assets/*.dat` decrypted at runtime (e.g., ClayRat AES/CBC; Anatsa DES-keyed strings + static-key DEX in assets), dynamic DEX loading — static alone misses these; flag "packed/encrypted → escalate to dynamic."
- **Anti-analysis/anti-emulation:** dormant-in-emulator behavior, device-model checks; Zombinder-style staged installs bypassing Android 13+.
- **GenAI failure modes:** hallucinated functions/capabilities, mangled C2 strings, prompt injection via embedded strings, context overflow/truncation. SentinelLABS ("Building an Adversarial Consensus Engine," Alex Delamotte & Gabriel Bernadett-Shapiro) found single-tool LLM runs produce confident-but-wrong reports (half the cited functions wrong, "capabilities" that are dead standard-library code, a C2 endpoint mangled by a string-extraction error); their fix is a serial multi-agent pipeline (radare2 → Ghidra → Binary Ninja → IDA Pro) with an "Active Rejection Mandate." Check Point Research documented real malware embedding "Ignore all previous instructions…" to evade AI analysis.
- **Dataset drift / evasion:** model staleness, adversarial feature manipulation.
- **Operational/security risks of the system itself:** safe live-malware handling (isolation, no egress, snapshot/destroy), preventing accidental execution, artifact data governance, access control, audit logging, and legal/compliance (chain-of-custody, retention, RBI/CERT-In reporting).

### Open questions
- Acceptable bank thresholds for FNR/FPR and the default operating mode (high-recall vs. balanced) — to be set with stakeholders. (Trigger logic in `TEST_PLAN.md`.)
- Whether/when to adopt the multi-agent verifier/consensus pattern for GenAI grounding (depends on measured factual-grounding failure rate).
- Final model tier selection and GPU budget (32B vs. 14B/7B) given available hardware; verify current model licenses/benchmarks before committing.
- Sourcing and licensing for India-specific samples (FatBoyPanel/SOVA families) for ML training.
- Scope and timing of dynamic-sandbox enablement given the required security review.

### Caveats / source reliability
- Several malware-capability and statistics sources are vendor blogs/news (Bitsight, Zscaler ThreatLabz, ThreatFabric, Group-IB, McAfee, Cyble, Zimperium); family capabilities are well-corroborated across multiple vendors, but specific victim counts and loss figures are point-in-time and sometimes self-reported. The ~$2.5bn-2025 India figure traces to a BBC report (April 30, 2025; several outlets garbled this as "$25bn"); RBI's own figures (₹520 crore / 13,516 cases for digital payment fraud in FY25) are more conservative and differently scoped — both are cited.
- Some 2026-dated "best model" rankings and VRAM figures come from fast-moving community/blog sources; verify current model licenses and benchmarks (Hugging Face cards) before committing. The model landscape shifts rapidly.
- ML F1 numbers (92-99%) are dataset-specific and optimistic; real-world cross-dataset and temporal performance is materially lower due to concept drift.
- CuckooDroid is aging and may need substantial engineering for modern Android; treat it as a research-grade option, not turnkey.
- MITRE ATT&CK Mobile content was confirmed at v19.1 (April 2026); one matrix page served a cached v18.1 permalink — technique IDs are unchanged across v18→v19, but re-verify IDs against attack.mitre.org at implementation time.
- This is a planning research package, not a security clearance to deploy; live-malware handling must be reviewed by the bank's security/compliance/legal functions before any sandbox goes live.
