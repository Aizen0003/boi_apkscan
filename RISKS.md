# RISKS.md

## Risk Register — GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System

> Risks and mitigations consolidated from the report. Design rules that enforce these mitigations are in `IMPLEMENTATION_RULES.md`; verification in `TEST_PLAN.md`. Source-reliability caveats are at the end.

### Technical risks
- **Static-analysis defeat (high).** Obfuscation, commercial packers (Virbox VM), `$JADXBLOCK`/ZIP tricks, encrypted payloads in `assets/*.dat` decrypted at runtime (e.g., ClayRat AES/CBC; Anatsa DES-keyed strings + static-key DEX in assets), and dynamic DEX loading — static alone misses these.
  - *Mitigation:* detect packing/encryption/dynamic loading and **flag "escalate to dynamic"**; provide the modular dynamic sandbox; reflect uncertainty in the verdict rather than under-reporting.
- **Anti-analysis / anti-emulation (high).** Dormant-in-emulator behavior, device-model checks; Zombinder-style staged installs bypassing Android 13+.
  - *Mitigation:* isolation and (where possible) emulation-evasion handling in the sandbox; explicitly mark inconclusive cases; document residual gaps.
- **GenAI hallucination / false confidence (high).** Single-tool LLM runs produce confident-but-wrong reports (e.g., half the cited functions wrong, "capabilities" that are dead standard-library code, a C2 endpoint mangled by string extraction — SentinelLABS).
  - *Mitigation:* **GenAI explains, deterministic+ML decides**; require artifact citations and grounding checks; human sign-off for High/Critical; adopt multi-agent verifier/consensus ("Active Rejection Mandate") if grounding-failure rate exceeds the agreed threshold.
- **Prompt injection via embedded strings (high).** Real malware embeds "Ignore all previous instructions…" to evade AI analysis (Check Point Research).
  - *Mitigation:* treat **all APK-derived strings as untrusted data, never instructions**, in every prompt path.
- **LLM context overflow/truncation (medium).** Large decompiled code overflows context; local Ollama may truncate and return invalid output.
  - *Mitigation:* per-function chunking; detect truncation; escalate to larger-context model tier if needed.
- **Dataset drift / evasion (high).** ML classifiers degrade quickly (F1 ~0.99→0.76 in six months); adversarial feature manipulation; cross-dataset performance drops.
  - *Mitigation:* temporal validation, drift monitoring, periodic retraining, YARA/rule refresh.
- **CuckooDroid maturity (medium).** Aging (last major work ~2017); needs engineering for modern Android; limited native-code analysis.
  - *Mitigation:* treat as research-grade; prefer Frida/MobSF analyzer first; scope engineering effort if adopted.
- **MobSF false positives (medium).** Many "dangerous" flags are legitimate-by-design.
  - *Mitigation:* require corroborating evidence before a Malicious verdict; never auto-flag on a single permission.
- **MobSF security posture (medium).** v4.4.6 patched a SQLite-viewer SQL-injection.
  - *Mitigation:* keep MobSF patched (≥ v4.4.6); track upstream advisories.

### Product risks
- **False negatives (critical for banking).** A fraudulent APK cleared → direct customer financial loss, fraud, regulatory exposure.
  - *Mitigation:* deliberate operating-point policy (high-recall mode available); track FNR explicitly; threshold-driven escalation to the dynamic module.
- **False positives (high).** A legitimate app flagged → blocked/eroded trust and SOC alert fatigue.
  - *Mitigation:* balanced mode; corroborating-evidence requirement; explainable evidence log for analyst triage.
- **Over-reliance on GenAI verdicts (high).** Treating AI text as ground truth.
  - *Mitigation:* enforce that GenAI never solely determines the verdict; analyst sign-off for High/Critical.
- **Stale threat coverage (medium).** New families/techniques outpace rules/model.
  - *Mitigation:* RAG over MITRE ATT&CK + internal TI; retraining and YARA/rule refresh; re-verify ATT&CK IDs at implementation time.

### Delivery risks
- **Scope creep into a full dynamic sandbox (high).** Compute-heavy, fragile, and security-sensitive.
  - *Mitigation:* keep dynamic analysis modular/stretch; MVP is static + GenAI; system must function without it.
- **Hardware/model availability (medium).** GPU budget and shifting model landscape.
  - *Mitigation:* target single 24 GB GPU (32B Q4) with documented 14B/7B fallback; verify model licenses/benchmarks before committing.
- **Sample sourcing/licensing for ML (medium).** India-specific samples (FatBoyPanel/SOVA) and dataset access.
  - *Mitigation:* use Drebin/CICMalDroid 2020/AndroZoo + MalwareBazaar/VT; resolve licensing early (open question).
- **Governance/legal review gating dynamic go-live (high).** Live-malware handling requires sign-off.
  - *Mitigation:* sequence the security/compliance/legal review before Phase 2 go-live.

### Governance, security, compliance, and operational risks (non-negotiable for a bank)
- **Live-malware handling.** Risk of accidental execution or escape.
  - *Mitigation:* dynamic sandbox runs with **no egress / dedicated VLAN / gVisor-style isolation**, snapshot/teardown, and accidental-execution safeguards; containment failure is a hard failure.
- **Data residency / governance.** Sensitive bank APKs and stolen-data artifacts must stay internal.
  - *Mitigation:* on-prem only; **commercial LLM APIs optional and off by default**; strict artifact isolation and retention/chain-of-custody.
- **Access control & auditability.** Unauthorized access or untraceable decisions.
  - *Mitigation:* authenticated, role-based access; full audit logging of every indicator, score contribution, and decision.
- **Regulatory reporting.** RBI/CERT-In obligations.
  - *Mitigation:* defined chain-of-custody, retention, and reporting coordination; this is why the brief mandates local/private models and optional-only commercial APIs.

### Caveats / source-reliability notes
- Many malware-capability and statistics sources are vendor blogs/news (Bitsight, Zscaler ThreatLabz, ThreatFabric, Group-IB, McAfee, Cyble, Zimperium); capabilities are well-corroborated, but victim counts and loss figures are point-in-time and sometimes self-reported. The ~$2.5bn-2025 India figure traces to a BBC report (April 30, 2025; several outlets garbled this as "$25bn"); RBI's figures (₹520 crore / 13,516 cases for digital payment fraud in FY25) are more conservative and differently scoped.
- Some 2026-dated "best model" rankings and VRAM figures come from fast-moving community/blog sources; verify current model licenses/benchmarks before committing.
- ML F1 numbers (92–99%) are dataset-specific and optimistic; real-world cross-dataset/temporal performance is materially lower.
- MITRE ATT&CK Mobile confirmed at v19.1 (April 2026); one matrix page served a cached v18.1 permalink — IDs unchanged across v18→v19, but re-verify against attack.mitre.org at implementation time.
- This is a planning package, not a deployment clearance; live-malware handling must be reviewed by the bank's security/compliance/legal functions before any sandbox goes live.
