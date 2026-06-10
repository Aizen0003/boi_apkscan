# TEST_PLAN.md

## Test & Validation Plan — GenAI-Powered Android Banking-Malware Analysis & Risk-Scoring System

> Converts the report's evaluation, validation, and benchmark sections into a verification plan. Acceptance criteria referenced here are defined in `PRD.md`; tasks in `TASKS.md`.

### What must be verified
- **Ingestion & pipeline:** upload (UI+API), hashing, dedupe, async queueing with priority, job-status tracking.
- **Static analysis & features:** correct parsing of manifest/DEX/resources/certificates/assets/native libs; canonical JSON feature output; packer/obfuscator detection; escalation-flag correctness.
- **ATT&CK mapping:** behaviors resolve to the correct ATT&CK for Mobile v19.1 technique IDs.
- **Scoring:** deterministic rule layer is reproducible; hybrid fusion produces score + verdict band + confidence + complete evidence log; "GenAI explains, deterministic+ML decides" is enforced.
- **GenAI output:** grounded (cited artifacts exist), ATT&CK-correct, untrusted-string isolation works, no context truncation.
- **Reporting:** PDF + JSON contain verdict, confidence, score, evidence, ATT&CK mapping, IOCs, recommendations.
- **Governance controls:** on-prem only (no commercial API egress), audit logging, access control, analyst sign-off for High/Critical, retention/chain-of-custody.
- **ML (Phase 1):** precision/recall/F1 and explicitly FPR/FNR; SHAP explanations; temporal validation; drift trigger; operating-mode policy.
- **Dynamic (Phase 2):** isolation/no-egress, behavior capture, auto-trigger, anti-emulation handling.

### Evaluation metrics
- Report **precision, recall, F1** (F1 good for imbalanced data), plus **FPR and FNR explicitly** (critical in security).
- **Banking cost asymmetry:** a false negative = a fraudulent APK cleared → direct customer financial loss, fraud, regulatory exposure. A false positive = a legitimate app flagged → blocked/eroded trust and SOC alert fatigue. Both are costly; the operating point is a deliberate, exposed policy (high-recall vs. balanced mode).
- **Temporal validation:** train-on-past/test-on-future; record metric deltas vs. random split.
- **Concept drift:** monitor F1 over time (literature: F1 ~0.99→0.76 within six months); plan periodic retraining.

### Validating GenAI output
- Ground every claim in deterministic evidence — cited functions/addresses/strings must actually exist in the extracted features.
- Require the LLM to cite the artifact for each statement; withhold/flag claims whose artifact is absent.
- Use multi-agent/verifier cross-checks if grounding failures exceed the agreed rate (per SentinelLABS' "Active Rejection Mandate").
- Require human analyst sign-off for High/Critical verdicts.
- Benchmark GenAI explanations against labeled samples.

### Unit validation
- Permission-weight and dangerous-combination scoring returns expected values for crafted manifests.
- Quark five-stage behavior scoring and YARA matches return expected hits on known inputs.
- ATT&CK mapping table returns correct technique IDs per behavior.
- Feature serializer emits the canonical schema for varied APK inputs.
- Prompt builder enforces untrusted-string isolation (no string is ever placed in an instruction position).
- Report serializer produces valid PDF and JSON.

### Integration validation
- MobSF REST scan → feature extraction → feature store: a sample flows through and produces canonical features.
- Static features + GenAI explanation + rule scores → fusion → score/verdict/confidence/evidence log.
- Escalation flag from static layer correctly triggers the dynamic module (Phase 2).
- ML probability + SHAP explanation integrate into fusion and appear in the evidence log (Phase 1).
- Report generator consumes fused result and emits complete PDF/JSON; findings indexed; audit log written.

### End-to-end validation
- **Core E2E (AC8 + AC1–AC7, AC9):** upload an APK on the single-host Docker stack with local models and no commercial API → receive a complete, evidence-grounded report with verdict, confidence, ATT&CK mapping, IOCs, and recommendations; High/Critical requires sign-off; audit log populated.
- Run against a labeled benign/malicious set (incl. India-specific families) and compute precision/recall/F1/FPR/FNR.
- Verify operating-mode switch changes the decision boundary as specified (Phase 1).

### Edge cases
- Packed/obfuscated samples (Virbox VM, `$JADXBLOCK`/ZIP tricks) — must set escalation flag, not silently under-report.
- Encrypted payloads / asset-hidden DEX / dynamic DEX loading (e.g., ClayRat AES/CBC; Anatsa DES-keyed strings + static-key DEX in assets) — static layer must flag; verdict must reflect uncertainty.
- Anti-emulation / device-model checks causing dormant behavior in the sandbox (Phase 2) — handle or explicitly mark inconclusive.
- Legitimate apps with "dangerous" permissions (known MobSF false-positive class) — must not be auto-flagged Malicious without corroborating evidence.
- Decompiled code exceeding LLM context — must chunk per-function, never truncate silently.
- Duplicate uploads — dedupe by hash.

### Failure scenarios
- **Prompt injection:** APK embeds "Ignore all previous instructions…" — model behavior must not change; string treated as data only.
- **GenAI hallucination/false confidence:** cited functions wrong, "capabilities" that are dead standard-library code, mangled C2 endpoint — grounding/citation checks must catch; GenAI must never solely set a High/Critical verdict.
- **Context truncation:** local Ollama returning invalid/truncated output — detect and re-chunk or escalate model tier.
- **Concept drift:** model F1 decline over time — drift monitor must fire the retraining trigger.
- **Dynamic sandbox containment failure:** any egress or accidental execution outside isolation is a hard failure (must be impossible by design; see `RISKS.md`).

### Benchmarks / thresholds that change the plan
- Static **FNR > agreed bank threshold (e.g., >2–3%)** on labeled holdout → prioritize the dynamic module sooner.
- GenAI **factual-grounding failure > agreed rate** (cited artifacts don't exist) → adopt the multi-agent verifier/consensus pattern before relying on AI text.
- **LLM context truncation degrading summaries** → per-function chunking and/or larger-context model tier.
- **Drift monitor F1 decline** → retrain and refresh YARA/rules.

### Definition of done
- **MVP (Phase 0) done when:** AC1–AC9 pass; full upload→analyze→report E2E runs on a single-host stack with local models and no commercial-API egress; rule-layer scores are deterministic and reproducible; every verdict has a complete evidence log and ATT&CK mapping; GenAI claims are artifact-grounded and never solely determine High/Critical; High/Critical require analyst sign-off; audit logging and access control active.
- **Phase 1 done when:** ML layer integrated into fusion with SHAP explanations; precision/recall/F1/FPR/FNR reported on holdout and on a temporal split; drift monitor + retraining trigger working; high-recall and balanced operating modes selectable and measured.
- **Phase 2 done when:** dynamic sandbox runs in a verified no-egress isolated environment with snapshot/teardown and accidental-execution safeguards; behaviors (API trace, PCAP, SMS/file) captured; auto-trigger on escalation flag working; results feed scoring/reporting; anti-emulation cases handled or explicitly flagged; security/compliance/legal review completed before go-live.
