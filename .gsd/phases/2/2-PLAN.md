---
phase: 2
plan: 2
wave: 2
gap_closure: false
---

# Plan 2.2: Sandbox Pipeline Cascade & Anti-Evasion

## Objective
Wire the dynamic sandbox client into the core analysis pipeline, update the scoring fusion engine and report generators to reflect dynamic signal evidence, and implement checks to detect evasive/anti-emulation behavior.

## Context
- [SPEC.md](file:///d:/BOI_Hackathon/boi_apkscan/.gsd/SPEC.md)
- [pipeline.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/pipeline.py)
- [fusion.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/scoring/fusion.py)
- [builder.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/reporting/builder.py)

## Tasks

<task type="auto">
  <name>Auto-Trigger Sandbox in Pipeline</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\pipeline.py
    d:\BOI_Hackathon\boi_apkscan\apkscan\dynamic_analysis\factory.py
  </files>
  <action>
    1. Create `apkscan/dynamic_analysis/factory.py` with `get_sandbox_client(settings: Settings) -> BaseSandbox` to load either the simulator or client wrapper.
    2. Modify `run_analysis` in `apkscan/pipeline.py`:
       - After running deterministic static feature extraction, check if:
         `settings.dynamic_enabled` is True AND `features.escalation.escalate` is True.
       - If so, invoke the sandbox client:
         `features.dynamic = get_sandbox_client(settings).analyze(apk_path, features)`
       - If not, ensure `features.dynamic` is left as None or set to default with `captured = False`.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_sandbox_pipeline.py
  </verify>
  <done>
    Pipeline execution auto-triggers dynamic analysis on escalation-flagged samples when enabled.
  </done>
</task>

<task type="auto">
  <name>Scoring, Reporting & Anti-Evasion Handling</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\scoring\fusion.py
    d:\BOI_Hackathon\boi_apkscan\apkscan\reporting\builder.py
  </files>
  <action>
    1. Update `apkscan/scoring/fusion.py`:
       - If `features.dynamic` is present and `captured` is True:
         * Add dynamic behavior indicators as evidence items (under layer `EvidenceLayer.DYNAMIC`).
         * Boost the risk score if dynamic evidence confirms malicious activities (e.g. dynamic SMS intercept or code injection).
         * Add a `DYNAMIC` layer score to the fusion layers list.
         * Identify anti-emulation signature evasion: if `features.dynamic.api_trace` contains common emulator-check signatures or exhibits total dormancy (no API activities despite static indicators), set an evasion note and downgrade analysis confidence.
    2. Update `apkscan/reporting/builder.py` and PDF generators:
       - Append the "Dynamic Analysis Trace" section to reports if dynamic features were captured.
       - Display dynamic findings and network endpoints in reports.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_sandbox_pipeline.py
  </verify>
  <done>
    Dynamic findings are incorporated in scoring fusion, reports render sandbox captures, and evasive behaviors downgrade confidence.
  </done>
</task>

## Success Criteria
- [ ] Pipeline auto-triggers dynamic analysis on escalation flag.
- [ ] Scoring fusion correctly scales with dynamic features and reflects evasion.
- [ ] Generated reports contain captured dynamic traces and network endpoints.
- [ ] Unit and integration tests verify the end-to-end sandbox pipeline flow.
