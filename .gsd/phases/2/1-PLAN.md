---
phase: 2
plan: 1
wave: 1
gap_closure: false
---

# Plan 2.1: Dynamic Sandbox Client & Simulation Layer

## Objective
Establish the configuration, client interfaces, and simulated sandbox runtime provider for the Phase 2 Isolated Dynamic Sandbox. This builds a clean interface that can communicate with a real MobSF sandbox backend or gracefully run in offline simulated mode for local tests.

## Context
- [SPEC.md](file:///d:/BOI_Hackathon/boi_apkscan/.gsd/SPEC.md)
- [config.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/config.py)
- [features.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/schema/features.py)

## Tasks

<task type="auto">
  <name>Configure Sandbox Settings & Simulator</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\config.py
    d:\BOI_Hackathon\boi_apkscan\apkscan\dynamic_analysis\base.py
    d:\BOI_Hackathon\boi_apkscan\apkscan\dynamic_analysis\simulator.py
  </files>
  <action>
    1. Verify/extend `Settings` in `config.py` with:
       - `dynamic_enabled` (boolean, defaults to False)
       - `sandbox_backend` (literal "mobsf" or "simulator", defaults to "simulator")
       - `sandbox_timeout` (integer, defaults to 60)
    2. Create `apkscan/dynamic_analysis/base.py` with an abstract/base interface:
       - `BaseSandbox.analyze(apk_path: Path, feature_set: FeatureSet) -> DynamicFeatures`
    3. Create `apkscan/dynamic_analysis/simulator.py` with `SimulatedSandbox`:
       - If the static features have high-risk permissions (e.g. `READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`), simulate corresponding dynamic actions:
         * Populate `api_trace` with typical SMS/window manager monitoring calls.
         * Populate `sms_events` and `network_endpoints` with C2 telemetry references.
         * Mark `captured = True`.
       - If no dangerous permissions exist, return empty `DynamicFeatures` with `captured = True`.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_sandbox_client.py
  </verify>
  <done>
    Settings are updated and SimulatedSandbox returns dynamic features matching the mock profiles.
  </done>
</task>

<task type="auto">
  <name>Implement MobSF Sandbox API Client</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\dynamic_analysis\client.py
    d:\BOI_Hackathon\boi_apkscan\apkscan\dynamic_analysis\__init__.py
  </files>
  <action>
    1. Create `apkscan/dynamic_analysis/client.py` with `MobSFSandbox` implementing the sandbox client:
       - Perform HTTP calls to MobSF Dynamic Analyzer API keys/endpoints:
         * Upload and start: `POST /api/v1/dynamic/start_analysis`
         * Run Frida scripts: `POST /api/v1/dynamic/frida/instrument` (e.g., tracing common API classes)
         * Stop and get JSON report: `POST /api/v1/dynamic/stop_analysis`
         * Download PCAP data: `POST /api/v1/dynamic/get_pcap` or `POST /api/v1/dynamic/stop_analysis`
       - Parse the resulting report into a `DynamicFeatures` schema object.
       - Implement fallback/degradation: if HTTP calls fail, raise an error or fallback to the simulator based on `sandbox_backend`.
    2. Register the modules in `apkscan/dynamic_analysis/__init__.py`.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_sandbox_client.py
  </verify>
  <done>
    The MobSFSandbox API calls are fully coded, mocked, and tested.
  </done>
</task>

## Success Criteria
- [ ] Sandbox settings are validated in config.
- [ ] Abstract base client, simulated runner, and real MobSF dynamic analyzer client are fully implemented.
- [ ] Unit tests cover both simulator behavior and mocked HTTP API calls.
