# Phase 2 Research: Isolated Dynamic Sandbox Integration

This research covers the design, security containment, and API interfaces required to integrate the modular dynamic analysis sandbox into the APKScan pipeline.

---

## 1. Safety Containment & Network Isolation (T2.1)

Dynamic analysis involves running live malware samples. To protect the host and the internal network, strict isolation is required.

### Containment Design
* **Network Isolation**: The dynamic sandbox container/VM runs on a dedicated, non-routing Docker network (no egress gateway). DNS resolution is disabled, and all external internet access is blocked.
* **gVisor Runtime**: Docker containers hosting emulators or Frida agents should run under the `runsc` (gVisor) runtime, which intercept system calls to prevent sandbox escapes.
* **Teardown & Rollback**: Each run must start from a clean snapshot of the Android image. After execution, the VM/container is completely torn down to guarantee a clean slate for the next sample.

---

## 2. Frida/MobSF API Integration (T2.2)

MobSF has a built-in Dynamic Analyzer that controls Frida and triggers activities.

### Key API Endpoints
* **Start Dynamic Analysis**: `POST /api/v1/dynamic/start_analysis`
  * Initiates the emulator and installs the APK.
* **Frida Tracing**: `POST /api/v1/dynamic/frida/instrument`
  * Instruments APIs (e.g. SMS, crypto, filesystem, overlays).
* **Network Traffic**: Mitmproxy captures traffic and outputs a PCAP.
* **Stop & Get Report**: `POST /api/v1/dynamic/stop_analysis`
  * Collects logs, API traces, and file modifications.

### Local/Test Simulation
To support local test suites and offline CLI execution, we will build a `SimulatedSandbox` provider. It will parse the APK's static signature/permissions (e.g. accessibility and SMS) and synthesize simulated behaviors (e.g. overlay injections, SMS interceptions) to verify the downstream scoring/reporting flows without requiring a live Android emulator.

---

## 3. Auto-Trigger & Pipeline Cascade (T2.3 & T2.4)

When a sample is analyzed:
1. Static analysis runs. If the static result has `escalation.escalate = True` AND `settings.dynamic_enabled = True`, the pipeline invokes the dynamic sandbox.
2. The dynamic features are captured and populated in the `dynamic` section of the canonical `FeatureSet`.
3. The scoring fusion engine incorporates dynamic behaviors:
   * Network endpoints and SMS interceptions add raw scoring weight.
   * Dynamic traces are mapped to ATT&CK tactics (e.g., T1636 / T1417).
   * A `DYNAMIC` layer score is added to the report.

---

## 4. Anti-Emulation & Evasion (T2.5)

Malware often checks Build/Hardware parameters (e.g., `Build.FINGERPRINT`, `Build.PRODUCT`, `Build.MANUFACTURER`) or looks for QEMU/Genymotion signatures.

### Evasion Indicators
* **Dormancy**: The app exits immediately or stays idle without calling any sensitive APIs.
* **Emulator Checks**: Code queries system properties commonly associated with emulators.
* **Resolution**: When evasion is suspected, the sandbox sets `notes = "Potential anti-emulation evasion detected; runtime behavior dormant."` and flags the run as inconclusive.
