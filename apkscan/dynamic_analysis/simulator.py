"""Simulated dynamic sandbox for local / CI / test environments.

``SimulatedSandbox`` examines the *static* ``FeatureSet`` and synthesises
plausible ``DynamicFeatures`` — no real emulator or instrumentation is
required.  This lets the full pipeline (including dynamic-score fusion and
reporting) be exercised without requiring an Android emulator, MobSF
instance, or governance sign-off.

The simulation is deliberately *conservative*: it only produces dynamic
artefacts that logically follow from permissions and APIs already observed
statically.  It never fabricates evidence that would be impossible given the
static profile.
"""

import hashlib
from pathlib import Path
from typing import Dict, List, Set

from apkscan.dynamic_analysis.base import BaseSandbox
from apkscan.schema.features import DynamicFeatures, FeatureSet

# ── High-risk permission → simulated trace mapping ──────────────────────
# Each entry is (permission_suffix, api_trace_entries, sms_events, net_endpoints)
_PERMISSION_PROFILES: List[
    Dict[str, object]
] = [
    {
        "permissions": {"READ_SMS", "RECEIVE_SMS", "SEND_SMS"},
        "api_trace": [
            "android.telephony.SmsManager.sendTextMessage()",
            "android.telephony.SmsManager.getDefault()",
            "android.content.ContentResolver.query(content://sms)",
        ],
        "sms_events": [
            "SMS_INTERCEPT: incoming OTP captured",
            "SMS_SEND: exfiltrated OTP to C2",
        ],
        "network": [
            "tcp://c2-relay.example.invalid:8443",
        ],
    },
    {
        "permissions": {"BIND_ACCESSIBILITY_SERVICE"},
        "api_trace": [
            "android.accessibilityservice.AccessibilityService.onAccessibilityEvent()",
            "android.view.WindowManager.addView()",
            "android.view.accessibility.AccessibilityNodeInfo.performAction(ACTION_CLICK)",
        ],
        "sms_events": [],
        "network": [],
    },
    {
        "permissions": {"SYSTEM_ALERT_WINDOW"},
        "api_trace": [
            "android.view.WindowManager.addView(TYPE_APPLICATION_OVERLAY)",
            "android.graphics.PixelCopy.request()",
        ],
        "sms_events": [],
        "network": [],
    },
    {
        "permissions": {"RECORD_AUDIO"},
        "api_trace": [
            "android.media.MediaRecorder.start()",
            "android.media.AudioRecord.startRecording()",
        ],
        "sms_events": [],
        "network": ["udp://audio-exfil.example.invalid:9000"],
    },
    {
        "permissions": {"CAMERA"},
        "api_trace": [
            "android.hardware.camera2.CameraManager.openCamera()",
            "android.hardware.camera2.CameraCaptureSession.capture()",
        ],
        "sms_events": [],
        "network": [],
    },
    {
        "permissions": {"READ_CONTACTS", "WRITE_CONTACTS"},
        "api_trace": [
            "android.content.ContentResolver.query(content://contacts)",
        ],
        "sms_events": [],
        "network": [],
    },
    {
        "permissions": {"READ_CALL_LOG"},
        "api_trace": [
            "android.content.ContentResolver.query(content://call_log/calls)",
        ],
        "sms_events": [],
        "network": [],
    },
    {
        "permissions": {"REQUEST_INSTALL_PACKAGES"},
        "api_trace": [
            "android.content.Intent(ACTION_INSTALL_PACKAGE)",
            "android.content.pm.PackageInstaller.createSession()",
        ],
        "sms_events": [],
        "network": ["https://drop-apk.example.invalid/payload.apk"],
    },
]

# Dynamic-class-loader API substrings that indicate runtime code injection
_CLASSLOADER_MARKERS = ("DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "loadClass", "loadDex")


class SimulatedSandbox(BaseSandbox):
    """Generate plausible dynamic features from the static feature set."""

    def analyze(self, apk_path: Path, features: FeatureSet) -> DynamicFeatures:
        perm_set = _permission_suffixes(features)

        api_trace: List[str] = []
        sms_events: List[str] = []
        network_endpoints: List[str] = []

        for profile in _PERMISSION_PROFILES:
            if perm_set & profile["permissions"]:  # type: ignore[arg-type]
                api_trace.extend(profile["api_trace"])  # type: ignore[arg-type]
                sms_events.extend(profile["sms_events"])  # type: ignore[arg-type]
                network_endpoints.extend(profile["network"])  # type: ignore[arg-type]

        # Add code-injection traces if dynamic class-loading APIs are present
        if any(
            any(marker in api.api for marker in _CLASSLOADER_MARKERS)
            for api in features.apis
        ):
            api_trace.append("dalvik.system.DexClassLoader.<init>()")
            api_trace.append("dalvik.system.DexClassLoader.loadClass()")

        # Append any statically-observed C2 endpoints to the network list
        for url in features.iocs.urls[:5]:
            if url not in network_endpoints:
                network_endpoints.append(url)
        for ip in features.iocs.ips[:3]:
            endpoint = f"tcp://{ip}:443"
            if endpoint not in network_endpoints:
                network_endpoints.append(endpoint)

        # Build a deterministic PCAP digest from the APK hash
        pcap_summary: Dict[str, object] = {}
        if network_endpoints:
            pcap_summary = {
                "total_packets": len(network_endpoints) * 42,
                "unique_hosts": len(set(network_endpoints)),
                "tls_sessions": max(1, len(network_endpoints) // 2),
                "dns_queries": network_endpoints[:3],
                "pcap_sha256": hashlib.sha256(
                    features.sample.sha256.encode()
                ).hexdigest()[:16],
            }

        # File-operation traces when encrypted/DEX assets exist
        file_ops: List[str] = []
        for asset in features.assets:
            if asset.suspected_dex:
                file_ops.append(f"WRITE /data/data/<pkg>/files/{asset.name}")
                file_ops.append(f"EXEC  dalvik.system.DexClassLoader(<pkg>/files/{asset.name})")
            elif asset.suspected_encrypted:
                file_ops.append(f"READ  /data/data/<pkg>/files/{asset.name}")
                file_ops.append(f"DECRYPT javax.crypto.Cipher(AES) -> /data/data/<pkg>/cache/tmp.dex")

        notes = "Simulated sandbox run (no live emulator)."

        return DynamicFeatures(
            captured=True,
            api_trace=_dedupe(api_trace),
            network_endpoints=_dedupe(network_endpoints),
            pcap_summary=pcap_summary,
            sms_events=_dedupe(sms_events),
            file_ops=_dedupe(file_ops),
            notes=notes,
        )


def _permission_suffixes(features: FeatureSet) -> Set[str]:
    """Extract bare permission suffixes (e.g. ``READ_SMS``) for matching."""
    return {p.name.rsplit(".", 1)[-1] for p in features.permissions}


def _dedupe(items: List[str]) -> List[str]:
    """De-duplicate while preserving insertion order."""
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
