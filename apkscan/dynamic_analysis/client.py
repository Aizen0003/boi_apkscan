"""MobSF Dynamic Analyzer sandbox client.

Wraps the MobSF REST API (v1) to upload an APK, start dynamic analysis in the
MobSF-managed emulator, run Frida instrumentation, stop analysis, and collect
the report + PCAP artefacts.  The result is parsed into the canonical
``DynamicFeatures`` schema.

If the HTTP calls fail (server offline, timeout, auth), the client raises
``SandboxError`` so the caller (the factory / pipeline) can degrade gracefully.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from apkscan.dynamic_analysis.base import BaseSandbox, SandboxError
from apkscan.schema.features import DynamicFeatures, FeatureSet

logger = logging.getLogger("apkscan.dynamic_analysis.client")

# Default Frida scripts to attach — traces high-value Android API classes
_DEFAULT_FRIDA_HOOKS = [
    "android.telephony.SmsManager",
    "android.content.ContentResolver",
    "android.view.WindowManager",
    "android.media.MediaRecorder",
    "dalvik.system.DexClassLoader",
    "javax.crypto.Cipher",
]


class MobSFSandbox(BaseSandbox):
    """Concrete sandbox backend using MobSF Dynamic Analyzer REST API.

    Parameters
    ----------
    api_url:
        Base URL of the MobSF instance (e.g. ``http://localhost:8000``).
    api_key:
        MobSF REST API key.
    timeout:
        Maximum seconds to wait for each individual HTTP call.
    """

    def __init__(self, api_url: str, api_key: str, timeout: int = 60):
        self._url = api_url.rstrip("/")
        self._key = api_key
        self._timeout = timeout

    # ── public interface ────────────────────────────────────────────────
    def analyze(self, apk_path: Path, features: FeatureSet) -> DynamicFeatures:
        """Full MobSF dynamic analysis flow for one sample.

        1. Upload the APK (the static scan must have run already in MobSF).
        2. Start dynamic analysis in the emulator.
        3. Attach Frida hooks for high-value API classes.
        4. Stop analysis and collect the JSON report.
        5. Parse into ``DynamicFeatures``.
        """
        try:
            import requests  # lazy — keeps the import optional in CI
        except ImportError as exc:
            raise SandboxError(
                "The 'requests' library is required for the MobSF sandbox client"
            ) from exc

        file_hash = features.sample.sha256

        # 1. Upload (idempotent — MobSF deduplicates by hash)
        self._upload(requests, apk_path)

        # 2. Start dynamic analysis
        self._start(requests, file_hash)

        # 3. Instrument with Frida
        self._instrument(requests, file_hash)

        # 4. Stop and collect report
        report = self._stop_and_report(requests, file_hash)

        # 5. Parse
        return self._parse_report(report)

    # ── private helpers ─────────────────────────────────────────────────
    def _headers(self) -> Dict[str, str]:
        return {"Authorization": self._key}

    def _upload(self, requests_mod: Any, apk_path: Path) -> Dict[str, Any]:
        url = f"{self._url}/api/v1/upload"
        try:
            with open(apk_path, "rb") as fh:
                resp = requests_mod.post(
                    url,
                    files={"file": (apk_path.name, fh, "application/octet-stream")},
                    headers=self._headers(),
                    timeout=self._timeout,
                )
            resp.raise_for_status()
            data = resp.json()
            logger.info("MobSF upload OK: hash=%s", data.get("hash", "?"))
            return data
        except Exception as exc:
            raise SandboxError(f"MobSF upload failed: {exc}") from exc

    def _start(self, requests_mod: Any, file_hash: str) -> Dict[str, Any]:
        url = f"{self._url}/api/v1/dynamic/start_analysis"
        try:
            resp = requests_mod.post(
                url,
                data={"hash": file_hash},
                headers=self._headers(),
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            logger.info("MobSF dynamic start: %s", data.get("status", "?"))
            return data
        except Exception as exc:
            raise SandboxError(f"MobSF start_analysis failed: {exc}") from exc

    def _instrument(self, requests_mod: Any, file_hash: str) -> None:
        url = f"{self._url}/api/v1/frida/instrument"
        for cls in _DEFAULT_FRIDA_HOOKS:
            try:
                resp = requests_mod.post(
                    url,
                    data={"hash": file_hash, "default_hooks": cls},
                    headers=self._headers(),
                    timeout=self._timeout,
                )
                resp.raise_for_status()
            except Exception:
                logger.warning("Frida hook for %s failed; continuing", cls)

    def _stop_and_report(self, requests_mod: Any, file_hash: str) -> Dict[str, Any]:
        # Stop
        stop_url = f"{self._url}/api/v1/dynamic/stop_analysis"
        try:
            resp = requests_mod.post(
                stop_url,
                data={"hash": file_hash},
                headers=self._headers(),
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except Exception as exc:
            raise SandboxError(f"MobSF stop_analysis failed: {exc}") from exc

        # Fetch JSON report
        report_url = f"{self._url}/api/v1/dynamic/report_json"
        try:
            resp = requests_mod.post(
                report_url,
                data={"hash": file_hash},
                headers=self._headers(),
                timeout=self._timeout,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise SandboxError(f"MobSF report_json failed: {exc}") from exc

    # ── report parsing ──────────────────────────────────────────────────
    @staticmethod
    def _parse_report(report: Dict[str, Any]) -> DynamicFeatures:
        api_trace: List[str] = []
        for entry in report.get("api_monitor", []):
            api_trace.append(str(entry) if not isinstance(entry, str) else entry)
        for entry in report.get("frida_logs", []):
            api_trace.append(str(entry) if not isinstance(entry, str) else entry)

        network_endpoints: List[str] = []
        for domain_info in report.get("domains", {}):
            if isinstance(domain_info, str):
                network_endpoints.append(domain_info)
            elif isinstance(domain_info, dict):
                network_endpoints.append(domain_info.get("domain", str(domain_info)))

        urls = report.get("urls", [])
        for u in urls:
            ep = str(u) if not isinstance(u, str) else u
            if ep not in network_endpoints:
                network_endpoints.append(ep)

        sms_events: List[str] = []
        for sms in report.get("sms", []):
            sms_events.append(str(sms) if not isinstance(sms, str) else sms)

        file_ops: List[str] = []
        for fop in report.get("file_analysis", []):
            file_ops.append(str(fop) if not isinstance(fop, str) else fop)

        pcap_summary: Dict[str, object] = {}
        if report.get("pcap"):
            pcap_summary["pcap_file"] = report["pcap"]
        if report.get("tls_tests"):
            pcap_summary["tls_tests"] = report["tls_tests"]

        return DynamicFeatures(
            captured=True,
            api_trace=api_trace,
            network_endpoints=network_endpoints,
            pcap_summary=pcap_summary,
            sms_events=sms_events,
            file_ops=file_ops,
            notes="MobSF dynamic analysis completed.",
        )
