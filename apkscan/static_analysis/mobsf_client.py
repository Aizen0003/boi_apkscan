"""MobSF REST client — baseline scanner + REST backbone (T0.2).

Wraps the four documented endpoints (`/api/v1/upload`, `/scan`, `/report_json`,
`/download_pdf`) and folds the result into the canonical ``MobSFSummary``. MobSF
is supplementary: Androguard is the authoritative parser for canonical features.

Guardrails:
  * Patch-level floor enforced (>= 4.4.6, IMPLEMENTATION_RULES). An older server
    is recorded as an ``error``-severity ``AnalysisGap`` rather than trusted
    silently.
  * Transport failures raise ``MobSFUnavailable`` so the orchestrator can record
    a gap and continue (graceful degradation).
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

from apkscan.schema import AnalysisGap, MobSFSummary
from apkscan.static_analysis.errors import MobSFUnavailable


def _version_tuple(version: Optional[str]) -> Tuple[int, ...]:
    """Parse a MobSF version string ('v4.4.6', '4.4.6 Beta') -> (4, 4, 6)."""

    if not version:
        return ()
    match = re.search(r"(\d+(?:\.\d+)+)", str(version))
    if not match:
        return ()
    return tuple(int(p) for p in match.group(1).split("."))


class MobSFClient:
    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        timeout: float = 120.0,
        min_version: str = "4.4.6",
        transport: Optional[httpx.BaseTransport] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.min_version = min_version
        headers = {"Authorization": api_key} if api_key else {}
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=timeout,
                transport=transport,
                headers=headers,
            )
            self._owns_client = True

    # -- lifecycle --
    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "MobSFClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @classmethod
    def from_settings(cls, settings) -> "MobSFClient":
        return cls(
            base_url=settings.mobsf_url,
            api_key=settings.mobsf_api_key,
            timeout=float(getattr(settings, "llm_timeout_seconds", 120)),
            min_version=settings.mobsf_min_version,
        )

    # -- low-level --
    def _post(self, path: str, **kwargs) -> httpx.Response:
        try:
            resp = self._client.post(path, **kwargs)
        except httpx.HTTPError as exc:  # connect/read/timeout
            raise MobSFUnavailable(f"MobSF request to {path} failed: {exc}") from exc
        resp.raise_for_status()
        return resp

    # -- endpoints --
    def upload(self, file_path) -> Dict:
        path = Path(file_path)
        with path.open("rb") as fh:
            files = {"file": (path.name, fh, "application/vnd.android.package-archive")}
            return self._post("/api/v1/upload", files=files).json()

    def scan(self, scan_hash: str) -> Dict:
        return self._post("/api/v1/scan", data={"hash": scan_hash}).json()

    def report_json(self, scan_hash: str) -> Dict:
        return self._post("/api/v1/report_json", data={"hash": scan_hash}).json()

    def download_pdf(self, scan_hash: str) -> bytes:
        return self._post("/api/v1/download_pdf", data={"hash": scan_hash}).content

    # -- high-level --
    def analyze(self, file_path) -> Tuple[MobSFSummary, List[AnalysisGap]]:
        """Run upload -> scan -> report_json and summarise.

        Returns the summary plus any gaps (e.g. an under-patched server). Raises
        ``MobSFUnavailable`` on transport errors so the caller records a gap.
        """

        gaps: List[AnalysisGap] = []
        uploaded = self.upload(file_path)
        scan_hash = uploaded.get("hash")
        if not scan_hash:
            raise MobSFUnavailable("MobSF upload returned no hash")
        self.scan(scan_hash)
        report = self.report_json(scan_hash)
        gaps.extend(self._check_version(report))
        return self.summarize_report(report), gaps

    def _check_version(self, report: Dict) -> List[AnalysisGap]:
        version = report.get("version") or report.get("mobsf_version")
        actual = _version_tuple(version)
        floor = _version_tuple(self.min_version)
        if actual and floor and actual < floor:
            return [
                AnalysisGap(
                    tool="mobsf",
                    reason=(
                        f"MobSF {version} is below the required patched minimum "
                        f"{self.min_version} (CVE-fixed SQLite viewer). Update the server."
                    ),
                    severity="error",
                )
            ]
        return []

    @staticmethod
    def summarize_report(report: Dict) -> MobSFSummary:
        """Defensively map a MobSF report into the canonical summary.

        MobSF's JSON layout has shifted across versions; we read several known
        key locations and tolerate absence.
        """

        appsec = report.get("appsec") or {}

        def _count(key: str) -> int:
            value = appsec.get(key)
            if isinstance(value, list):
                return len(value)
            if isinstance(value, int):
                return value
            return 0

        trackers = report.get("trackers") or {}
        trackers_detected = trackers.get("detected_trackers")
        if isinstance(trackers_detected, list):
            trackers_count = len(trackers_detected)
        elif isinstance(trackers_detected, int):
            trackers_count = trackers_detected
        else:
            trackers_count = 0

        malware_domains = []
        for host, info in (report.get("domains") or {}).items():
            if isinstance(info, dict) and info.get("bad") in ("yes", True):
                malware_domains.append(host)

        return MobSFSummary(
            mobsf_version=report.get("version") or report.get("mobsf_version"),
            security_score=appsec.get("security_score", report.get("security_score")),
            grade=appsec.get("security_grade") or report.get("security_grade"),
            high=_count("high"),
            medium=_count("warning") or _count("medium"),
            info=_count("info"),
            secure=_count("secure"),
            hotspot=_count("hotspot"),
            trackers=trackers_count,
            malware_domains=malware_domains,
            firebase_urls=report.get("firebase_urls", []) or [],
            findings={"appsec_keys": list(appsec.keys())},
        )
