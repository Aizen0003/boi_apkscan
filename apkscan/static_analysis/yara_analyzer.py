"""YARA analyzer — matches internal banking-malware rules against the APK.

Rules are loaded from (in order) ``APKSCAN_YARA_RULES``, ``/opt/apkscan/yara_rules``,
or the repo's ``data/yara_rules``. Imported lazily; absent yara-python or rules
=> graceful gap.
"""

import os
from pathlib import Path
from typing import Optional

from apkscan.schema import YaraMatch
from apkscan.static_analysis.base import Analyzer, AnalyzerResult
from apkscan.static_analysis.errors import ToolUnavailable


def _rules_dir() -> Optional[Path]:
    candidates = [
        os.environ.get("APKSCAN_YARA_RULES"),
        "/opt/apkscan/yara_rules",
        str(Path(__file__).resolve().parents[2] / "data" / "yara_rules"),
    ]
    for cand in candidates:
        if cand and Path(cand).is_dir() and any(Path(cand).glob("*.yar*")):
            return Path(cand)
    return None


class YaraAnalyzer(Analyzer):
    name = "yara"

    def is_available(self) -> bool:
        try:
            import yara  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return _rules_dir() is not None

    def analyze(self, apk_path) -> AnalyzerResult:
        rules_dir = _rules_dir()
        if rules_dir is None:
            raise ToolUnavailable("no YARA rule files found")
        try:
            import yara
        except Exception as exc:  # noqa: BLE001
            raise ToolUnavailable(f"yara import failed: {exc}") from exc

        filepaths = {p.stem: str(p) for p in sorted(rules_dir.glob("*.yar*"))}
        try:
            self.version = getattr(yara, "YARA_VERSION", None)
            rules = yara.compile(filepaths=filepaths)
            matches = rules.match(str(apk_path), timeout=120)
        except Exception as exc:  # noqa: BLE001
            raise ToolUnavailable(f"yara compile/match failed: {exc}") from exc

        result = AnalyzerResult()
        for match in matches:
            matched_strings = []
            for s in getattr(match, "strings", []) or []:
                identifier = getattr(s, "identifier", None)
                if identifier:
                    matched_strings.append(str(identifier))
            result.yara_matches.append(
                YaraMatch(
                    rule=match.rule,
                    namespace=getattr(match, "namespace", None),
                    tags=list(getattr(match, "tags", []) or []),
                    meta=dict(getattr(match, "meta", {}) or {}),
                    matched_strings=sorted(set(matched_strings)),
                    source="internal",
                )
            )
        return result
