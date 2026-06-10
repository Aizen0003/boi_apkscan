"""Quark-Engine analyzer — five-stage 'order theory of crime' behavior scoring.

Uses Quark's Report API. Requires the quark-rules dataset (fetched by
``freshquark`` into ~/.quark-engine by default, or pointed to via
``APKSCAN_QUARK_RULES``). The Dalvik-bytecode loader is obfuscation-resistant.
"""

import os
from pathlib import Path
from typing import Optional

from apkscan.schema import QuarkBehavior
from apkscan.static_analysis.base import Analyzer, AnalyzerResult
from apkscan.static_analysis.errors import ToolUnavailable


def _rules_dir() -> Optional[Path]:
    candidates = [
        os.environ.get("APKSCAN_QUARK_RULES"),
        os.path.expanduser("~/.quark-engine/quark-rules"),
        "/opt/apkscan/quark-rules",
    ]
    for cand in candidates:
        if cand and Path(cand).is_dir():
            return Path(cand)
    return None


def _confidence_to_stage(confidence_percent: float) -> int:
    # Quark confidence comes in 20% increments mapping to the five stages.
    return max(0, min(5, round(confidence_percent / 20.0)))


class QuarkAnalyzer(Analyzer):
    name = "quark"

    def is_available(self) -> bool:
        try:
            import quark  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return _rules_dir() is not None

    def analyze(self, apk_path) -> AnalyzerResult:
        rules = _rules_dir()
        if rules is None:
            raise ToolUnavailable("quark-rules dataset not found (run freshquark)")
        try:
            from quark.report import Report
        except Exception as exc:  # noqa: BLE001
            raise ToolUnavailable(f"quark import failed: {exc}") from exc

        try:
            report = Report()
            report.analysis(str(apk_path), str(rules))
            data = report.get_report("json")
        except Exception as exc:  # noqa: BLE001
            raise ToolUnavailable(f"quark analysis failed: {exc}") from exc

        result = AnalyzerResult()
        for crime in data.get("crimes", []):
            confidence_raw = str(crime.get("confidence", "0%")).replace("%", "").strip()
            try:
                confidence_percent = float(confidence_raw)
            except ValueError:
                confidence_percent = 0.0
            apis = []
            for api in crime.get("native_api", []) or []:
                if isinstance(api, dict):
                    apis.append(f"{api.get('class', '')}->{api.get('method', '')}")
                else:
                    apis.append(str(api))
            result.quark_behaviors.append(
                QuarkBehavior(
                    crime=str(crime.get("crime", "")),
                    confidence_stage=_confidence_to_stage(confidence_percent),
                    confidence_percent=confidence_percent,
                    weight=_safe_float(crime.get("weight")),
                    score=_safe_float(crime.get("score")),
                    apis=apis,
                )
            )
        return result


def _safe_float(value) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
