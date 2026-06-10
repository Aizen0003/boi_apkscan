"""MobSF analyzer — wraps the MobSF REST client as a pluggable analyzer."""

from apkscan.config import Settings, get_settings
from apkscan.static_analysis.base import Analyzer, AnalyzerResult
from apkscan.static_analysis.errors import MobSFUnavailable, ToolUnavailable
from apkscan.static_analysis.mobsf_client import MobSFClient


class MobSFAnalyzer(Analyzer):
    name = "mobsf"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def is_available(self) -> bool:
        return bool(self.settings.mobsf_enabled)

    def analyze(self, apk_path) -> AnalyzerResult:
        result = AnalyzerResult()
        try:
            with MobSFClient.from_settings(self.settings) as client:
                summary, gaps = client.analyze(apk_path)
        except MobSFUnavailable as exc:
            raise ToolUnavailable(str(exc)) from exc
        result.mobsf = summary
        result.gaps.extend(gaps)
        return result
