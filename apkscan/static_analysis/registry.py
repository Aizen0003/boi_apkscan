"""Default analyzer registry.

Order matters: Androguard runs first (authoritative sample metadata + features),
then APKiD, Quark, YARA, and finally MobSF (network call). Any analyzer that is
unavailable degrades to an ``AnalysisGap`` in the extractor.
"""

from typing import List, Optional

from apkscan.config import Settings, get_settings
from apkscan.static_analysis.androguard_analyzer import AndroguardAnalyzer
from apkscan.static_analysis.apkid_analyzer import ApkidAnalyzer
from apkscan.static_analysis.base import Analyzer
from apkscan.static_analysis.mobsf_analyzer import MobSFAnalyzer
from apkscan.static_analysis.quark_analyzer import QuarkAnalyzer
from apkscan.static_analysis.yara_analyzer import YaraAnalyzer


def default_analyzers(settings: Optional[Settings] = None) -> List[Analyzer]:
    settings = settings or get_settings()
    analyzers: List[Analyzer] = [
        AndroguardAnalyzer(),
        ApkidAnalyzer(),
        QuarkAnalyzer(),
        YaraAnalyzer(),
    ]
    if settings.mobsf_enabled:
        analyzers.append(MobSFAnalyzer(settings))
    return analyzers
