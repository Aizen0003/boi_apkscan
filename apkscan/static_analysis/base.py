"""Analyzer contract.

Each analyzer contributes a partial ``AnalyzerResult`` that the extractor merges
into the canonical ``FeatureSet``. String/API indices are assigned centrally by
the extractor so artifact ids are stable and globally unique.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from apkscan.schema import (
    AnalysisGap,
    Asset,
    Certificate,
    Component,
    MobSFSummary,
    NativeLib,
    PackerDetection,
    Permission,
    QuarkBehavior,
    YaraMatch,
)


@dataclass
class AnalyzerResult:
    # partial sample-metadata updates (package_name, version_name, sdk, main_activity ...)
    sample: dict = field(default_factory=dict)
    permissions: List[Permission] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    certificates: List[Certificate] = field(default_factory=list)
    raw_apis: List[Tuple[str, Optional[str]]] = field(default_factory=list)  # (api, caller)
    raw_strings: List[Tuple[str, Optional[str]]] = field(default_factory=list)  # (value, location)
    native_libs: List[NativeLib] = field(default_factory=list)
    assets: List[Asset] = field(default_factory=list)
    packers: List[PackerDetection] = field(default_factory=list)
    quark_behaviors: List[QuarkBehavior] = field(default_factory=list)
    yara_matches: List[YaraMatch] = field(default_factory=list)
    mobsf: Optional[MobSFSummary] = None
    # non-fatal gaps the analyzer wants recorded (e.g. under-patched MobSF)
    gaps: List[AnalysisGap] = field(default_factory=list)


class Analyzer:
    """Base analyzer. Subclasses set ``name`` and implement ``analyze``.

    ``is_available`` should cheaply check whether the underlying tool/library can
    run; when it returns False the extractor records an ``AnalysisGap`` instead of
    failing (graceful degradation).
    """

    name: str = "analyzer"
    version: Optional[str] = None

    def is_available(self) -> bool:  # pragma: no cover - trivial default
        return True

    def analyze(self, apk_path) -> AnalyzerResult:  # pragma: no cover - interface
        raise NotImplementedError
