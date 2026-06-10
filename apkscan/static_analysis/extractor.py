"""Static feature extraction orchestrator (T0.5 / AC2).

Runs each analyzer, merges partial results into the canonical ``FeatureSet``,
assigns stable string/API indices, mines IOCs, and records analysis gaps for any
analyzer that was unavailable or errored (graceful degradation). Escalation
(T0.6) is applied as the final step.
"""

import time
from pathlib import Path
from typing import List, Optional, Sequence

from apkscan.config import Settings, get_settings
from apkscan.schema import (
    AnalysisGap,
    AnalyzerRun,
    ApiReference,
    ExtractedString,
    FeatureSet,
    SampleMetadata,
)
from apkscan.static_analysis.base import Analyzer, AnalyzerResult
from apkscan.static_analysis.errors import ToolUnavailable
from apkscan.static_analysis.escalation import detect_escalation
from apkscan.static_analysis.iocs import build_iocset

_MAX_STRINGS = 5000


def extract_features(
    apk_path,
    sample: SampleMetadata,
    *,
    analyzers: Optional[Sequence[Analyzer]] = None,
    settings: Optional[Settings] = None,
) -> FeatureSet:
    settings = settings or get_settings()
    if analyzers is None:
        from apkscan.static_analysis.registry import default_analyzers

        analyzers = default_analyzers(settings)

    apk_path = Path(apk_path)
    results: List[AnalyzerResult] = []
    gaps: List[AnalysisGap] = []
    runs: List[AnalyzerRun] = []

    for analyzer in analyzers:
        start = time.perf_counter()
        try:
            if not analyzer.is_available():
                gaps.append(
                    AnalysisGap(
                        tool=analyzer.name,
                        reason="tool/library not available in this environment",
                        severity="warning",
                    )
                )
                runs.append(AnalyzerRun(name=analyzer.name, ok=False, error="unavailable"))
                continue
            result = analyzer.analyze(apk_path)
            results.append(result)
            runs.append(
                AnalyzerRun(
                    name=analyzer.name,
                    version=analyzer.version,
                    ok=True,
                    duration_ms=(time.perf_counter() - start) * 1000.0,
                )
            )
        except ToolUnavailable as exc:
            gaps.append(AnalysisGap(tool=analyzer.name, reason=str(exc), severity="warning"))
            runs.append(AnalyzerRun(name=analyzer.name, ok=False, error=str(exc)))
        except Exception as exc:  # noqa: BLE001 - never let one analyzer abort the run
            gaps.append(AnalysisGap(tool=analyzer.name, reason=f"analyzer error: {exc}", severity="error"))
            runs.append(AnalyzerRun(name=analyzer.name, ok=False, error=str(exc)))

    features = _merge(sample, results, gaps, runs)
    features.escalation = detect_escalation(features)
    return features


def _merge(
    sample: SampleMetadata,
    results: Sequence[AnalyzerResult],
    gaps: List[AnalysisGap],
    runs: List[AnalyzerRun],
) -> FeatureSet:
    features = FeatureSet(sample=sample, analysis_gaps=list(gaps), analyzer_runs=list(runs))

    # non-fatal gaps surfaced by analyzers themselves
    for result in results:
        features.analysis_gaps.extend(result.gaps)

    # sample-metadata enrichment (first analyzer to provide a field wins)
    for result in results:
        for key, value in result.sample.items():
            if value is not None and getattr(features.sample, key, None) in (None, "", 0):
                setattr(features.sample, key, value)

    # dedupe helpers keyed for stability
    seen_perms = set()
    for result in results:
        for perm in result.permissions:
            if perm.name not in seen_perms:
                seen_perms.add(perm.name)
                features.permissions.append(perm)

    seen_comp = set()
    for result in results:
        for comp in result.components:
            key = (comp.type, comp.name)
            if key not in seen_comp:
                seen_comp.add(key)
                features.components.append(comp)

    seen_cert = set()
    for result in results:
        for cert in result.certificates:
            key = cert.sha256 or cert.sha1 or cert.subject
            if key not in seen_cert:
                seen_cert.add(key)
                features.certificates.append(cert)

    seen_lib = set()
    for result in results:
        for lib in result.native_libs:
            if lib.name not in seen_lib:
                seen_lib.add(lib.name)
                features.native_libs.append(lib)

    seen_asset = set()
    for result in results:
        for asset in result.assets:
            if asset.name not in seen_asset:
                seen_asset.add(asset.name)
                features.assets.append(asset)

    seen_packer = set()
    for result in results:
        for packer in result.packers:
            if packer.name not in seen_packer:
                seen_packer.add(packer.name)
                features.packers.append(packer)

    seen_quark = set()
    for result in results:
        for q in result.quark_behaviors:
            if q.crime not in seen_quark:
                seen_quark.add(q.crime)
                features.quark_behaviors.append(q)

    seen_yara = set()
    for result in results:
        for y in result.yara_matches:
            if y.rule not in seen_yara:
                seen_yara.add(y.rule)
                features.yara_matches.append(y)

    for result in results:
        if result.mobsf is not None and features.mobsf is None:
            features.mobsf = result.mobsf

    # strings -> indexed ExtractedString (dedupe by value+location, capped)
    seen_str = set()
    for result in results:
        for value, location in result.raw_strings:
            key = (value, location)
            if key in seen_str or len(features.strings) >= _MAX_STRINGS:
                continue
            seen_str.add(key)
            features.strings.append(
                ExtractedString(index=len(features.strings), value=value, location=location)
            )

    # apis -> indexed ApiReference (dedupe by api)
    seen_api = set()
    for result in results:
        for api, caller in result.raw_apis:
            if api in seen_api:
                continue
            seen_api.add(api)
            features.apis.append(ApiReference(index=len(features.apis), api=api, caller=caller))

    # IOCs: mine all string values, seed from MobSF-provided firebase/domains
    seed = features.mobsf and _seed_iocs(features)
    features.iocs = build_iocset((s.value for s in features.strings), seed=seed)

    return features


def _seed_iocs(features: FeatureSet):
    from apkscan.schema import IOCSet

    mobsf = features.mobsf
    return IOCSet(
        domains=list(mobsf.malware_domains),
        firebase_urls=list(mobsf.firebase_urls),
    )
