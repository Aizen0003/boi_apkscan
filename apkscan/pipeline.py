"""Analysis pipeline orchestrator (T0.20 spine).

Runs the full flow for one sample and structurally enforces the core decision
rule: the verdict comes from the deterministic rule layer (and Phase-1 ML); the
GenAI interpretation is produced and attached but passed to fusion as
explanatory-only. Used by both the Celery worker and the CLI.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from apkscan.config import Settings, get_settings
from apkscan.genai.interpreter import interpret
from apkscan.reporting.builder import build_report_document
from apkscan.schema import FeatureSet, GenAIInterpretation, ReportDocument, SampleMetadata, ScoreResult
from apkscan.scoring.fusion import fuse
from apkscan.scoring.rule_engine import score_rules
from apkscan.static_analysis.base import Analyzer
from apkscan.static_analysis.decompile import decompile_apk
from apkscan.static_analysis.extractor import extract_features


@dataclass
class AnalysisOutcome:
    features: FeatureSet
    score: ScoreResult
    genai: GenAIInterpretation
    report: ReportDocument


def run_analysis(
    apk_path,
    sample: SampleMetadata,
    *,
    settings: Optional[Settings] = None,
    analyzers: Optional[Sequence[Analyzer]] = None,
    llm_client=None,
    code: Optional[str] = None,
    report_id: Optional[str] = None,
) -> AnalysisOutcome:
    settings = settings or get_settings()
    apk_path = Path(apk_path)

    # 1) deterministic static feature extraction (+ escalation flag)
    features = extract_features(apk_path, sample, analyzers=analyzers, settings=settings)

    # 2) deterministic rule scoring (the primary, decisive layer)
    rule_result = score_rules(features)

    # 3) GenAI interpretation (explanatory only). Decompile for code chunks if enabled.
    if code is None:
        code = decompile_apk(apk_path, settings) if settings.llm_enabled else ""
    genai = interpret(features, code=code, settings=settings, client=llm_client)

    # 4) fusion — rule layer decides, GenAI explains (weight 0)
    score = fuse(features, rule_result, genai, settings=settings)

    # 5) report document
    report = build_report_document(features, score, genai, report_id=report_id)

    return AnalysisOutcome(features=features, score=score, genai=genai, report=report)
