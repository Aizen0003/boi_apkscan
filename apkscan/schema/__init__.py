"""Canonical data contracts shared across every APKScan component.

This package is THE central contract (IMPLEMENTATION_RULES.md): static workers,
the GenAI service, the scoring engine, the report generator, and the future
dynamic module all exchange data through these models. Changing the schema
requires coordinated updates across all components — do not change it casually.
"""

from apkscan.schema.artifacts import ArtifactKind, make_artifact_id
from apkscan.schema.features import (
    SCHEMA_VERSION,
    AnalysisGap,
    AnalyzerRun,
    ApiReference,
    Asset,
    Certificate,
    Component,
    DynamicFeatures,
    EscalationFlag,
    ExtractedString,
    FeatureSet,
    IOCSet,
    MobSFSummary,
    NativeLib,
    PackerDetection,
    Permission,
    QuarkBehavior,
    SampleMetadata,
    YaraMatch,
)
from apkscan.schema.evidence import (
    EvidenceCategory,
    EvidenceItem,
    EvidenceLayer,
    LayerScore,
    ScoreResult,
    Severity,
    Verdict,
)
from apkscan.schema.genai import GenAIClaim, GenAIInterpretation
from apkscan.schema.report import (
    AttackTechniqueRef,
    ReportDocument,
    SignOffBlock,
    VerdictBlock,
)

__all__ = [
    "SCHEMA_VERSION",
    "ArtifactKind",
    "make_artifact_id",
    # features
    "AnalysisGap",
    "AnalyzerRun",
    "ApiReference",
    "Asset",
    "Certificate",
    "Component",
    "DynamicFeatures",
    "EscalationFlag",
    "ExtractedString",
    "FeatureSet",
    "IOCSet",
    "MobSFSummary",
    "NativeLib",
    "PackerDetection",
    "Permission",
    "QuarkBehavior",
    "SampleMetadata",
    "YaraMatch",
    # evidence / scoring
    "EvidenceCategory",
    "EvidenceItem",
    "EvidenceLayer",
    "LayerScore",
    "ScoreResult",
    "Severity",
    "Verdict",
    # genai
    "GenAIClaim",
    "GenAIInterpretation",
    # report
    "AttackTechniqueRef",
    "ReportDocument",
    "SignOffBlock",
    "VerdictBlock",
]
