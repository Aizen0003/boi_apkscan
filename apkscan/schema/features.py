"""The canonical APK feature schema (version 1.0.0).

A ``FeatureSet`` is the single structured representation of everything extracted
from a sample. Static workers populate it; the GenAI service reads it (and may
only cite artifacts that exist in it); the scoring engine derives evidence from
it; the report generator renders it; the future dynamic module appends to its
``dynamic`` section.

Design notes:
  * Every citable element exposes an ``artifact_id`` so claims/evidence can
    reference it (see ``apkscan.schema.artifacts``).
  * ``ExtractedString.value`` and all IOC values are UNTRUSTED input. Nothing in
    this module trusts them; downstream prompt construction isolates them.
  * Optional/missing analyzers are recorded in ``analysis_gaps`` rather than
    omitted silently — this is the fail-safe-on-uncertainty contract.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from apkscan.schema.artifacts import ArtifactKind, make_artifact_id

SCHEMA_VERSION = "1.0.0"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Provenance / transparency
# --------------------------------------------------------------------------- #
class AnalysisGap(BaseModel):
    """A capability that could not be exercised (tool missing, error, packed).

    Recorded explicitly so the scorer can lower confidence instead of
    under-reporting (IMPLEMENTATION_RULES.md §7, fail-safe on uncertainty).
    """

    tool: str
    reason: str
    severity: str = "warning"  # info | warning | error


class AnalyzerRun(BaseModel):
    """Audit record of one analyzer execution."""

    name: str
    version: Optional[str] = None
    ok: bool = True
    duration_ms: Optional[float] = None
    error: Optional[str] = None


# --------------------------------------------------------------------------- #
# Core extracted entities
# --------------------------------------------------------------------------- #
class SampleMetadata(BaseModel):
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    file_name: Optional[str] = None
    file_size: int = 0
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    main_activity: Optional[str] = None


class Permission(BaseModel):
    name: str
    protection_level: Optional[str] = None  # dangerous | signature | normal | ...
    maybe_custom: bool = False

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.PERMISSION, self.name)


class Component(BaseModel):
    name: str
    type: str  # activity | service | receiver | provider
    exported: Optional[bool] = None
    permission: Optional[str] = None
    intent_actions: List[str] = Field(default_factory=list)

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.COMPONENT, self.type, self.name)


class Certificate(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    self_signed: bool = False
    is_debug: bool = False
    public_key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.CERTIFICATE, self.sha256 or self.sha1 or "unknown")


class ApiReference(BaseModel):
    """A sensitive API/method reference of interest (for ML + grounding)."""

    index: int
    api: str  # e.g. "Landroid/telephony/SmsManager;->sendTextMessage"
    caller: Optional[str] = None

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.API, self.index)


class ExtractedString(BaseModel):
    """An extracted string. ``value`` is UNTRUSTED input — never an instruction."""

    index: int
    value: str
    location: Optional[str] = None  # dex | manifest | asset:<name> | resource

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.STRING, self.index)


class IOCSet(BaseModel):
    domains: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    firebase_urls: List[str] = Field(default_factory=list)
    crypto_constants: List[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            [self.domains, self.urls, self.ips, self.emails, self.firebase_urls, self.crypto_constants]
        )


class NativeLib(BaseModel):
    name: str
    size: Optional[int] = None
    architectures: List[str] = Field(default_factory=list)

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.NATIVE_LIB, self.name)


class Asset(BaseModel):
    name: str
    size: Optional[int] = None
    entropy: Optional[float] = None
    suspected_encrypted: bool = False
    suspected_dex: bool = False

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.ASSET, self.name)


class PackerDetection(BaseModel):
    name: str
    type: str = "packer"  # packer | obfuscator | compiler | anti_vm | anti_debug | protector
    source: str = "apkid"

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.PACKER, self.name)


class QuarkBehavior(BaseModel):
    """A Quark-Engine behavior match (five-stage 'order theory of crime').

    ``confidence_stage`` is the highest matched stage (1..5): 1 permission,
    2 native API, 3 combination of APIs, 4 calling sequence, 5 same register.
    ``weight`` is Quark's exponential weight; ``score`` its contribution.
    """

    crime: str
    confidence_stage: int = 0  # 0..5 (0 = no match)
    confidence_percent: Optional[float] = None  # 0..100
    weight: Optional[float] = None
    score: Optional[float] = None
    apis: List[str] = Field(default_factory=list)

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.QUARK, self.crime)


class YaraMatch(BaseModel):
    rule: str
    namespace: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    meta: Dict[str, object] = Field(default_factory=dict)
    matched_strings: List[str] = Field(default_factory=list)
    source: str = "internal"  # internal | mobsf | community

    @property
    def artifact_id(self) -> str:
        return make_artifact_id(ArtifactKind.YARA, self.rule)


class MobSFSummary(BaseModel):
    """Structured summary of a MobSF scan (not the full raw dump)."""

    mobsf_version: Optional[str] = None
    security_score: Optional[float] = None  # 0..100
    grade: Optional[str] = None  # A..F
    high: int = 0
    medium: int = 0
    info: int = 0
    secure: int = 0
    hotspot: int = 0
    trackers: int = 0
    malware_domains: List[str] = Field(default_factory=list)
    firebase_urls: List[str] = Field(default_factory=list)
    findings: Dict[str, object] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Phase 2 seam — dynamic analysis (declared but unused in MVP)
# --------------------------------------------------------------------------- #
class DynamicFeatures(BaseModel):
    captured: bool = False
    api_trace: List[str] = Field(default_factory=list)
    network_endpoints: List[str] = Field(default_factory=list)
    pcap_summary: Dict[str, object] = Field(default_factory=dict)
    sms_events: List[str] = Field(default_factory=list)
    file_ops: List[str] = Field(default_factory=list)
    notes: Optional[str] = None


# --------------------------------------------------------------------------- #
# Escalation
# --------------------------------------------------------------------------- #
class EscalationFlag(BaseModel):
    """The 'escalate to dynamic' decision (FR4/T0.6)."""

    escalate: bool = False
    reasons: List[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# The canonical container
# --------------------------------------------------------------------------- #
class FeatureSet(BaseModel):
    schema_version: str = SCHEMA_VERSION
    created_at: datetime = Field(default_factory=_utcnow)

    sample: SampleMetadata
    permissions: List[Permission] = Field(default_factory=list)
    components: List[Component] = Field(default_factory=list)
    certificates: List[Certificate] = Field(default_factory=list)
    apis: List[ApiReference] = Field(default_factory=list)
    strings: List[ExtractedString] = Field(default_factory=list)
    iocs: IOCSet = Field(default_factory=IOCSet)
    native_libs: List[NativeLib] = Field(default_factory=list)
    assets: List[Asset] = Field(default_factory=list)
    packers: List[PackerDetection] = Field(default_factory=list)
    quark_behaviors: List[QuarkBehavior] = Field(default_factory=list)
    yara_matches: List[YaraMatch] = Field(default_factory=list)
    mobsf: Optional[MobSFSummary] = None
    dynamic: Optional[DynamicFeatures] = None

    escalation: EscalationFlag = Field(default_factory=EscalationFlag)
    analysis_gaps: List[AnalysisGap] = Field(default_factory=list)
    analyzer_runs: List[AnalyzerRun] = Field(default_factory=list)

    # ---- artifact index (grounding + evidence anchoring) ----
    def artifact_index(self) -> Dict[str, str]:
        """Map every citable artifact id -> a short human-readable value.

        Used by grounding (does this cited id exist?) and reporting (render the
        value behind an evidence reference).
        """

        index: Dict[str, str] = {}
        for perm in self.permissions:
            index[perm.artifact_id] = perm.name
        for comp in self.components:
            index[comp.artifact_id] = f"{comp.type}:{comp.name}"
        for cert in self.certificates:
            index[cert.artifact_id] = cert.subject or cert.sha256 or "certificate"
        for api in self.apis:
            index[api.artifact_id] = api.api
        for s in self.strings:
            index[s.artifact_id] = s.value
        for lib in self.native_libs:
            index[lib.artifact_id] = lib.name
        for asset in self.assets:
            index[asset.artifact_id] = asset.name
        for pk in self.packers:
            index[pk.artifact_id] = f"{pk.type}:{pk.name}"
        for q in self.quark_behaviors:
            index[q.artifact_id] = q.crime
        for y in self.yara_matches:
            index[y.artifact_id] = y.rule
        for kind, values in (
            ("domain", self.iocs.domains),
            ("url", self.iocs.urls),
            ("ip", self.iocs.ips),
            ("email", self.iocs.emails),
            ("firebase", self.iocs.firebase_urls),
            ("crypto", self.iocs.crypto_constants),
        ):
            for value in values:
                index[make_artifact_id(ArtifactKind.IOC, kind, value)] = value
        return index

    def has_artifact(self, artifact_id: str) -> bool:
        return artifact_id in self.artifact_index()

    def permission_names(self) -> List[str]:
        return [p.name for p in self.permissions]
