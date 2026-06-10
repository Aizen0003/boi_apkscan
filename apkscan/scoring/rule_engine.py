"""Deterministic rule-scoring layer (T0.8 / AC4).

Produces a reproducible 0..100 rule score and a complete, per-indicator evidence
list. This is the primary, auditable source of truth for the verdict. Given the
same ``FeatureSet`` it always yields the same score and evidence.

Normalization: ``score = 100 * (1 - exp(-raw / K))`` where ``raw`` is the sum of
all indicator weights and ``K`` (NORMALIZATION_K) is an exposed operating-point
constant. The function is monotonic and saturating, so more/stronger indicators
never lower the score.
"""

import math
from dataclasses import dataclass, field
from typing import List
from urllib.parse import urlparse

from apkscan.attack.mapping import technique_ids_for_permission, technique_ids_for_text
from apkscan.schema import EvidenceCategory, EvidenceItem, EvidenceLayer, FeatureSet
from apkscan.schema.artifacts import ArtifactKind, make_artifact_id
from apkscan.scoring import weights as W


@dataclass
class RuleResult:
    raw_weight: float
    normalized_score: float  # 0..100
    evidence: List[EvidenceItem] = field(default_factory=list)


def _normalize(raw: float) -> float:
    if raw <= 0:
        return 0.0
    return round(100.0 * (1.0 - math.exp(-raw / W.NORMALIZATION_K)), 2)


def _ip_host(url: str) -> bool:
    host = urlparse(url).hostname or ""
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def score_rules(features: FeatureSet) -> RuleResult:
    evidence: List[EvidenceItem] = []

    # --- single permissions ---
    perm_index = {p.name: p for p in features.permissions}
    for perm in features.permissions:
        weight = W.PERMISSION_WEIGHTS.get(perm.name)
        if not weight:
            continue
        evidence.append(
            EvidenceItem(
                id=f"rule:perm:{perm.name}",
                layer=EvidenceLayer.RULE,
                category=EvidenceCategory.PERMISSION.value,
                title=f"Dangerous permission: {perm.name.split('.')[-1]}",
                detail=f"Requests {perm.name} (weight {weight}).",
                weight=float(weight),
                artifact_refs=[perm.artifact_id],
                attack_techniques=technique_ids_for_permission(perm.name),
            )
        )

    # --- dangerous combinations ---
    present = set(perm_index)
    for idx, (combo, bonus, description) in enumerate(W.PERMISSION_COMBINATIONS):
        if combo.issubset(present):
            refs = [perm_index[name].artifact_id for name in sorted(combo)]
            techniques: List[str] = []
            for name in sorted(combo):
                for tid in technique_ids_for_permission(name):
                    if tid not in techniques:
                        techniques.append(tid)
            evidence.append(
                EvidenceItem(
                    id=f"rule:combo:{idx}",
                    layer=EvidenceLayer.RULE,
                    category=EvidenceCategory.PERMISSION_COMBO.value,
                    title=f"Dangerous permission combination (+{bonus})",
                    detail=description,
                    weight=float(bonus),
                    artifact_refs=refs,
                    attack_techniques=techniques,
                )
            )

    # --- Quark five-stage behaviors ---
    for i, q in enumerate(features.quark_behaviors):
        weight = q.score if q.score else W.QUARK_STAGE_WEIGHTS.get(q.confidence_stage, 0.0)
        if weight <= 0:
            continue
        evidence.append(
            EvidenceItem(
                id=f"rule:quark:{i}",
                layer=EvidenceLayer.RULE,
                category=EvidenceCategory.QUARK_BEHAVIOR.value,
                title=f"Quark behavior (stage {q.confidence_stage}/5): {q.crime}",
                detail=f"Quark matched '{q.crime}' at confidence stage {q.confidence_stage} "
                f"({q.confidence_percent}%).",
                weight=float(weight),
                confidence=(q.confidence_percent or 0) / 100.0 or 1.0,
                artifact_refs=[q.artifact_id],
                attack_techniques=technique_ids_for_text(q.crime),
            )
        )

    # --- YARA hits ---
    for y in features.yara_matches:
        boost = sum(W.YARA_TAG_BOOSTS.get(t.lower(), 0.0) for t in y.tags)
        weight = min(W.YARA_BASE_WEIGHT + boost, W.YARA_MAX_WEIGHT)
        techniques = []
        attck_meta = y.meta.get("attck") if isinstance(y.meta, dict) else None
        if attck_meta:
            techniques = [str(attck_meta)]
        else:
            techniques = technique_ids_for_text(" ".join([y.rule, *y.tags]))
        evidence.append(
            EvidenceItem(
                id=f"rule:yara:{y.rule}",
                layer=EvidenceLayer.RULE,
                category=EvidenceCategory.YARA.value,
                title=f"YARA rule matched: {y.rule}",
                detail=f"Tags: {', '.join(y.tags) or 'none'}.",
                weight=float(weight),
                artifact_refs=[y.artifact_id],
                attack_techniques=techniques,
            )
        )

    # --- certificate checks ---
    for cert in features.certificates:
        if cert.is_debug:
            evidence.append(
                EvidenceItem(
                    id="rule:cert:debug",
                    layer=EvidenceLayer.RULE,
                    category=EvidenceCategory.CERTIFICATE.value,
                    title="Debug-signed certificate",
                    detail=f"Signed with an Android debug certificate ({cert.subject}).",
                    weight=W.CERT_DEBUG_WEIGHT,
                    artifact_refs=[cert.artifact_id],
                )
            )
        elif cert.self_signed:
            evidence.append(
                EvidenceItem(
                    id="rule:cert:self_signed",
                    layer=EvidenceLayer.RULE,
                    category=EvidenceCategory.CERTIFICATE.value,
                    title="Self-signed certificate",
                    detail=f"Subject equals issuer ({cert.subject}).",
                    weight=W.CERT_SELF_SIGNED_WEIGHT,
                    artifact_refs=[cert.artifact_id],
                )
            )

    # --- Firebase endpoints (C2 / exfil; FatBoyPanel India context) ---
    if features.iocs.firebase_urls:
        refs = [make_artifact_id(ArtifactKind.IOC, "firebase", u) for u in features.iocs.firebase_urls]
        weight = min(W.FIREBASE_WEIGHT * len(features.iocs.firebase_urls), W.FIREBASE_MAX)
        evidence.append(
            EvidenceItem(
                id="rule:ioc:firebase",
                layer=EvidenceLayer.RULE,
                category=EvidenceCategory.FIREBASE.value,
                title="Firebase endpoint(s) referenced",
                detail="Firebase often used as C2 / exfiltration sink by India-targeting bankers.",
                weight=float(weight),
                artifact_refs=refs,
                attack_techniques=["T1544"],
            )
        )

    # --- raw IP-literal C2 endpoints ---
    ip_urls = [u for u in features.iocs.urls if _ip_host(u)]
    if ip_urls:
        refs = [make_artifact_id(ArtifactKind.IOC, "url", u) for u in ip_urls]
        weight = min(W.IP_LITERAL_C2_WEIGHT * len(ip_urls), W.IP_LITERAL_C2_MAX)
        evidence.append(
            EvidenceItem(
                id="rule:ioc:ip_c2",
                layer=EvidenceLayer.RULE,
                category=EvidenceCategory.DOMAIN.value,
                title="Hardcoded IP-literal endpoint(s)",
                detail="Connections to raw IP addresses are a common C2 indicator.",
                weight=float(weight),
                artifact_refs=refs,
            )
        )

    # --- escalation (packing/encryption/dynamic loading) ---
    if features.escalation.escalate:
        weight = min(W.ESCALATION_WEIGHT * len(features.escalation.reasons), W.ESCALATION_MAX)
        evidence.append(
            EvidenceItem(
                id="rule:escalation",
                layer=EvidenceLayer.RULE,
                category=EvidenceCategory.ESCALATION.value,
                title="Static analysis partially defeated (escalation flagged)",
                detail="; ".join(features.escalation.reasons),
                weight=float(weight),
                attack_techniques=["T1406", "T1407"],
                metadata={"reasons": features.escalation.reasons},
            )
        )

    raw = round(sum(e.weight for e in evidence), 4)
    return RuleResult(raw_weight=raw, normalized_score=_normalize(raw), evidence=evidence)
