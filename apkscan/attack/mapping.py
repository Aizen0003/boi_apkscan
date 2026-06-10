"""Behavior taxonomy + behavior->technique mapping, and feature derivation.

``derive_behaviors`` is the single source of truth that turns canonical features
(permissions, components, Quark behaviors, YARA hits, packers, dynamic-loading
indicators) into ATT&CK technique matches with the exact artifacts that triggered
them. Both the report (AC5) and the rule scorer consume it.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple

from apkscan.attack.techniques import TECHNIQUES, Technique, get_technique
from apkscan.schema import FeatureSet


class Behavior(str, Enum):
    OVERLAY = "overlay"
    ACCESSIBILITY_ABUSE = "accessibility_abuse"
    SMS_READ = "sms_read"
    SMS_INTERCEPT = "sms_intercept"
    KEYLOGGING = "keylogging"
    SCREEN_CAPTURE = "screen_capture"
    VIDEO_CAPTURE = "video_capture"
    RAT = "rat"
    HIDE_ICON = "hide_icon"
    DYNAMIC_CODE_LOAD = "dynamic_code_load"
    INGRESS_TOOL_TRANSFER = "ingress_tool_transfer"
    APP_DISCOVERY = "app_discovery"
    SECURITY_SOFTWARE_DISCOVERY = "security_software_discovery"
    OBFUSCATION = "obfuscation"
    SOFTWARE_PACKING = "software_packing"
    SMISHING = "smishing"


# Behavior -> verified ATT&CK for Mobile v19.1 technique ID.
BEHAVIOR_TECHNIQUE: Dict[Behavior, str] = {
    Behavior.OVERLAY: "T1417.002",
    Behavior.ACCESSIBILITY_ABUSE: "T1453",
    Behavior.SMS_READ: "T1636.004",
    Behavior.SMS_INTERCEPT: "T1582",
    Behavior.KEYLOGGING: "T1417.001",
    Behavior.SCREEN_CAPTURE: "T1513",
    Behavior.VIDEO_CAPTURE: "T1512",
    Behavior.RAT: "T1663",
    Behavior.HIDE_ICON: "T1628.001",
    Behavior.DYNAMIC_CODE_LOAD: "T1407",
    Behavior.INGRESS_TOOL_TRANSFER: "T1544",
    Behavior.APP_DISCOVERY: "T1418",
    Behavior.SECURITY_SOFTWARE_DISCOVERY: "T1418.001",
    Behavior.OBFUSCATION: "T1406",
    Behavior.SOFTWARE_PACKING: "T1406.002",
    Behavior.SMISHING: "T1660",
}

# Permission -> behaviors it directly evidences.
PERMISSION_BEHAVIORS: Dict[str, Tuple[Behavior, ...]] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": (Behavior.ACCESSIBILITY_ABUSE,),
    "android.permission.SYSTEM_ALERT_WINDOW": (Behavior.OVERLAY,),
    "android.permission.READ_SMS": (Behavior.SMS_READ,),
    "android.permission.RECEIVE_SMS": (Behavior.SMS_READ,),
    "android.permission.SEND_SMS": (Behavior.SMS_INTERCEPT,),
    "android.permission.QUERY_ALL_PACKAGES": (Behavior.APP_DISCOVERY,),
    "android.permission.REQUEST_INSTALL_PACKAGES": (Behavior.INGRESS_TOOL_TRANSFER,),
}


def technique_for(behavior: Behavior) -> Technique:
    return TECHNIQUES[BEHAVIOR_TECHNIQUE[behavior]]


def techniques_for_behaviors(behaviors) -> List[Technique]:
    seen: Dict[str, Technique] = {}
    for b in behaviors:
        tech = technique_for(b)
        seen[tech.id] = tech
    return list(seen.values())


@dataclass
class BehaviorMatch:
    behavior: Behavior
    technique_id: str
    technique_name: str
    tactics: Tuple[str, ...]
    artifact_refs: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)


# Keyword -> behavior, applied to Quark crime descriptions and YARA tags/rules.
_KEYWORD_BEHAVIORS: Tuple[Tuple[Tuple[str, ...], Behavior], ...] = (
    (("accessibility", "a11y"), Behavior.ACCESSIBILITY_ABUSE),
    (("overlay", "draw over", "system_alert", "addview", "type_application_overlay"), Behavior.OVERLAY),
    (("keylog", "keystroke", "key log"), Behavior.KEYLOGGING),
    (("screenshot", "screen capture", "screen record", "mediaprojection"), Behavior.SCREEN_CAPTURE),
    (("camera", "video capture", "record video"), Behavior.VIDEO_CAPTURE),
    (("vnc", "remote control", "remote access", "remote desktop"), Behavior.RAT),
    (("hide icon", "suppress", "hide application", "remove icon"), Behavior.HIDE_ICON),
    (("dexclassloader", "pathclassloader", "load dex", "dynamic load", "load class", "runtime code"), Behavior.DYNAMIC_CODE_LOAD),
    (("install package", "request_install"), Behavior.INGRESS_TOOL_TRANSFER),
    (("installed applications", "list package", "enumerate app", "query_all_packages", "get installed"), Behavior.APP_DISCOVERY),
    (("antivirus", "security software", "detect av"), Behavior.SECURITY_SOFTWARE_DISCOVERY),
)


def _keyword_behaviors(text: str) -> List[Behavior]:
    text = text.lower()
    hits: List[Behavior] = []
    for keywords, behavior in _KEYWORD_BEHAVIORS:
        if any(k in text for k in keywords):
            hits.append(behavior)
    # SMS handled with read/intercept disambiguation
    if "sms" in text or "text message" in text:
        if any(k in text for k in ("send", "abort", "intercept", "suppress", "delete", "block")):
            hits.append(Behavior.SMS_INTERCEPT)
        else:
            hits.append(Behavior.SMS_READ)
    return hits


def behaviors_for_text(text: str) -> List[Behavior]:
    """Public keyword->behavior mapping (used by the rule scorer)."""

    return _keyword_behaviors(text)


def technique_ids_for_text(text: str) -> List[str]:
    seen = []
    for behavior in _keyword_behaviors(text):
        tid = BEHAVIOR_TECHNIQUE[behavior]
        if tid not in seen:
            seen.append(tid)
    return seen


def technique_ids_for_permission(name: str) -> List[str]:
    return [BEHAVIOR_TECHNIQUE[b] for b in PERMISSION_BEHAVIORS.get(name, ())]


def derive_behaviors(features: FeatureSet) -> List[BehaviorMatch]:
    """Map canonical features -> ATT&CK behavior matches (deduped, with refs)."""

    agg: Dict[Behavior, BehaviorMatch] = {}

    def add(behavior: Behavior, artifact_ref: str, source: str) -> None:
        tech = technique_for(behavior)
        match = agg.get(behavior)
        if match is None:
            match = BehaviorMatch(
                behavior=behavior,
                technique_id=tech.id,
                technique_name=tech.name,
                tactics=tech.tactics,
            )
            agg[behavior] = match
        if artifact_ref and artifact_ref not in match.artifact_refs:
            match.artifact_refs.append(artifact_ref)
        if source not in match.sources:
            match.sources.append(source)

    # permissions
    for perm in features.permissions:
        for behavior in PERMISSION_BEHAVIORS.get(perm.name, ()):  # exact name match
            add(behavior, perm.artifact_id, "permission")

    # components (intent actions reveal accessibility / SMS handlers)
    for comp in features.components:
        actions = " ".join(comp.intent_actions).lower()
        if "accessibilityservice" in actions or comp.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE":
            add(Behavior.ACCESSIBILITY_ABUSE, comp.artifact_id, "component")
        if "sms_received" in actions or "sms_deliver" in actions:
            add(Behavior.SMS_READ, comp.artifact_id, "component")

    # quark behaviors
    for q in features.quark_behaviors:
        for behavior in _keyword_behaviors(q.crime):
            add(behavior, q.artifact_id, "quark")

    # yara matches (rule name + tags)
    for y in features.yara_matches:
        text = " ".join([y.rule, *y.tags])
        for behavior in _keyword_behaviors(text):
            add(behavior, y.artifact_id, "yara")
        if "rat" in [t.lower() for t in y.tags] or "rat" in y.rule.lower():
            add(Behavior.RAT, y.artifact_id, "yara")

    # packers / obfuscators (APKiD)
    for pk in features.packers:
        if pk.type in ("packer", "protector"):
            add(Behavior.SOFTWARE_PACKING, pk.artifact_id, "apkid")
        elif pk.type == "obfuscator":
            add(Behavior.OBFUSCATION, pk.artifact_id, "apkid")

    # dynamic code loading: asset-hidden DEX or dynamic loader APIs
    for asset in features.assets:
        if asset.suspected_dex:
            add(Behavior.DYNAMIC_CODE_LOAD, asset.artifact_id, "asset")
    for api in features.apis:
        if any(loader in api.api for loader in ("DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader")):
            add(Behavior.DYNAMIC_CODE_LOAD, api.artifact_id, "api")

    return list(agg.values())


def all_technique_ids() -> List[str]:
    return list(TECHNIQUES.keys())


# re-export for callers that want the catalog lookup
__all__ = [
    "Behavior",
    "BEHAVIOR_TECHNIQUE",
    "PERMISSION_BEHAVIORS",
    "BehaviorMatch",
    "derive_behaviors",
    "technique_for",
    "techniques_for_behaviors",
    "get_technique",
]
