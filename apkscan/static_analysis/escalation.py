"""Packing/encryption/dynamic-loading detector + escalation flag (T0.6 / FR4).

Static analysis cannot defeat runtime-decrypted payloads, asset-hidden DEX, or
dynamic class loading (e.g. Anatsa, ClayRat). When such indicators are present we
set ``escalate=True`` with explicit reasons so the verdict reflects uncertainty
(fail-safe) and the sample can be routed to the dynamic module (Phase 2) when
enabled — rather than being silently under-reported.
"""

from typing import List

from apkscan.schema import EscalationFlag, FeatureSet

_DYNAMIC_LOADERS = ("DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "loadClass", "loadDex")


def detect_escalation(features: FeatureSet) -> EscalationFlag:
    reasons: List[str] = []

    for packer in features.packers:
        if packer.type in ("packer", "protector"):
            reasons.append(f"packer/protector detected: {packer.name}")
        elif packer.type == "obfuscator":
            reasons.append(f"obfuscation detected: {packer.name}")
        elif packer.type in ("anti_vm", "anti_debug"):
            reasons.append(f"anti-analysis technique detected: {packer.name} ({packer.type})")

    for asset in features.assets:
        if asset.suspected_dex:
            reasons.append(f"asset-hidden DEX payload: {asset.name}")
        elif asset.suspected_encrypted:
            reasons.append(f"high-entropy/encrypted asset: {asset.name}")

    for api in features.apis:
        if any(loader in api.api for loader in _DYNAMIC_LOADERS):
            reasons.append(f"dynamic code-loading API: {api.api}")

    # runtime-decryption signal: crypto constants alongside encrypted assets
    has_encrypted_asset = any(a.suspected_encrypted or a.suspected_dex for a in features.assets)
    if features.iocs.crypto_constants and has_encrypted_asset:
        reasons.append(
            "runtime decryption indicators: crypto constants "
            f"({', '.join(features.iocs.crypto_constants[:3])}) with encrypted asset(s)"
        )

    # dedupe while preserving order
    seen = set()
    deduped = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped.append(r)

    return EscalationFlag(escalate=bool(deduped), reasons=deduped)
