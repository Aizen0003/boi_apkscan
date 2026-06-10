"""Verdict + IOC export, including a minimal STIX 2.1-style bundle."""

import uuid
from datetime import datetime, timezone
from typing import Dict, List


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _indicator(pattern: str, name: str, created: str) -> Dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "name": name,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": created,
    }


def _stix_bundle(sha256: str, verdict: str, iocs: Dict, techniques: List[str]) -> Dict:
    created = _now()
    objects: List[Dict] = []

    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": f"malware--{uuid.uuid4()}",
        "created": created,
        "modified": created,
        "name": f"APKScan:{sha256[:16]}",
        "is_family": False,
        "malware_types": ["trojan"] if verdict == "Malicious" else ["unknown"],
    }
    objects.append(malware)
    objects.append(
        _indicator(f"[file:hashes.'SHA-256' = '{sha256}']", f"APK sample {sha256[:16]}", created)
    )
    for domain in iocs.get("domains", []):
        objects.append(_indicator(f"[domain-name:value = '{domain}']", f"domain {domain}", created))
    for url in iocs.get("urls", []):
        objects.append(_indicator(f"[url:value = '{url}']", "url", created))
    for ip in iocs.get("ips", []):
        objects.append(_indicator(f"[ipv4-addr:value = '{ip}']", f"ip {ip}", created))
    for tid in techniques:
        objects.append(
            {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{uuid.uuid4()}",
                "created": created,
                "modified": created,
                "name": tid,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": tid}
                ],
            }
        )
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def build_export(*, sha256: str, score_json: Dict, features_json: Dict) -> Dict:
    iocs = features_json.get("iocs", {}) or {}
    techniques = score_json.get("attack_techniques", []) or []
    return {
        "sample_sha256": sha256,
        "verdict": score_json.get("verdict"),
        "severity": score_json.get("severity"),
        "risk_score": score_json.get("risk_score"),
        "confidence": score_json.get("confidence"),
        "attack_techniques": techniques,
        "iocs": iocs,
        "stix_bundle": _stix_bundle(sha256, score_json.get("verdict"), iocs, techniques),
    }
