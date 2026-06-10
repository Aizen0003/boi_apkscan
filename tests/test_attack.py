"""ATT&CK for Mobile v19.1 mapping tests (T0.7 / AC5)."""

import pytest

from apkscan.attack import (
    ATTACK_MOBILE_VERSION,
    TACTICS,
    TECHNIQUES,
    Behavior,
    derive_behaviors,
    technique_for,
)
from apkscan.attack.mapping import BEHAVIOR_TECHNIQUE

# The exact behavior->technique contract from RESEARCH.md (verified v19.1).
EXPECTED = {
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


def test_version_is_v19_1():
    assert ATTACK_MOBILE_VERSION == "19.1"


@pytest.mark.parametrize("behavior,technique_id", EXPECTED.items())
def test_each_behavior_resolves_to_correct_technique(behavior, technique_id):
    assert BEHAVIOR_TECHNIQUE[behavior] == technique_id
    tech = technique_for(behavior)
    assert tech.id == technique_id
    assert tech.name  # has a name
    # tactics reference the 12-tactic catalog
    for tactic in tech.tactics:
        assert tactic in TACTICS


def test_all_twelve_tactics_present():
    assert len(TACTICS) == 12
    assert TACTICS["TA0027"] == "Initial Access"
    assert TACTICS["TA0037"] == "Command and Control"


def test_every_referenced_technique_is_catalogued():
    for technique_id in BEHAVIOR_TECHNIQUE.values():
        assert technique_id in TECHNIQUES


def test_sub_technique_url_form():
    assert technique_for(Behavior.OVERLAY).url.endswith("/techniques/T1417/002")
    assert technique_for(Behavior.RAT).url.endswith("/techniques/T1663")


def test_derive_behaviors_on_banking_trojan(malicious_features):
    matches = derive_behaviors(malicious_features)
    found = {m.technique_id for m in matches}
    # accessibility abuse, SMS read, overlay, app discovery, dropper, dynamic load,
    # obfuscation must all surface from the trojan-like fixture.
    assert "T1453" in found          # accessibility (permission + component)
    assert "T1636.004" in found      # SMS read
    assert "T1417.002" in found      # overlay (SYSTEM_ALERT_WINDOW)
    assert "T1418" in found          # QUERY_ALL_PACKAGES
    assert "T1544" in found          # REQUEST_INSTALL_PACKAGES
    assert "T1407" in found          # asset-hidden DEX + DexClassLoader api
    assert "T1406" in found          # obfuscator

    # every match cites at least one real artifact that exists in the features
    idx = malicious_features.artifact_index()
    for m in matches:
        assert m.artifact_refs, f"{m.technique_id} has no artifact refs"
        for ref in m.artifact_refs:
            assert ref in idx, f"{ref} not a real artifact"


def test_derive_behaviors_on_benign_is_quiet(benign_features):
    matches = derive_behaviors(benign_features)
    # A calculator with INTERNET + ACCESS_NETWORK_STATE evidences no malicious techniques.
    assert matches == []
