"""Deterministic rule-scoring + policy tests (T0.8 / AC4)."""

from apkscan.schema import EvidenceLayer, Severity, Verdict
from apkscan.scoring.policy import classify, thresholds_for_mode
from apkscan.scoring.rule_engine import score_rules
from apkscan.static_analysis.escalation import detect_escalation


def _scored_malicious(malicious_features):
    # apply escalation as the pipeline would before scoring
    malicious_features.escalation = detect_escalation(malicious_features)
    return malicious_features


# --- determinism (the load-bearing property) ---
def test_rule_scoring_is_reproducible(malicious_features):
    f = _scored_malicious(malicious_features)
    r1 = score_rules(f)
    r2 = score_rules(f)
    assert r1.raw_weight == r2.raw_weight
    assert r1.normalized_score == r2.normalized_score
    assert [(e.id, e.weight) for e in r1.evidence] == [(e.id, e.weight) for e in r2.evidence]


# --- benign stays low ---
def test_benign_scores_low_and_benign(benign_features):
    result = score_rules(benign_features)
    assert result.normalized_score < 25
    verdict, severity, signoff = classify(result.normalized_score, "balanced")
    assert verdict == Verdict.BENIGN
    assert severity == Severity.LOW
    assert signoff is False


# --- banking trojan scores high & requires sign-off ---
def test_malicious_scores_high_requires_signoff(malicious_features):
    f = _scored_malicious(malicious_features)
    result = score_rules(f)
    assert result.normalized_score >= 75
    verdict, severity, signoff = classify(result.normalized_score, "balanced")
    assert verdict == Verdict.MALICIOUS
    assert severity in (Severity.HIGH, Severity.CRITICAL)
    assert signoff is True


# --- evidence completeness + all rule-layer ---
def test_evidence_covers_all_indicator_categories(malicious_features):
    f = _scored_malicious(malicious_features)
    result = score_rules(f)
    categories = {e.category for e in result.evidence}
    for expected in ("permission", "permission_combo", "quark_behavior", "yara", "certificate", "firebase", "escalation"):
        assert expected in categories, f"missing {expected} evidence"
    # the rule layer is, by construction, entirely deterministic RULE evidence
    assert all(e.layer == EvidenceLayer.RULE for e in result.evidence)


# --- rule evidence is grounded: every artifact_ref exists in the features ---
def test_rule_evidence_artifact_refs_are_grounded(malicious_features):
    f = _scored_malicious(malicious_features)
    result = score_rules(f)
    index = f.artifact_index()
    for item in result.evidence:
        for ref in item.artifact_refs:
            assert ref in index, f"evidence {item.id} cites non-existent artifact {ref}"


def test_combination_bonus_present(malicious_features):
    result = score_rules(malicious_features)
    combos = [e for e in result.evidence if e.category == "permission_combo"]
    assert combos
    # the overlay+accessibility classic-banker combo must be detected
    assert any("accessibility" in e.detail.lower() for e in combos)


# --- policy ---
def test_classify_boundaries_balanced():
    assert classify(0, "balanced")[0] == Verdict.BENIGN
    assert classify(24.9, "balanced")[1] == Severity.LOW
    assert classify(25, "balanced") == (Verdict.SUSPICIOUS, Severity.MODERATE, False)
    assert classify(50, "balanced") == (Verdict.MALICIOUS, Severity.HIGH, True)
    assert classify(75, "balanced") == (Verdict.MALICIOUS, Severity.CRITICAL, True)


def test_high_recall_mode_lowers_bar():
    # a score of 40 is Suspicious under balanced but Malicious under high_recall
    assert classify(40, "balanced")[0] == Verdict.SUSPICIOUS
    assert classify(40, "high_recall")[0] == Verdict.MALICIOUS
    assert thresholds_for_mode("high_recall").suspicious_max < thresholds_for_mode("balanced").suspicious_max
