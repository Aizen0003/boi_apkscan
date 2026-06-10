"""Report generation tests (T0.14 / AC5, AC6)."""

import json

from apkscan.config import Settings
from apkscan.reporting import build_report_document, render_json, render_pdf
from apkscan.schema import GenAIClaim, GenAIInterpretation, ReportDocument
from apkscan.scoring.fusion import fuse
from apkscan.scoring.rule_engine import score_rules
from apkscan.static_analysis.escalation import detect_escalation


def _report_for(features, genai=None):
    features.escalation = detect_escalation(features)
    score = fuse(features, score_rules(features), genai, settings=Settings(_env_file=None))
    return build_report_document(features, score, genai, report_id="r-123")


def _genai():
    return GenAIInterpretation(
        generated=True,
        model_name="qwen2.5-coder:7b",
        summary="Banking trojan: accessibility abuse + SMS interception + firebase C2.",
        claims=[GenAIClaim(text="Intercepts SMS for OTP theft", category="behavior", artifact_refs=["perm:android.permission.READ_SMS"], attack_techniques=["T1636.004"], grounded=True)],
        recommendations=["Block the firebase endpoint"],
        prompt_injection_detected=True,
    )


def test_report_has_all_required_sections(malicious_features):
    report = _report_for(malicious_features, _genai())
    assert report.verdict.verdict.value == "Malicious"
    assert report.verdict.risk_score > 0
    assert 0 <= report.verdict.confidence <= 1
    assert report.evidence
    assert report.attack  # ATT&CK mapping present
    assert report.recommendations
    assert report.signoff.required is True
    assert report.signoff.status == "pending"
    # summary taken from grounded GenAI
    assert "trojan" in report.summary.lower()


def test_attack_refs_resolve_to_names_and_tactics(malicious_features):
    report = _report_for(malicious_features, _genai())
    by_id = {a.id: a for a in report.attack}
    assert "T1453" in by_id
    assert by_id["T1453"].name == "Abuse Accessibility Features"
    assert by_id["T1453"].tactics  # tactic names present
    assert by_id["T1453"].url.endswith("/techniques/T1453")


def test_recommendations_are_deterministic_and_actionable(malicious_features):
    report = _report_for(malicious_features, _genai())
    joined = " ".join(report.recommendations).lower()
    assert "sign-off" in joined           # High/Critical sign-off
    assert "firebase" in joined           # firebase IOC present
    assert "dynamic sandbox" in joined    # escalation flagged
    # GenAI suggestions are clearly tagged as secondary
    assert any(r.startswith("[GenAI suggestion]") for r in report.recommendations)


def test_summary_falls_back_to_deterministic_when_no_genai(malicious_features):
    report = _report_for(malicious_features, None)
    assert "deterministic analysis" in report.summary.lower()
    assert report.genai.generated is False


# --- AC6: both formats render ---
def test_render_json_is_valid_and_complete(malicious_features):
    report = _report_for(malicious_features, _genai())
    data = json.loads(render_json(report))
    assert data["verdict"]["verdict"] == "Malicious"
    assert "evidence" in data and data["evidence"]
    assert "attack" in data and data["attack"]
    assert "iocs" in data
    assert "recommendations" in data
    assert data["genai"]["generated"] is True
    # round-trips back into the model
    assert ReportDocument.model_validate(data).report_id == "r-123"


def test_render_pdf_produces_valid_pdf(malicious_features):
    report = _report_for(malicious_features, _genai())
    pdf = render_pdf(report)
    assert pdf.startswith(b"%PDF")
    assert len(pdf) > 1500


def test_pdf_escapes_untrusted_markup(malicious_features):
    # inject XML-special chars via an IOC value; PDF must still render (escaped)
    malicious_features.iocs.domains.append("<script>alert('x')</script>.evil.com")
    report = _report_for(malicious_features, None)
    pdf = render_pdf(report)
    assert pdf.startswith(b"%PDF")


def test_benign_report_no_signoff(benign_features):
    report = _report_for(benign_features, None)
    assert report.verdict.verdict.value == "Benign"
    assert report.signoff.required is False
    assert report.signoff.status == "not_required"
