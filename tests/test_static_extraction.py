"""Static feature-extraction + escalation tests (T0.5/T0.6, AC2/AC3)."""

from apkscan.schema import Asset, PackerDetection, Permission, SampleMetadata
from apkscan.static_analysis.base import Analyzer, AnalyzerResult
from apkscan.static_analysis.escalation import detect_escalation
from apkscan.static_analysis.extractor import extract_features
from apkscan.static_analysis.heuristics import is_dex_magic, looks_encrypted, shannon_entropy
from apkscan.static_analysis.iocs import build_iocset, extract_domains


# --- IOC extraction ---
def test_domain_extraction_filters_package_names():
    domains = extract_domains("pkg com.sbi.secure.update calls https://gold-c2.firebaseio.com/x")
    assert "gold-c2.firebaseio.com" in domains
    # a Java/Android package name must NOT be treated as a domain
    assert "com.sbi.secure.update" not in domains


def test_build_iocset_classifies_and_dedupes():
    strings = [
        "https://gold-c2-panel.firebaseio.com",
        "http://203.0.113.45/gate.php",
        "mailto contact evil@bad.ru",
        "cipher DESede/CBC/PKCS5Padding",
        "https://gold-c2-panel.firebaseio.com",  # dup
    ]
    iocs = build_iocset(strings)
    assert "203.0.113.45" in iocs.ips
    assert "evil@bad.ru" in iocs.emails
    assert "DESede/CBC/PKCS5Padding" in iocs.crypto_constants
    assert any("firebaseio.com" in f for f in iocs.firebase_urls)
    # deterministic: sorted + deduped
    assert iocs.urls == sorted(set(iocs.urls))


# --- heuristics ---
def test_entropy_and_dex_magic():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert shannon_entropy(bytes(range(256))) > 7.9
    assert looks_encrypted(7.9) is True
    assert looks_encrypted(4.0) is False
    assert is_dex_magic(b"dex\n035\x00") is True
    assert is_dex_magic(b"PK\x03\x04") is False


# --- extractor merge + graceful degradation ---
class _FakeAnalyzer(Analyzer):
    def __init__(self, name, result=None, available=True, raises=None):
        self.name = name
        self._result = result or AnalyzerResult()
        self._available = available
        self._raises = raises

    def is_available(self):
        return self._available

    def analyze(self, apk_path):
        if self._raises:
            raise self._raises
        return self._result


def _sample():
    return SampleMetadata(sha256="a" * 64, file_name="x.apk", file_size=10)


def test_extractor_merges_indexes_and_mines_iocs(tmp_path):
    apk = tmp_path / "x.apk"
    apk.write_bytes(b"PK")
    good = AnalyzerResult(
        sample={"package_name": "com.evil.app"},
        permissions=[Permission(name="android.permission.READ_SMS")],
        raw_strings=[("https://c2.evil.ru/gate.php", "dex"), ("https://c2.evil.ru/gate.php", "dex")],
        raw_apis=[("DexClassLoader.<init>", None), ("DexClassLoader.<init>", None)],
        assets=[Asset(name="assets/p.dat", suspected_dex=True, suspected_encrypted=True, entropy=7.9)],
    )
    features = extract_features(
        apk,
        _sample(),
        analyzers=[
            _FakeAnalyzer("good", good),
            _FakeAnalyzer("missing_tool", available=False),
            _FakeAnalyzer("boom", raises=ValueError("kaboom")),
        ],
    )

    # sample enrichment
    assert features.sample.package_name == "com.evil.app"
    # strings deduped + indexed 0..n
    assert [s.index for s in features.strings] == list(range(len(features.strings)))
    assert len(features.strings) == 1
    # apis deduped + indexed
    assert len(features.apis) == 1
    # IOCs mined from strings
    assert "c2.evil.ru" in features.iocs.domains
    # gaps: one for unavailable tool, one for the erroring analyzer
    gap_tools = {g.tool for g in features.analysis_gaps}
    assert "missing_tool" in gap_tools and "boom" in gap_tools
    assert any(g.severity == "error" for g in features.analysis_gaps)  # the exception
    # analyzer runs recorded for all three
    assert {r.name for r in features.analyzer_runs} == {"good", "missing_tool", "boom"}


# --- escalation (AC3) ---
def test_escalation_fires_on_packing_and_hidden_dex(malicious_features):
    # add a packer + dynamic-loader API so all escalation paths are exercised
    flag = detect_escalation(malicious_features)
    assert flag.escalate is True
    joined = " ".join(flag.reasons).lower()
    assert "dex" in joined  # asset-hidden DEX
    assert "obfuscation" in joined or "packer" in joined


def test_escalation_quiet_on_benign(benign_features):
    flag = detect_escalation(benign_features)
    assert flag.escalate is False
    assert flag.reasons == []


def test_escalation_detects_runtime_decryption_combo():
    from apkscan.schema import FeatureSet, IOCSet

    fs = FeatureSet(
        sample=_sample(),
        assets=[Asset(name="assets/c.dat", suspected_encrypted=True, entropy=7.8)],
        iocs=IOCSet(crypto_constants=["AES/CBC/PKCS5Padding"]),
    )
    flag = detect_escalation(fs)
    assert flag.escalate is True
    assert any("runtime decryption" in r.lower() for r in flag.reasons)
