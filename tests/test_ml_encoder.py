"""Tests for ml_encoder.py (Plan 1.1)."""

from apkscan.scoring.ml_encoder import FeatureEncoder


def test_encoder_produces_fixed_length_for_benign(benign_features):
    enc = FeatureEncoder()
    vec = enc.encode(benign_features)
    assert len(vec) == enc.n_features
    assert all(isinstance(v, float) for v in vec)


def test_encoder_produces_fixed_length_for_malicious(malicious_features):
    enc = FeatureEncoder()
    vec = enc.encode(malicious_features)
    assert len(vec) == enc.n_features


def test_encoder_sets_permission_bits_correctly(malicious_features):
    enc = FeatureEncoder()
    vec = enc.encode(malicious_features)
    names = enc.get_feature_names()
    idx_acc = names.index("perm:BIND_ACCESSIBILITY_SERVICE")
    idx_sms = names.index("perm:READ_SMS")
    assert vec[idx_acc] == 1.0
    assert vec[idx_sms] == 1.0


def test_encoder_sets_api_bits_correctly(malicious_features):
    enc = FeatureEncoder()
    vec = enc.encode(malicious_features)
    names = enc.get_feature_names()
    idx_sms_api = names.index("api:SmsManager")
    assert vec[idx_sms_api] == 1.0


def test_encoder_benign_has_low_signal(benign_features):
    enc = FeatureEncoder()
    vec = enc.encode(benign_features)
    names = enc.get_feature_names()
    # benign app should only have INTERNET set
    idx_internet = names.index("perm:INTERNET")
    assert vec[idx_internet] == 1.0
    # and high-risk permissions should be 0
    idx_acc = names.index("perm:BIND_ACCESSIBILITY_SERVICE")
    assert vec[idx_acc] == 0.0


def test_feature_names_length_matches_vector(benign_features):
    enc = FeatureEncoder()
    names = enc.get_feature_names()
    vec = enc.encode(benign_features)
    assert len(names) == len(vec)


def test_encoder_numeric_metrics(malicious_features):
    enc = FeatureEncoder()
    vec = enc.encode(malicious_features)
    names = enc.get_feature_names()
    idx_fs = names.index("file_size")
    assert vec[idx_fs] == float(malicious_features.sample.file_size)
    idx_nq = names.index("n_quark_behaviors")
    assert vec[idx_nq] == float(len(malicious_features.quark_behaviors))
    idx_ny = names.index("n_yara_matches")
    assert vec[idx_ny] == float(len(malicious_features.yara_matches))
