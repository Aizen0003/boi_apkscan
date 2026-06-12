"""Tests for ml_trainer.py (Plan 1.2)."""

import numpy as np
import pytest

from apkscan.scoring.ml_trainer import (
    load_classifier,
    predict_threat_probability,
    save_classifier,
    train_classifier,
)


@pytest.fixture
def dummy_data():
    rng = np.random.RandomState(42)
    X = rng.rand(100, 10)
    y = (X[:, 0] + X[:, 1] > 1.0).astype(int)
    return X, y


def test_train_rf(dummy_data):
    X, y = dummy_data
    model = train_classifier(X, y, model_type="rf")
    assert hasattr(model, "predict_proba")
    assert hasattr(model, "classes_")


def test_save_and_load(tmp_path, dummy_data):
    X, y = dummy_data
    model = train_classifier(X, y)
    path = str(tmp_path / "model.pkl")
    save_classifier(model, path)
    loaded = load_classifier(path)
    assert loaded is not None
    # predictions should match
    orig = model.predict_proba(X[:5])
    reloaded = loaded.predict_proba(X[:5])
    np.testing.assert_allclose(orig, reloaded, rtol=1e-14)


def test_load_missing_returns_none(tmp_path):
    result = load_classifier(str(tmp_path / "nonexistent.pkl"))
    assert result is None


def test_predict_returns_probability(dummy_data):
    X, y = dummy_data
    model = train_classifier(X, y)
    prob = predict_threat_probability(model, X[0].tolist())
    assert 0.0 <= prob <= 1.0


def test_predict_with_none_model():
    prob = predict_threat_probability(None, [0.0] * 10)
    assert prob == 0.0


def test_train_xgb(dummy_data):
    X, y = dummy_data
    try:
        model = train_classifier(X, y, model_type="xgb")
        assert hasattr(model, "predict_proba")
    except ImportError:
        pytest.skip("xgboost not installed")
