"""Tests for ml_explainer.py (Plan 1.2)."""

import numpy as np
import pytest

from apkscan.scoring.ml_explainer import MLExplainer
from apkscan.scoring.ml_trainer import train_classifier


@pytest.fixture
def trained_model():
    rng = np.random.RandomState(42)
    X = rng.rand(100, 5)
    y = (X[:, 0] + X[:, 1] > 1.0).astype(int)
    model = train_classifier(X, y, model_type="rf")
    return model, X


def test_explainer_returns_attributions(trained_model):
    model, X = trained_model
    names = [f"f{i}" for i in range(5)]
    explainer = MLExplainer(model, names)
    attrs = explainer.explain_prediction(X[0].tolist())
    assert isinstance(attrs, dict)
    assert len(attrs) <= 5
    # all values are floats
    for v in attrs.values():
        assert isinstance(v, float)


def test_explainer_top_n(trained_model):
    model, X = trained_model
    names = [f"f{i}" for i in range(5)]
    explainer = MLExplainer(model, names)
    attrs = explainer.explain_prediction(X[0].tolist(), top_n=2)
    assert len(attrs) <= 2


def test_explainer_with_none_model():
    explainer = MLExplainer(None, ["a", "b"])
    attrs = explainer.explain_prediction([1.0, 2.0])
    assert attrs == {}


def test_format_explanation(trained_model):
    model, X = trained_model
    names = [f"f{i}" for i in range(5)]
    explainer = MLExplainer(model, names)
    attrs = explainer.explain_prediction(X[0].tolist())
    text = explainer.format_explanation(attrs)
    assert isinstance(text, str)
    if attrs:
        assert "(" in text  # contains formatted values


def test_format_empty_explanation():
    explainer = MLExplainer(None, [])
    text = explainer.format_explanation({})
    assert "No ML explanations" in text
