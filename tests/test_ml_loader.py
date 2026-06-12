"""Tests for ml_loader.py (Plan 1.1)."""

import json
import pytest
import numpy as np

from apkscan.scoring.ml_loader import load_dataset
from apkscan.schema import FeatureSet


def test_load_dataset_empty_dir(tmp_path):
    X, y, names = load_dataset(str(tmp_path))
    assert X.shape == (0, 42)
    assert y.shape == (0,)
    assert len(names) == 42


def test_load_dataset_with_files(tmp_path, benign_features, malicious_features):
    # Save benign features with filename hint
    benign_path = tmp_path / "sample_benign.json"
    with open(benign_path, "w") as f:
        # Pydantic dump
        f.write(benign_features.model_dump_json())

    # Save malicious features in a report structure
    malicious_path = tmp_path / "sample_malicious.json"
    report_data = {
        "verdict": "Malicious",
        "features": json.loads(malicious_features.model_dump_json())
    }
    with open(malicious_path, "w") as f:
        json.dump(report_data, f)

    # Load dataset
    X, y, names = load_dataset(str(tmp_path))
    assert X.shape == (2, 42)
    assert y.shape == (2,)
    
    # We should have one benign (0) and one malicious (1)
    # The order depends on rglob, so check values exist
    assert 0 in y
    assert 1 in y
    assert len(names) == 42
