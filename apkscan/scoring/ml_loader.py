"""Dataset loader for ML training (Phase 1 / Plan 1.1).

Scans a directory of analysis JSON files, parses them into ``FeatureSet``
objects, encodes them, and extracts the target labels.
"""

import json
import logging
from pathlib import Path
from typing import List, Tuple

from apkscan.schema import FeatureSet
from apkscan.scoring.ml_encoder import FeatureEncoder

logger = logging.getLogger("apkscan.ml.loader")


def load_dataset(directory_path: str) -> Tuple["np.ndarray", "np.ndarray", List[str]]:
    """Scan a directory of JSON reports/features, encode them and extract labels.

    Labels are derived as:
        - 1 (Malicious / Suspicious)
        - 0 (Benign)
    Based on the verdict key in the JSON, or filename hint (e.g. if 'benign'
    or 'malicious' is in the filename).

    Returns:
        (X, y, feature_names) where X and y are numpy arrays.
    """
    import numpy as np  # lazy import

    dir_path = Path(directory_path)
    if not dir_path.is_dir():
        raise ValueError(f"Directory {directory_path} does not exist.")

    encoder = FeatureEncoder()
    X_list = []
    y_list = []

    # Find all .json files recursively
    for file_path in dir_path.rglob("*.json"):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            logger.warning("Failed to parse JSON file: %s", file_path, exc_info=True)
            continue

        # Try to extract FeatureSet
        features = None
        # Case A: File is a raw FeatureSet
        try:
            features = FeatureSet.model_validate(data)
        except Exception:
            # Case B: File is a full report containing features key
            if isinstance(data, dict) and "features" in data:
                try:
                    features = FeatureSet.model_validate(data["features"])
                except Exception:
                    pass

        if features is None:
            logger.warning("Could not extract FeatureSet from: %s", file_path)
            continue

        # Try to determine label:
        # 1. From explicit "verdict" or "label" in report JSON
        label = None
        if isinstance(data, dict):
            # Check verdict (from ScoreResult or top-level)
            v = data.get("verdict")
            if not v and "score" in data and isinstance(data["score"], dict):
                v = data["score"].get("verdict")

            if v:
                v_str = str(v).lower()
                if v_str in ("malicious", "suspicious"):
                    label = 1
                elif v_str == "benign":
                    label = 0

            if label is None:
                lbl = data.get("label")
                if lbl is not None:
                    if str(lbl).lower() in ("malicious", "suspicious", "1", "true"):
                        label = 1
                    else:
                        label = 0

        # 2. Hint from filename
        if label is None:
            name_lower = file_path.name.lower()
            if "malicious" in name_lower or "suspicious" in name_lower:
                label = 1
            elif "benign" in name_lower:
                label = 0

        # Default fallback: 0
        if label is None:
            label = 0

        # Encode features
        vec = encoder.encode(features)
        X_list.append(vec)
        y_list.append(label)

    if not X_list:
        # Return empty numpy arrays if no samples were loaded
        return (
            np.empty((0, encoder.n_features), dtype=np.float64),
            np.empty((0,), dtype=np.int64),
            encoder.get_feature_names(),
        )

    X = np.array(X_list, dtype=np.float64)
    y = np.array(y_list, dtype=np.int64)
    return X, y, encoder.get_feature_names()
