"""Temporal validation and F1-based concept drift monitoring (Phase 1 / Plan 1.3).

Contains utilities to:
1. Chronologically split datasets to prevent lookahead bias.
2. Evaluate classification F1-score and flag drift if performance drops.
"""

import logging
from typing import List, Tuple

from apkscan.schema import FeatureSet

logger = logging.getLogger("apkscan.ml.monitor")


def temporal_train_test_split(
    samples: List[FeatureSet], test_ratio: float = 0.2
) -> Tuple[List[FeatureSet], List[FeatureSet]]:
    """Sort samples chronologically by ``created_at`` and split them.

    Parameters
    ----------
    samples : List[FeatureSet]
        The list of feature sets to split.
    test_ratio : float
        The ratio of samples to allocate to the test (future) set.

    Returns:
        Tuple[train_samples, test_samples]
    """
    if not samples:
        return [], []

    # Sort chronologically
    sorted_samples = sorted(samples, key=lambda s: s.created_at)

    split_idx = int(len(sorted_samples) * (1.0 - test_ratio))
    # Ensure at least 1 sample in train if samples is not empty
    if split_idx == 0 and len(sorted_samples) > 0:
        split_idx = 1

    return sorted_samples[:split_idx], sorted_samples[split_idx:]


def check_concept_drift(
    predictions: List[int], actual_labels: List[int], f1_threshold: float = 0.85
) -> Tuple[bool, float]:
    """Calculate F1-score and determine if classification performance has drifted.

    Parameters
    ----------
    predictions : List[int]
        Model prediction binary labels (0 or 1).
    actual_labels : List[int]
        Ground truth binary labels (0 or 1).
    f1_threshold : float
        The F1 score threshold below which drift is flagged.

    Returns:
        (drift_detected, f1_score)
    """
    if not predictions or not actual_labels or len(predictions) != len(actual_labels):
        return False, 0.0

    tp = sum(1 for p, a in zip(predictions, actual_labels) if p == 1 and a == 1)
    fp = sum(1 for p, a in zip(predictions, actual_labels) if p == 1 and a == 0)
    fn = sum(1 for p, a in zip(predictions, actual_labels) if p == 0 and a == 1)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2.0 * precision * recall / (precision + recall) if (precision + recall) > 0.0 else 0.0

    drift_detected = f1_score < f1_threshold

    if drift_detected:
        logger.warning(
            "CONCEPT DRIFT DETECTED: F1 score %.3f has fallen below threshold %.3f. "
            "Retraining recommended.",
            f1_score,
            f1_threshold,
        )

    return drift_detected, round(f1_score, 4)
