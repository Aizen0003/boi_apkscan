"""ML model training, serialization, and inference (Phase 1 / T1.3).

Supports Random Forest (default) and XGBoost classifiers. All heavy ML imports
are lazy so the deterministic core remains importable without the ``ml`` extra.
"""

import logging
import pickle
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("apkscan.ml.trainer")


def train_classifier(X, y, *, model_type: str = "rf"):
    """Train a classifier on feature matrix *X* and label vector *y*.

    Parameters
    ----------
    model_type : str
        ``"rf"`` for Random Forest (default) or ``"xgb"`` for XGBoost.

    Returns the trained model (sklearn-compatible ``.predict_proba`` API).
    """
    if model_type == "xgb":
        try:
            from xgboost import XGBClassifier
        except ImportError:
            logger.warning("xgboost not installed, falling back to RandomForest")
            model_type = "rf"
        else:
            model = XGBClassifier(
                n_estimators=200,
                max_depth=6,
                learning_rate=0.1,
                eval_metric="logloss",
                use_label_encoder=False,
            )
            model.fit(X, y)
            return model

    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X, y)
    return model


def save_classifier(model, path: str) -> None:
    """Persist a trained model to disk."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        pickle.dump(model, f, protocol=pickle.HIGHEST_PROTOCOL)
    logger.info("Model saved to %s", p)


def load_classifier(path: str) -> Optional[object]:
    """Load a model from disk. Returns ``None`` if the file is absent."""
    p = Path(path)
    if not p.is_file():
        logger.warning("Model file not found at %s — ML layer disabled.", p)
        return None
    with open(p, "rb") as f:
        model = pickle.load(f)  # noqa: S301 — trusted internal file
    logger.info("Model loaded from %s", p)
    return model


def predict_threat_probability(model, feature_vector: List[float]) -> float:
    """Return the predicted malicious-class probability for a single sample.

    Returns 0.0 if the model is ``None`` or prediction fails.
    """
    if model is None:
        return 0.0
    try:
        import numpy as np

        x = np.array(feature_vector, dtype=np.float64).reshape(1, -1)
        proba = model.predict_proba(x)
        # malicious class is assumed to be label 1
        class_idx = list(model.classes_).index(1) if 1 in model.classes_ else -1
        if class_idx < 0:
            return 0.0
        return float(proba[0, class_idx])
    except Exception:
        logger.exception("ML prediction failed; returning 0.0")
        return 0.0
