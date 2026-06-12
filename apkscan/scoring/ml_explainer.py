"""SHAP-based ML explanation layer (Phase 1 / T1.4).

Produces human-readable feature-importance attributions for each prediction.
Falls back to a feature-weight approximation when SHAP is unavailable.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger("apkscan.ml.explainer")


class MLExplainer:
    """Explain individual ML predictions with SHAP or a fallback method."""

    def __init__(self, model, feature_names: List[str]) -> None:
        self._model = model
        self._feature_names = feature_names
        self._shap_explainer: Optional[object] = None
        self._fallback = False

        try:
            import shap  # noqa: F401

            self._shap_explainer = shap.TreeExplainer(model)
            logger.info("SHAP TreeExplainer initialized")
        except Exception:
            logger.warning("SHAP unavailable — using feature-importance fallback")
            self._fallback = True

    def explain_prediction(
        self, feature_vector: List[float], *, top_n: int = 5
    ) -> Dict[str, float]:
        """Return a map of ``feature_name → attribution`` for the top-*n* features.

        Positive values push toward malicious; negative values push toward benign.
        """
        if self._model is None:
            return {}

        try:
            if not self._fallback and self._shap_explainer is not None:
                return self._explain_shap(feature_vector, top_n)
            return self._explain_fallback(feature_vector, top_n)
        except Exception:
            logger.exception("Explanation failed; returning empty attributions")
            return {}

    def _explain_shap(
        self, feature_vector: List[float], top_n: int
    ) -> Dict[str, float]:
        import numpy as np

        x = np.array(feature_vector, dtype=np.float64).reshape(1, -1)
        shap_values = self._shap_explainer.shap_values(x)

        # For binary classification, shap_values may be a list of arrays
        if isinstance(shap_values, list):
            # malicious class is index 1
            vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
        else:
            vals = shap_values[0]

        indexed = list(zip(self._feature_names, vals))
        indexed.sort(key=lambda t: abs(t[1]), reverse=True)
        return {name: round(float(val), 4) for name, val in indexed[:top_n]}

    def _explain_fallback(
        self, feature_vector: List[float], top_n: int
    ) -> Dict[str, float]:
        """Simplified explanation using feature importances × feature value."""
        try:
            importances = self._model.feature_importances_
        except AttributeError:
            return {}

        weighted = []
        for i, (name, imp) in enumerate(zip(self._feature_names, importances)):
            contribution = float(imp) * float(feature_vector[i])
            weighted.append((name, round(contribution, 4)))

        weighted.sort(key=lambda t: abs(t[1]), reverse=True)
        return dict(weighted[:top_n])

    def format_explanation(self, attributions: Dict[str, float]) -> str:
        """Format attributions into a human-readable string."""
        if not attributions:
            return "No ML explanations available."
        parts = []
        for name, val in attributions.items():
            sign = "+" if val >= 0 else ""
            parts.append(f"{name} ({sign}{val:.3f})")
        return ", ".join(parts)
