"""Model drift monitoring and temporal validation (Phase 1 / Plan 1.3).

Tracks prediction distributions over time windows and emits alerts when the
model's output profile shifts significantly.  Two complementary checks:

1. **Population Stability Index (PSI)**: compares the prediction distribution in
   the current window against a reference (training) distribution.
2. **Rule–ML divergence**: detects when the ML and rule layers persistently
   disagree (directional drift).

All state is stored on disk (JSON) so it survives restarts.
"""

import json
import logging
import math
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("apkscan.ml.drift")

# ── Constants ────────────────────────────────────────────────────────────────
PSI_WARN = 0.15
PSI_CRITICAL = 0.25
N_BINS = 10
WINDOW_SIZE = 200  # predictions per window


@dataclass
class DriftSnapshot:
    """One monitoring window."""

    timestamp: float
    n_samples: int
    psi: float
    mean_ml_score: float
    mean_rule_score: float
    divergence_rate: float  # fraction of cases where ML/rule disagree by >30pts
    alert: str = ""  # "", "warn", or "critical"


@dataclass
class DriftState:
    """Persistent drift-monitoring state."""

    reference_distribution: List[float] = field(default_factory=list)
    current_ml_scores: List[float] = field(default_factory=list)
    current_rule_scores: List[float] = field(default_factory=list)
    snapshots: List[DriftSnapshot] = field(default_factory=list)
    total_predictions: int = 0


class DriftMonitor:
    """Monitors ML model prediction drift."""

    def __init__(self, state_path: str = "data/drift_state.json") -> None:
        self._state_path = Path(state_path)
        self._state: DriftState = self._load_state()

    def _load_state(self) -> DriftState:
        if self._state_path.is_file():
            try:
                with open(self._state_path) as f:
                    data = json.load(f)
                snapshots = [DriftSnapshot(**s) for s in data.get("snapshots", [])]
                return DriftState(
                    reference_distribution=data.get("reference_distribution", []),
                    current_ml_scores=data.get("current_ml_scores", []),
                    current_rule_scores=data.get("current_rule_scores", []),
                    snapshots=snapshots,
                    total_predictions=data.get("total_predictions", 0),
                )
            except Exception:
                logger.warning("Could not load drift state; starting fresh")
        return DriftState()

    def _save_state(self) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "reference_distribution": self._state.reference_distribution,
            "current_ml_scores": self._state.current_ml_scores,
            "current_rule_scores": self._state.current_rule_scores,
            "snapshots": [asdict(s) for s in self._state.snapshots],
            "total_predictions": self._state.total_predictions,
        }
        with open(self._state_path, "w") as f:
            json.dump(data, f, indent=2)

    def set_reference(self, training_scores: List[float]) -> None:
        """Set the reference distribution from training predictions."""
        self._state.reference_distribution = _histogram(training_scores)
        self._save_state()
        logger.info("Reference distribution set from %d training scores", len(training_scores))

    def record(self, ml_score: float, rule_score: float) -> Optional[DriftSnapshot]:
        """Record a new prediction. Returns a ``DriftSnapshot`` if a window completed."""
        self._state.current_ml_scores.append(ml_score)
        self._state.current_rule_scores.append(rule_score)
        self._state.total_predictions += 1

        if len(self._state.current_ml_scores) >= WINDOW_SIZE:
            snapshot = self._evaluate_window()
            self._state.current_ml_scores.clear()
            self._state.current_rule_scores.clear()
            self._save_state()
            return snapshot

        # Save periodically (every 50 predictions)
        if self._state.total_predictions % 50 == 0:
            self._save_state()
        return None

    def _evaluate_window(self) -> DriftSnapshot:
        ml_scores = self._state.current_ml_scores
        rule_scores = self._state.current_rule_scores

        current_hist = _histogram(ml_scores)
        psi = _psi(self._state.reference_distribution, current_hist) if self._state.reference_distribution else 0.0

        mean_ml = sum(ml_scores) / len(ml_scores) if ml_scores else 0.0
        mean_rule = sum(rule_scores) / len(rule_scores) if rule_scores else 0.0

        divergent = sum(1 for m, r in zip(ml_scores, rule_scores) if abs(m - r) > 30.0)
        divergence_rate = divergent / len(ml_scores) if ml_scores else 0.0

        alert = ""
        if psi >= PSI_CRITICAL:
            alert = "critical"
            logger.error("DRIFT CRITICAL: PSI=%.3f — model retraining recommended", psi)
        elif psi >= PSI_WARN:
            alert = "warn"
            logger.warning("DRIFT WARNING: PSI=%.3f — monitor closely", psi)

        if divergence_rate > 0.3:
            if alert != "critical":
                alert = alert or "warn"
            logger.warning("DIVERGENCE: %.0f%% of predictions diverge from rules by >30pts",
                           divergence_rate * 100)

        snapshot = DriftSnapshot(
            timestamp=time.time(),
            n_samples=len(ml_scores),
            psi=round(psi, 4),
            mean_ml_score=round(mean_ml, 2),
            mean_rule_score=round(mean_rule, 2),
            divergence_rate=round(divergence_rate, 3),
            alert=alert,
        )
        self._state.snapshots.append(snapshot)
        return snapshot

    def get_status(self) -> Dict:
        """Return current monitoring status."""
        return {
            "total_predictions": self._state.total_predictions,
            "window_progress": f"{len(self._state.current_ml_scores)}/{WINDOW_SIZE}",
            "has_reference": bool(self._state.reference_distribution),
            "snapshots": len(self._state.snapshots),
            "latest_alert": self._state.snapshots[-1].alert if self._state.snapshots else "",
        }


def _histogram(scores: List[float], n_bins: int = N_BINS) -> List[float]:
    """Compute a normalized histogram over [0, 100]."""
    if not scores:
        return [1.0 / n_bins] * n_bins  # uniform prior
    bins = [0.0] * n_bins
    for s in scores:
        idx = min(int(s / (100.0 / n_bins)), n_bins - 1)
        bins[idx] += 1
    total = sum(bins) or 1
    return [b / total for b in bins]


def _psi(reference: List[float], current: List[float]) -> float:
    """Population Stability Index between two distributions."""
    eps = 1e-6
    psi = 0.0
    for r, c in zip(reference, current):
        r = max(r, eps)
        c = max(c, eps)
        psi += (c - r) * math.log(c / r)
    return psi
