"""Operating-point policy: score -> verdict band + severity + sign-off.

Two coupled axes are derived deterministically from the 0..100 risk score:
  * verdict band  : Benign / Suspicious / Malicious   (AC4)
  * severity      : Low / Moderate / High / Critical   (sign-off trigger, AC7)

Thresholds are the exposed operating-point knob (TEST_PLAN: high-recall vs.
balanced). High-recall lowers the bars to catch more (more FPs, fewer FNs).
Sign-off is required for High/Critical severity (i.e. all Malicious verdicts).
"""

from dataclasses import dataclass
from typing import Tuple

from apkscan.schema import Severity, Verdict


@dataclass(frozen=True)
class Thresholds:
    benign_max: float       # score < benign_max  -> Low / Benign
    suspicious_max: float   # < suspicious_max    -> Moderate / Suspicious
    high_max: float         # < high_max          -> High / Malicious; else Critical / Malicious


_MODES = {
    "balanced": Thresholds(benign_max=25.0, suspicious_max=50.0, high_max=75.0),
    "high_recall": Thresholds(benign_max=15.0, suspicious_max=35.0, high_max=60.0),
}


def thresholds_for_mode(mode: str) -> Thresholds:
    return _MODES.get(mode, _MODES["balanced"])


def classify(score: float, mode: str = "balanced") -> Tuple[Verdict, Severity, bool]:
    t = thresholds_for_mode(mode)
    if score < t.benign_max:
        return Verdict.BENIGN, Severity.LOW, False
    if score < t.suspicious_max:
        return Verdict.SUSPICIOUS, Severity.MODERATE, False
    if score < t.high_max:
        return Verdict.MALICIOUS, Severity.HIGH, True
    return Verdict.MALICIOUS, Severity.CRITICAL, True
