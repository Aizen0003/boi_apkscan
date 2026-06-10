"""Hybrid scoring engine.

Layered and auditable (RESEARCH.md / IMPLEMENTATION_RULES.md):
  1. deterministic rule layer  — primary, reproducible evidence (T0.8)
  2. ML layer                  — probability + SHAP (Phase 1 seam)
  3. GenAI explanation         — explanatory only, never decides
  4. fusion                    — score + verdict band + confidence + evidence log (T0.13)
"""

from apkscan.scoring.fusion import fuse
from apkscan.scoring.policy import classify, thresholds_for_mode
from apkscan.scoring.rule_engine import RuleResult, score_rules

__all__ = ["RuleResult", "score_rules", "classify", "thresholds_for_mode", "fuse"]
