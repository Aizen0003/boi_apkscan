"""APKScan — self-hosted Android banking-malware analysis & risk-scoring system.

MVP scope (Phase 0): static analysis + grounded local-LLM interpretation +
deterministic hybrid scoring + auditable reporting. The ML layer (Phase 1) and
dynamic sandbox (Phase 2) are modular seams, not MVP dependencies.

Binding guardrails (see IMPLEMENTATION_RULES.md):
  * GenAI explains, the deterministic rule layer decides.
  * On-prem / local-model-first; commercial LLM APIs off by default.
  * All APK-derived strings are untrusted data, never instructions.
  * Every verdict traces to a logged evidence list.
"""

__version__ = "0.1.0"
