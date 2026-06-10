"""GenAI interpretation layer (T0.9-T0.12).

Strictly an interpretation/assist layer. Guardrails enforced here:
  * untrusted-string isolation in every prompt path (T0.10)
  * per-function chunking, never silent truncation (T0.9)
  * grounded claims only — cited artifacts must exist (T0.12)
  * local model backend; commercial egress gated off by default
The output never carries verdict weight (enforced in fusion).
"""
