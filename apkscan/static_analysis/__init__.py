"""Static analysis: MobSF backbone + Androguard/APKiD/Quark/YARA/cert wrappers.

All wrappers degrade gracefully: a missing tool or unreachable service records an
``AnalysisGap`` and lowers confidence rather than aborting the pipeline
(IMPLEMENTATION_RULES.md §7). Heavy native libraries are imported lazily so the
deterministic core remains importable without them.
"""
