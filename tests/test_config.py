"""Config governance-posture tests (T0.1 / NFR1).

The defaults must encode: commercial LLM egress OFF, dynamic analysis OFF,
on-prem datastores, local model backend.
"""

from apkscan.config import Settings


def _defaults() -> Settings:
    # Ignore any local .env so we assert the *code* defaults.
    return Settings(_env_file=None)


def test_commercial_llm_off_by_default():
    s = _defaults()
    assert s.allow_commercial_llm is False
    assert s.commercial_llm_allowed is False


def test_dynamic_analysis_off_by_default():
    assert _defaults().dynamic_enabled is False


def test_local_model_first_defaults():
    s = _defaults()
    assert s.llm_backend == "ollama"
    assert s.llm_enabled is True
    # The default model string is a local Ollama tag, never a commercial model.
    assert "qwen2.5-coder" in s.llm_model


def test_storage_is_on_prem_by_default():
    assert _defaults().storage_backend == "filesystem"


def test_mobsf_min_version_guard_present():
    # The patch-level floor from IMPLEMENTATION_RULES (>= 4.4.6).
    assert _defaults().mobsf_min_version == "4.4.6"


def test_operating_mode_default_is_balanced():
    assert _defaults().operating_mode == "balanced"
