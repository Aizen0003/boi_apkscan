"""Runtime configuration.

Defaults encode the binding governance posture (IMPLEMENTATION_RULES.md):
on-prem, local-model-first, and **commercial LLM APIs off by default**. The
``commercial_llm_allowed`` guard is the single chokepoint any code must consult
before considering a non-local model backend.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="APKSCAN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["development", "test", "production"] = "development"
    secret_key: str = "dev-insecure-change-me"

    # --- datastores ---
    database_url: str = "postgresql+psycopg2://apkscan:apkscan@localhost:5432/apkscan"
    redis_url: str = "redis://localhost:6379/0"

    # --- object storage ---
    storage_backend: Literal["filesystem", "s3"] = "filesystem"
    storage_root: Path = Path("/var/lib/apkscan/storage")
    s3_endpoint: Optional[str] = None
    s3_bucket: str = "apkscan"
    s3_access_key: Optional[str] = None
    s3_secret_key: Optional[str] = None

    # --- MobSF (keep patched >= 4.4.6) ---
    mobsf_url: str = "http://localhost:8000"
    mobsf_api_key: str = ""
    mobsf_enabled: bool = True
    mobsf_min_version: str = "4.4.6"

    # --- local LLM ---
    llm_backend: Literal["ollama", "vllm"] = "ollama"
    ollama_url: str = "http://localhost:11434"
    # Default tier targets a 24 GB GPU; documented fallback for smaller GPUs.
    llm_model: str = "qwen2.5-coder:7b-instruct-q4_K_M"
    llm_max_input_tokens: int = 8192
    llm_timeout_seconds: int = 120
    llm_enabled: bool = True

    # --- commercial LLM egress: OFF by default (governance-gated exception) ---
    allow_commercial_llm: bool = False

    # --- scoring operating point ---
    operating_mode: Literal["balanced", "high_recall"] = "balanced"

    # --- ML layer (Phase 1; disabled by default until a trained model is present) ---
    ml_enabled: bool = False
    ml_model_path: str = "data/model.pkl"
    ml_fusion_weight: float = 0.3  # 0.0..1.0 — weight of ML score in fusion

    # --- retention / chain-of-custody ---
    retention_days: int = 365

    # --- dynamic analysis (Phase 2; gated on governance sign-off) ---
    dynamic_enabled: bool = False
    sandbox_backend: Literal["mobsf", "simulator"] = "simulator"
    sandbox_timeout: int = 60  # seconds; maximum wall-clock time per sample

    # --- auth ---
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 720

    @property
    def commercial_llm_allowed(self) -> bool:
        """The single chokepoint guarding non-local model egress."""

        return bool(self.allow_commercial_llm)

    @property
    def celery_eager(self) -> bool:
        """Run tasks inline (no broker) for local/CLI/test execution."""

        return self.env == "test"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    """Clear the cache (used by tests that mutate the environment)."""

    get_settings.cache_clear()
    return get_settings()
