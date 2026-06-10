"""Local LLM client (Ollama) with truncation detection (T0.9).

Local-only by default. ``get_llm_client`` refuses any non-local backend unless
``commercial_llm_allowed`` is explicitly enabled (governance-gated). Inference is
deterministic (temperature 0). Ollama signals context-limit truncation via
``done_reason == "length"`` — surfaced as ``truncated`` so the interpreter can
re-chunk or flag rather than trust a cut-off response.
"""

from dataclasses import dataclass
from typing import List, Optional

import httpx

from apkscan.config import Settings, get_settings


class LLMUnavailable(Exception):
    pass


class CommercialLLMBlocked(Exception):
    """Raised when a commercial backend is requested but egress is disabled."""


@dataclass
class ChatResponse:
    content: str
    done_reason: Optional[str] = None
    eval_count: Optional[int] = None
    prompt_eval_count: Optional[int] = None

    @property
    def truncated(self) -> bool:
        return self.done_reason == "length"


class OllamaClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        timeout: float = 120.0,
        transport: Optional[httpx.BaseTransport] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(base_url=self.base_url, timeout=timeout, transport=transport)
            self._owns_client = True

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "OllamaClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def is_available(self) -> bool:
        try:
            resp = self._client.get("/api/tags")
            resp.raise_for_status()
            return True
        except httpx.HTTPError:
            return False

    def chat(self, messages: List[dict], temperature: float = 0.0) -> ChatResponse:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature},
        }
        try:
            resp = self._client.post("/api/chat", json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise LLMUnavailable(f"Ollama chat failed: {exc}") from exc
        data = resp.json()
        message = data.get("message") or {}
        return ChatResponse(
            content=message.get("content", ""),
            done_reason=data.get("done_reason"),
            eval_count=data.get("eval_count"),
            prompt_eval_count=data.get("prompt_eval_count"),
        )


def get_llm_client(settings: Optional[Settings] = None):
    """Factory enforcing the local-first / commercial-off governance posture."""

    settings = settings or get_settings()
    if settings.llm_backend in ("ollama", "vllm"):
        # vLLM exposes an OpenAI-compatible API; for the MVP we drive Ollama.
        return OllamaClient(base_url=settings.ollama_url, model=settings.llm_model,
                            timeout=float(settings.llm_timeout_seconds))
    # Any other backend is treated as commercial/external and gated.
    if not settings.commercial_llm_allowed:
        raise CommercialLLMBlocked(
            f"LLM backend '{settings.llm_backend}' is non-local and commercial egress "
            "is disabled (APKSCAN_ALLOW_COMMERCIAL_LLM=false)."
        )
    raise CommercialLLMBlocked(f"unsupported LLM backend: {settings.llm_backend}")
