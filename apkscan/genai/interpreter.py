"""GenAI interpretation orchestrator (T0.9-T0.12).

Pipeline: chunk decompiled code -> retrieve trusted ATT&CK/TI context -> build an
isolation-hardened prompt -> call the local LLM -> parse -> ground every claim.
Degrades gracefully to an empty (generated=False) interpretation when the LLM is
disabled/unavailable, so the deterministic pipeline always completes. The output
never carries verdict weight (enforced in fusion).
"""

import json
import re
from typing import List, Optional, Sequence

from apkscan.config import Settings, get_settings
from apkscan.genai.chunking import CodeChunk, chunk_code
from apkscan.genai.grounding import ground_claims
from apkscan.genai.llm_client import CommercialLLMBlocked, LLMUnavailable, get_llm_client
from apkscan.genai.prompt import build_analysis_prompt
from apkscan.genai.rag import RagIndex, format_context, query_terms_from_features
from apkscan.schema import FeatureSet, GenAIClaim, GenAIInterpretation

_DEFAULT_INDEX: Optional[RagIndex] = None
_SUSPICIOUS = (
    "sms", "otp", "overlay", "accessibility", "dexclassloader", "cipher", "http",
    "firebase", "addview", "sendtextmessage", "abortbroadcast", "inject", "/gate", "c2",
)


def _default_index() -> RagIndex:
    global _DEFAULT_INDEX
    if _DEFAULT_INDEX is None:
        _DEFAULT_INDEX = RagIndex.build_default()
    return _DEFAULT_INDEX


def _suspicion(text: str) -> int:
    low = text.lower()
    return sum(low.count(tok) for tok in _SUSPICIOUS)


def _select_chunks(chunks: Sequence[CodeChunk], max_chunks: int) -> List[CodeChunk]:
    if len(chunks) <= max_chunks:
        return list(chunks)
    # keep the most suspicious chunks, but preserve original order in the prompt
    ranked = sorted(chunks, key=lambda c: (-_suspicion(c.text), c.index))[:max_chunks]
    return sorted(ranked, key=lambda c: c.index)


def _extract_json(content: str) -> Optional[dict]:
    if not content:
        return None
    text = content.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _degraded(reason: str) -> GenAIInterpretation:
    return GenAIInterpretation(generated=False, warnings=[reason])


def interpret(
    features: FeatureSet,
    code: str = "",
    *,
    settings: Optional[Settings] = None,
    client=None,
    rag_index: Optional[RagIndex] = None,
    max_chunks: int = 6,
) -> GenAIInterpretation:
    settings = settings or get_settings()
    if not settings.llm_enabled:
        return _degraded("LLM disabled (APKSCAN_LLM_ENABLED=false)")

    # acquire a client (gated against commercial egress)
    if client is None:
        try:
            client = get_llm_client(settings)
        except CommercialLLMBlocked as exc:
            return _degraded(str(exc))
        try:
            if not client.is_available():
                return _degraded("local LLM endpoint unavailable")
        except Exception as exc:  # noqa: BLE001
            return _degraded(f"local LLM endpoint error: {exc}")

    chunk_budget = min(1500, max(256, settings.llm_max_input_tokens // 4))
    all_chunks = chunk_code(code, max_tokens=chunk_budget)
    selected = _select_chunks(all_chunks, max_chunks)
    truncated_cap = len(all_chunks) > len(selected)

    index = rag_index or _default_index()
    docs = index.retrieve(query_terms_from_features(features), k=5)
    rag_context = format_context(docs)

    bundle = build_analysis_prompt(features, selected, rag_context)

    try:
        response = client.chat(bundle.messages)
    except LLMUnavailable as exc:
        return _degraded(f"LLM call failed: {exc}")

    warnings: List[str] = []
    if truncated_cap:
        warnings.append(
            f"sent {len(selected)}/{len(all_chunks)} code chunks (budget cap); "
            "interpretation may be partial"
        )
    if response.truncated:
        warnings.append("LLM reported context-length truncation (done_reason=length)")

    parsed = _extract_json(response.content)
    if parsed is None:
        warnings.append("LLM output was not parseable JSON; claims withheld")
        return GenAIInterpretation(
            generated=True,
            model_name=settings.llm_model,
            truncated=truncated_cap or response.truncated,
            chunks_total=len(all_chunks),
            chunks_sent=len(selected),
            prompt_injection_detected=bundle.injection_detected,
            rag_sources=[d.id for d in docs],
            warnings=warnings,
        )

    raw_claims = [
        GenAIClaim(
            text=str(c.get("text", "")).strip(),
            category=str(c.get("category", "behavior")).strip() or "behavior",
            artifact_refs=[str(x) for x in c.get("artifact_ids", []) if x],
            attack_techniques=[str(x) for x in c.get("attack_techniques", []) if x],
        )
        for c in (parsed.get("claims") or [])
        if str(c.get("text", "")).strip()
    ]
    grounding = ground_claims(raw_claims, features)

    attack_techniques: List[str] = []
    for claim in grounding.grounded:
        for tid in claim.attack_techniques:
            if tid not in attack_techniques:
                attack_techniques.append(tid)

    index_map = features.artifact_index()
    iocs: List[str] = []
    for claim in grounding.grounded:
        if claim.category == "ioc":
            for ref in claim.artifact_refs:
                if ref.startswith("ioc:") and index_map.get(ref) not in iocs:
                    iocs.append(index_map[ref])

    if grounding.withheld:
        warnings.append(f"withheld {len(grounding.withheld)} ungrounded claim(s)")

    return GenAIInterpretation(
        generated=True,
        model_name=settings.llm_model,
        summary=str(parsed.get("summary", "")).strip(),
        claims=grounding.grounded,
        withheld_claims=grounding.withheld,
        attack_techniques=attack_techniques,
        iocs=iocs,
        recommendations=[str(r).strip() for r in (parsed.get("recommendations") or []) if str(r).strip()],
        rag_sources=[d.id for d in docs],
        truncated=truncated_cap or response.truncated,
        chunks_total=len(all_chunks),
        chunks_sent=len(selected),
        prompt_injection_detected=bundle.injection_detected,
        grounding_failure_rate=grounding.failure_rate,
        warnings=warnings,
    )
