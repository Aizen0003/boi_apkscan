"""Local RAG over ATT&CK + internal threat intel (T0.11).

Fully on-prem: a small TF-IDF retriever over the ATT&CK v19.1 technique catalog
plus the internal threat-intel corpus (``data/threat_intel``). No external
embeddings or services. Retrieved context is *trusted* and grounds the GenAI
explanation (and keeps its ATT&CK references aligned to the verified IDs).
"""

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from apkscan.attack.techniques import TECHNIQUES, TACTICS
from apkscan.schema import FeatureSet

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> List[str]:
    return _TOKEN_RE.findall(text.lower())


@dataclass(frozen=True)
class Document:
    id: str
    title: str
    text: str
    source: str  # "attack" | "threat_intel"


def _threat_intel_dir() -> Optional[Path]:
    for cand in (
        os.environ.get("APKSCAN_THREAT_INTEL"),
        "/opt/apkscan/threat_intel",
        str(Path(__file__).resolve().parents[2] / "data" / "threat_intel"),
    ):
        if cand and Path(cand).is_dir():
            return Path(cand)
    return None


def _attack_documents() -> List[Document]:
    docs = []
    for tid, tech in TECHNIQUES.items():
        tactics = ", ".join(TACTICS.get(t, t) for t in tech.tactics)
        docs.append(
            Document(
                id=f"attack:{tid}",
                title=f"{tid} {tech.name}",
                text=f"{tid} {tech.name}. Tactics: {tactics}. ATT&CK for Mobile technique.",
                source="attack",
            )
        )
    return docs


def _threat_intel_documents() -> List[Document]:
    docs: List[Document] = []
    directory = _threat_intel_dir()
    if directory is None:
        return docs
    for path in sorted(directory.glob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        # split into sections on markdown headings for finer retrieval
        sections = re.split(r"\n(?=#{1,6}\s)", text)
        for i, section in enumerate(sections):
            section = section.strip()
            if not section:
                continue
            title_line = section.splitlines()[0].lstrip("# ").strip()
            docs.append(
                Document(
                    id=f"ti:{path.stem}#{i}",
                    title=title_line or path.stem,
                    text=section,
                    source="threat_intel",
                )
            )
    return docs


class RagIndex:
    def __init__(self, documents: Sequence[Document]) -> None:
        self.documents = list(documents)
        self._doc_tokens: List[List[str]] = [_tokens(f"{d.title} {d.text}") for d in self.documents]
        self._df: Dict[str, int] = {}
        for tokens in self._doc_tokens:
            for term in set(tokens):
                self._df[term] = self._df.get(term, 0) + 1
        self._n = max(1, len(self.documents))

    @classmethod
    def build_default(cls) -> "RagIndex":
        return cls(_attack_documents() + _threat_intel_documents())

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        return math.log((self._n + 1) / (df + 1)) + 1.0

    def retrieve(self, query_terms: Sequence[str], k: int = 5) -> List[Document]:
        if not self.documents:
            return []
        q = [t.lower() for t in query_terms if t]
        scored = []
        for doc, tokens in zip(self.documents, self._doc_tokens):
            if not tokens:
                continue
            counts: Dict[str, int] = {}
            for tok in tokens:
                counts[tok] = counts.get(tok, 0) + 1
            score = 0.0
            for term in q:
                tf = counts.get(term, 0)
                if tf:
                    score += (tf / len(tokens)) * self._idf(term)
            if score > 0:
                scored.append((score, doc))
        # deterministic order: score desc, then id asc
        scored.sort(key=lambda x: (-x[0], x[1].id))
        return [doc for _, doc in scored[:k]]


def query_terms_from_features(features: FeatureSet) -> List[str]:
    """Build a retrieval query from the salient features."""

    terms: List[str] = []
    for perm in features.permissions:
        terms.append(perm.name.split(".")[-1])
    for q in features.quark_behaviors:
        terms.extend(_tokens(q.crime))
    for y in features.yara_matches:
        terms.append(y.rule)
        terms.extend(y.tags)
    for pk in features.packers:
        terms.append(pk.type)
    if features.iocs.firebase_urls:
        terms.append("firebase")
    if features.escalation.escalate:
        terms.extend(["obfuscation", "packing", "dynamic", "encrypted"])
    return terms


def format_context(documents: Sequence[Document]) -> str:
    return "\n".join(f"- [{d.id}] {d.title}: {_first_sentence(d.text)}" for d in documents)


def _first_sentence(text: str) -> str:
    body = " ".join(text.replace("\n", " ").split())
    # skip a leading markdown heading token
    body = re.sub(r"^#+\s*", "", body)
    parts = re.split(r"(?<=[.!?])\s", body)
    return parts[0][:300] if parts else body[:300]
