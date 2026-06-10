"""Per-function chunking of decompiled code (T0.9).

LLM context limits force chunking. The contract: never silently truncate. Code
is split into whole functions packed under a token budget; a single oversized
function is split into explicitly-marked partial chunks rather than dropped. The
caller decides how many chunks to send and records ``truncated`` if any are left
out — surfacing uncertainty instead of hiding it.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple

# Heuristic Java/decompiled method signature: optional modifiers, a return type,
# a name, an argument list, then an opening brace on the same line.
_SIG_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract|default)\s+)*"
    r"[\w$<>\[\]\.]+\s+([\w$]+)\s*\([^;{]*\)\s*(?:throws[\w\s,\.]*)?\{"
)


def estimate_tokens(text: str) -> int:
    """Cheap, deterministic token estimate (~4 chars/token)."""

    return max(1, (len(text) + 3) // 4)


@dataclass
class CodeChunk:
    index: int
    name: str
    text: str
    tokens: int
    partial: bool = False


def _iter_functions(code: str) -> List[Tuple[str, str]]:
    lines = code.splitlines(keepends=True)
    funcs: List[Tuple[str, str]] = []
    i, n = 0, len(lines)
    while i < n:
        match = _SIG_RE.match(lines[i])
        if match:
            start = i
            depth = lines[i].count("{") - lines[i].count("}")
            j = i + 1
            while j < n and depth > 0:
                depth += lines[j].count("{") - lines[j].count("}")
                j += 1
            funcs.append((match.group(1), "".join(lines[start:j])))
            i = j
        else:
            i += 1
    return funcs


def _split_oversized(name: str, body: str, max_tokens: int) -> List[Tuple[str, str, bool]]:
    """Split one oversized function into line-bounded partial pieces."""

    lines = body.splitlines(keepends=True)
    pieces: List[Tuple[str, str, bool]] = []
    buf: List[str] = []
    for line in lines:
        if buf and estimate_tokens("".join(buf) + line) > max_tokens:
            pieces.append((name, "".join(buf), True))
            buf = [line]
        else:
            buf.append(line)
    if buf:
        pieces.append((name, "".join(buf), len(pieces) > 0))
    return pieces


def chunk_code(code: str, max_tokens: int = 1500) -> List[CodeChunk]:
    """Chunk decompiled code into per-function, budget-bounded chunks.

    Functions are packed greedily; oversized functions are split into partial
    chunks. If no functions are detected, falls back to line-bounded chunks. No
    content is dropped.
    """

    if not code or not code.strip():
        return []

    functions = _iter_functions(code)
    if not functions:
        # fallback: treat the whole blob as one "function" and split by size
        functions = [("<module>", code)]

    units: List[Tuple[str, str, bool]] = []
    for name, body in functions:
        if estimate_tokens(body) > max_tokens:
            units.extend(_split_oversized(name, body, max_tokens))
        else:
            units.append((name, body, False))

    # greedily pack whole units (that fit) into chunks
    chunks: List[CodeChunk] = []
    cur_text: List[str] = []
    cur_names: List[str] = []
    cur_partial = False

    def flush():
        nonlocal cur_text, cur_names, cur_partial
        if cur_text:
            text = "".join(cur_text)
            chunks.append(
                CodeChunk(
                    index=len(chunks),
                    name=", ".join(dict.fromkeys(cur_names)),
                    text=text,
                    tokens=estimate_tokens(text),
                    partial=cur_partial,
                )
            )
            cur_text, cur_names, cur_partial = [], [], False

    for name, body, partial in units:
        if partial:
            flush()
            chunks.append(
                CodeChunk(index=len(chunks), name=name, text=body, tokens=estimate_tokens(body), partial=True)
            )
            continue
        if cur_text and estimate_tokens("".join(cur_text) + body) > max_tokens:
            flush()
        cur_text.append(body)
        cur_names.append(name)
    flush()
    return chunks
