"""Optional jadx decompilation for GenAI code interpretation (graceful).

Produces Java source for per-function chunking. If jadx is unavailable the
pipeline proceeds with feature-only interpretation — decompilation is never a
hard dependency.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from apkscan.config import Settings, get_settings


def is_available() -> bool:
    return shutil.which("jadx") is not None


def decompile_apk(apk_path, settings: Optional[Settings] = None, max_chars: int = 200_000) -> str:
    settings = settings or get_settings()
    if not is_available():
        return ""
    try:
        with tempfile.TemporaryDirectory(prefix="apkscan-jadx-") as out:
            subprocess.run(
                ["jadx", "--no-res", "--no-imports", "-q", "-d", out, str(apk_path)],
                capture_output=True,
                text=True,
                timeout=600,
            )
            return _concat_sources(Path(out) / "sources", max_chars)
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _concat_sources(sources_dir: Path, max_chars: int) -> str:
    if not sources_dir.is_dir():
        return ""
    pieces = []
    total = 0
    for java in sorted(sources_dir.rglob("*.java")):
        try:
            text = java.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        header = f"\n// ==== {java.name} ====\n"
        pieces.append(header)
        pieces.append(text)
        total += len(text) + len(header)
        if total >= max_chars:
            break
    return "".join(pieces)[:max_chars]
