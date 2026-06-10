"""APKiD analyzer — compiler/packer/obfuscator/anti-analysis detection.

Invokes the ``apkid`` CLI with JSON output and maps result categories to
``PackerDetection`` entries (compiler entries are ignored — they are not
malicious indicators).
"""

import json
import shutil
import subprocess
from typing import Dict

from apkscan.schema import PackerDetection
from apkscan.static_analysis.base import Analyzer, AnalyzerResult
from apkscan.static_analysis.errors import ToolUnavailable

# APKiD result category -> canonical PackerDetection.type
_CATEGORY_TYPES: Dict[str, str] = {
    "packer": "packer",
    "protector": "protector",
    "obfuscator": "obfuscator",
    "anti_vm": "anti_vm",
    "anti_debug": "anti_debug",
    "anti_disassembly": "anti_debug",
    "manipulator": "obfuscator",
    "dropper": "packer",
    "abnormal": "obfuscator",
    "embedded": "packer",
}


class ApkidAnalyzer(Analyzer):
    name = "apkid"

    def is_available(self) -> bool:
        return shutil.which("apkid") is not None

    def analyze(self, apk_path) -> AnalyzerResult:
        try:
            proc = subprocess.run(
                ["apkid", "--json", str(apk_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ToolUnavailable(f"apkid execution failed: {exc}") from exc

        result = AnalyzerResult()
        stdout = proc.stdout.strip()
        if not stdout:
            return result
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise ToolUnavailable(f"apkid produced non-JSON output: {exc}") from exc

        self.version = data.get("apkid_version")
        seen = set()
        for file_entry in data.get("files", []):
            for category, matches in (file_entry.get("results") or {}).items():
                if category == "compiler":
                    continue
                ptype = _CATEGORY_TYPES.get(category, "obfuscator")
                for match in matches:
                    if match in seen:
                        continue
                    seen.add(match)
                    result.packers.append(
                        PackerDetection(name=str(match), type=ptype, source="apkid")
                    )
        return result
