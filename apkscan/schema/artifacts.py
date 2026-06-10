"""Canonical artifact-identity scheme.

Every *citable* artifact extracted from an APK gets a stable, deterministic id of
the form ``<kind>:<key>``. These ids are the anchor for two guardrails:

  * **Grounding (T0.12):** every material GenAI claim must cite an artifact id
    that actually exists in the extracted feature set, otherwise the claim is
    withheld/flagged.
  * **Evidence (T0.16):** every deterministic indicator references the artifact
    ids it is derived from, so a verdict is fully traceable.

Ids are intentionally human-readable and stable for the same input so reports
and audit logs are reproducible.
"""

from enum import Enum


class ArtifactKind(str, Enum):
    """Kinds of citable artifacts. The string value is the id prefix."""

    PERMISSION = "perm"
    COMPONENT = "component"
    STRING = "str"
    API = "api"
    IOC = "ioc"
    CERTIFICATE = "cert"
    ASSET = "asset"
    NATIVE_LIB = "lib"
    YARA = "yara"
    QUARK = "quark"
    PACKER = "packer"
    DYNAMIC = "dyn"


def make_artifact_id(kind: ArtifactKind, *parts: object) -> str:
    """Build a canonical artifact id ``<kind>:<part>[:<part>...]``.

    Parts are stringified and ``:`` inside a part is escaped to ``∶`` (U+2236)
    so the id stays unambiguously splittable. Whitespace is collapsed so an
    untrusted string value cannot inject newlines into an id.
    """

    safe_parts = []
    for part in parts:
        text = str(part).replace(":", "∶")
        text = " ".join(text.split())  # collapse all whitespace runs to single space
        safe_parts.append(text)
    return ":".join([kind.value, *safe_parts])
