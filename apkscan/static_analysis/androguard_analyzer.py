"""Androguard analyzer — the authoritative manifest/DEX/cert/asset parser.

Extracts permissions (+ protection level), components (+ exported/intent),
certificates, native libs, assets (with entropy + DEX-magic checks), sensitive
API references, and a filtered set of interesting strings. Imported lazily; if
androguard is absent the extractor records a gap.
"""

import hashlib
from pathlib import Path
from typing import List, Optional, Tuple

from apkscan.schema import Asset, Certificate, Component, NativeLib, Permission
from apkscan.static_analysis.base import Analyzer, AnalyzerResult
from apkscan.static_analysis.errors import ToolUnavailable
from apkscan.static_analysis.heuristics import is_dex_magic, looks_encrypted, shannon_entropy

# (class regex, method regex, canonical label) for sensitive API discovery.
_SENSITIVE_APIS: Tuple[Tuple[str, str, str], ...] = (
    ("Landroid/telephony/SmsManager;", "sendTextMessage", "SmsManager.sendTextMessage"),
    ("Landroid/telephony/SmsManager;", "sendMultipartTextMessage", "SmsManager.sendMultipartTextMessage"),
    ("Landroid/telephony/TelephonyManager;", "getDeviceId", "TelephonyManager.getDeviceId"),
    ("Landroid/telephony/TelephonyManager;", "getSubscriberId", "TelephonyManager.getSubscriberId"),
    ("Ldalvik/system/DexClassLoader;", "<init>", "DexClassLoader.<init>"),
    ("Ldalvik/system/PathClassLoader;", "<init>", "PathClassLoader.<init>"),
    ("Ldalvik/system/InMemoryDexClassLoader;", "<init>", "InMemoryDexClassLoader.<init>"),
    ("Landroid/app/admin/DevicePolicyManager;", "lockNow", "DevicePolicyManager.lockNow"),
    ("Landroid/app/admin/DevicePolicyManager;", "wipeData", "DevicePolicyManager.wipeData"),
    ("Landroid/view/WindowManager;", "addView", "WindowManager.addView"),
    ("Landroid/media/projection/MediaProjectionManager;", "createScreenCaptureIntent", "MediaProjection.createScreenCaptureIntent"),
    ("Ljavax/crypto/Cipher;", "getInstance", "Cipher.getInstance"),
    ("Ljava/lang/Runtime;", "exec", "Runtime.exec"),
    ("Landroid/content/pm/PackageManager;", "getInstalledPackages", "PackageManager.getInstalledPackages"),
)

_SUSPICIOUS_TOKENS = (
    "http://", "https://", "ftp://", ".php", "/gate", "/c2", "firebase", "bot", "token",
    "/api/", "sms", "otp", "overlay", "inject", "accessibility", "/upload", "telegram",
)


def _interesting_string(value: str) -> bool:
    if len(value) < 6:
        return False
    low = value.lower()
    if any(tok in low for tok in _SUSPICIOUS_TOKENS):
        return True
    return "://" in value or value.count(".") >= 2


class AndroguardAnalyzer(Analyzer):
    name = "androguard"
    max_strings = 3000

    def is_available(self) -> bool:
        try:
            import androguard  # noqa: F401

            self.version = getattr(androguard, "__version__", None)
            return True
        except Exception:  # noqa: BLE001
            return False

    def analyze(self, apk_path) -> AnalyzerResult:
        try:
            from androguard.misc import AnalyzeAPK
        except Exception as exc:  # noqa: BLE001
            raise ToolUnavailable(f"androguard import failed: {exc}") from exc

        apk, _dex, analysis = AnalyzeAPK(str(apk_path))
        result = AnalyzerResult()
        self._sample(apk, result)
        self._permissions(apk, result)
        self._components(apk, result)
        self._certificates(apk, result)
        self._native_and_assets(apk, result)
        self._apis(analysis, result)
        self._strings(apk, analysis, result)
        return result

    # -- sub-extractors (each guarded so partial failure degrades) --
    def _sample(self, apk, result: AnalyzerResult) -> None:
        try:
            result.sample = {
                "package_name": apk.get_package(),
                "version_name": apk.get_androidversion_name(),
                "version_code": _safe_int(apk.get_androidversion_code()),
                "min_sdk": _safe_int(apk.get_min_sdk_version()),
                "target_sdk": _safe_int(apk.get_target_sdk_version()),
                "main_activity": apk.get_main_activity(),
            }
        except Exception:  # noqa: BLE001
            pass

    def _permissions(self, apk, result: AnalyzerResult) -> None:
        try:
            details = {}
            try:
                details = apk.get_details_permissions() or {}
            except Exception:  # noqa: BLE001
                details = {}
            for name in apk.get_permissions():
                level = None
                info = details.get(name)
                if isinstance(info, (list, tuple)) and info:
                    level = str(info[0])
                result.permissions.append(
                    Permission(name=name, protection_level=level, maybe_custom=not name.startswith("android.permission."))
                )
        except Exception:  # noqa: BLE001
            pass

    def _components(self, apk, result: AnalyzerResult) -> None:
        getters = (
            ("activity", apk.get_activities),
            ("service", apk.get_services),
            ("receiver", apk.get_receivers),
            ("provider", apk.get_providers),
        )
        for ctype, getter in getters:
            try:
                for name in getter():
                    result.components.append(
                        Component(
                            name=name,
                            type=ctype,
                            exported=_safe_exported(apk, name),
                            intent_actions=_intent_actions(apk, name, ctype),
                        )
                    )
            except Exception:  # noqa: BLE001
                continue

    def _certificates(self, apk, result: AnalyzerResult) -> None:
        try:
            for der in apk.get_certificates_der_v2() if hasattr(apk, "get_certificates_der_v2") else []:
                result.certificates.append(_summarize_cert(der))
            if not result.certificates:
                for cert in apk.get_certificates():
                    result.certificates.append(_summarize_cert(cert.dump()))
        except Exception:  # noqa: BLE001
            pass

    def _native_and_assets(self, apk, result: AnalyzerResult) -> None:
        try:
            for fname in apk.get_files():
                if fname.startswith("lib/") and fname.endswith(".so"):
                    arch = fname.split("/")[1] if "/" in fname else None
                    result.native_libs.append(
                        NativeLib(name=fname, architectures=[arch] if arch else [])
                    )
                elif fname.startswith("assets/"):
                    data = b""
                    try:
                        data = apk.get_file(fname)
                    except Exception:  # noqa: BLE001
                        data = b""
                    entropy = shannon_entropy(data[:65536]) if data else 0.0
                    result.assets.append(
                        Asset(
                            name=fname,
                            size=len(data) if data else None,
                            entropy=round(entropy, 3),
                            suspected_encrypted=looks_encrypted(entropy),
                            suspected_dex=is_dex_magic(data[:8]) if data else False,
                        )
                    )
        except Exception:  # noqa: BLE001
            pass

    def _apis(self, analysis, result: AnalyzerResult) -> None:
        for class_re, method_re, label in _SENSITIVE_APIS:
            try:
                for meth in analysis.find_methods(classname=class_re, methodname=method_re):
                    callers = list(meth.get_xref_from())
                    caller = None
                    if callers:
                        cls, method, _ = callers[0]
                        caller = f"{cls.name}->{method.name}"
                    result.raw_apis.append((label, caller))
                    break  # one reference per label is enough for features
            except Exception:  # noqa: BLE001
                continue

    def _strings(self, apk, analysis, result: AnalyzerResult) -> None:
        count = 0
        try:
            for s in analysis.get_strings():
                value = s.get_value() if hasattr(s, "get_value") else str(s)
                if _interesting_string(value):
                    result.raw_strings.append((value, "dex"))
                    count += 1
                    if count >= self.max_strings:
                        break
        except Exception:  # noqa: BLE001
            pass


def _safe_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_exported(apk, name) -> Optional[bool]:
    try:
        element = apk.get_element("activity", "exported", name=name)
        if element is not None:
            return str(element).lower() == "true"
    except Exception:  # noqa: BLE001
        pass
    return None


def _intent_actions(apk, name, ctype) -> List[str]:
    try:
        filters = apk.get_intent_filters(ctype, name) or {}
        return list(filters.get("action", []))
    except Exception:  # noqa: BLE001
        return []


def _summarize_cert(der: bytes) -> Certificate:
    sha1 = hashlib.sha1(der).hexdigest()
    sha256 = hashlib.sha256(der).hexdigest()
    subject = issuer = serial = pubalg = sigalg = None
    not_before = not_after = None
    key_size = None
    try:
        from asn1crypto import x509  # ships with androguard

        cert = x509.Certificate.load(der)
        subject = cert.subject.human_friendly
        issuer = cert.issuer.human_friendly
        serial = str(cert.serial_number)
        validity = cert["tbs_certificate"]["validity"]
        not_before = str(validity["not_before"].native)
        not_after = str(validity["not_after"].native)
        pubalg = cert.public_key.algorithm
        sigalg = cert.signature_algo
        try:
            key_size = cert.public_key.bit_size
        except Exception:  # noqa: BLE001
            key_size = None
    except Exception:  # noqa: BLE001
        pass
    return Certificate(
        subject=subject,
        issuer=issuer,
        serial_number=serial,
        sha1=sha1,
        sha256=sha256,
        not_before=not_before,
        not_after=not_after,
        self_signed=bool(subject and issuer and subject == issuer),
        is_debug=bool(subject and "Android Debug" in subject),
        public_key_algorithm=pubalg,
        key_size=key_size,
        signature_algorithm=sigalg,
    )
