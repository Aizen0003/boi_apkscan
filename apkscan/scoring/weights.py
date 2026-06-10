"""Deterministic scoring weights (the rule layer's transparent parameters).

These tables are the audited, reproducible knobs of the primary verdict source.
Anchors match RESEARCH.md (accessibility/device-admin/install = 10, READ_SMS /
RECORD_AUDIO = 9, INTERNET+READ_SMS combination bonus, etc.). Every weight maps
to an explicit evidence item; nothing is hidden.
"""

from typing import Dict, FrozenSet, List, Tuple

# --- single-permission weights ---
PERMISSION_WEIGHTS: Dict[str, float] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 10,
    "android.permission.BIND_DEVICE_ADMIN": 10,
    "android.permission.REQUEST_INSTALL_PACKAGES": 10,
    "android.permission.READ_SMS": 9,
    "android.permission.RECORD_AUDIO": 9,
    "android.permission.WRITE_SMS": 7,
    "android.permission.RECEIVE_SMS": 8,
    "android.permission.SEND_SMS": 8,
    "android.permission.SYSTEM_ALERT_WINDOW": 7,
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": 6,
    "android.permission.READ_CALL_LOG": 4,
    "android.permission.PROCESS_OUTGOING_CALLS": 5,
    "android.permission.QUERY_ALL_PACKAGES": 5,
    "android.permission.READ_PHONE_STATE": 4,
    "android.permission.READ_CONTACTS": 4,
    "android.permission.CAMERA": 3,
    "android.permission.GET_TASKS": 3,
    "android.permission.PACKAGE_USAGE_STATS": 3,
    "android.permission.DISABLE_KEYGUARD": 3,
    "android.permission.CALL_PHONE": 3,
    "android.permission.RECEIVE_BOOT_COMPLETED": 2,
    "android.permission.WRITE_EXTERNAL_STORAGE": 1,
    "android.permission.INTERNET": 1,
    "android.permission.FOREGROUND_SERVICE": 1,
}

# --- dangerous permission combinations (bonus on top of singles) ---
# (permissions, bonus, description)
PERMISSION_COMBINATIONS: List[Tuple[FrozenSet[str], float, str]] = [
    (
        frozenset({"android.permission.INTERNET", "android.permission.READ_SMS"}),
        5,
        "SMS exfiltration capability (read SMS + network egress)",
    ),
    (
        frozenset({"android.permission.INTERNET", "android.permission.RECEIVE_SMS"}),
        4,
        "Incoming-SMS interception with network egress (OTP theft)",
    ),
    (
        frozenset(
            {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"}
        ),
        6,
        "Overlay + accessibility abuse (classic banking-trojan pattern)",
    ),
    (
        frozenset(
            {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN"}
        ),
        5,
        "Accessibility + device-admin (device takeover / anti-removal)",
    ),
    (
        frozenset(
            {"android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"}
        ),
        4,
        "Dropper capability (download + install additional package)",
    ),
    (
        frozenset({"android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"}),
        4,
        "SMS interception + sending (OTP relay / ATS support)",
    ),
    (
        frozenset(
            {
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.INTERNET",
            }
        ),
        6,
        "Full OTP-relay capability (read + send SMS + network)",
    ),
]

# --- Quark five-stage -> weight (exponential-ish growth by matched stage) ---
QUARK_STAGE_WEIGHTS: Dict[int, float] = {0: 0.0, 1: 0.5, 2: 1.5, 3: 3.0, 4: 5.0, 5: 8.0}

# --- YARA hit weights ---
YARA_BASE_WEIGHT = 4.0
YARA_TAG_BOOSTS: Dict[str, float] = {
    "banker": 3.0,
    "banking": 3.0,
    "overlay": 3.0,
    "rat": 3.0,
    "keylog": 3.0,
    "keylogger": 3.0,
    "dropper": 2.0,
    "c2": 2.0,
    "stealer": 2.0,
}
YARA_MAX_WEIGHT = 8.0

# --- certificate / IOC weights ---
CERT_SELF_SIGNED_WEIGHT = 2.0
CERT_DEBUG_WEIGHT = 3.0
FIREBASE_WEIGHT = 4.0
FIREBASE_MAX = 6.0
IP_LITERAL_C2_WEIGHT = 3.0
IP_LITERAL_C2_MAX = 6.0
ESCALATION_WEIGHT = 2.0
ESCALATION_MAX = 4.0

# --- normalization: raw additive weight -> 0..100 (saturating, monotonic) ---
# rule_score = 100 * (1 - exp(-raw / K)). K is an exposed operating-point knob.
NORMALIZATION_K = 18.0
