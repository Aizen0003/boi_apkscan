"""Feature encoder: FeatureSet → fixed-length numeric vector for ML.

Encodes the canonical ``FeatureSet`` into a fixed-size numeric array suitable
for tree-based classifiers (RF / XGBoost). The vocabulary of features is
declared statically so the same encoder can be used at training time and at
inference time without leaking information.

Lazy-imports ``numpy`` so the deterministic core remains importable when the
``ml`` extra is not installed.
"""

from typing import TYPE_CHECKING, List

from apkscan.schema import FeatureSet

if TYPE_CHECKING:
    import numpy as np

# ── Vocabulary ──────────────────────────────────────────────────────────────

# 23 dangerous/common permissions tracked as binary features
PERMISSION_VOCAB: List[str] = [
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.WRITE_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.READ_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.CAMERA",
    "android.permission.GET_TASKS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.CALL_PHONE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.INTERNET",
    "android.permission.FOREGROUND_SERVICE",
]

# 12 sensitive API classes/methods tracked as binary features
API_VOCAB: List[str] = [
    "Landroid/telephony/SmsManager;->sendTextMessage",
    "Landroid/telephony/SmsManager;->getDefault",
    "Landroid/app/admin/DevicePolicyManager;->lockNow",
    "Ldalvik/system/DexClassLoader;-><init>",
    "Ljava/lang/reflect/Method;->invoke",
    "Landroid/media/MediaRecorder;->start",
    "Landroid/view/WindowManager;->addView",
    "Landroid/accessibilityservice/AccessibilityService",
    "Landroid/content/ContentResolver;->query",
    "Landroid/os/Build;->MODEL",
    "Ljava/net/URL;->openConnection",
    "Ljavax/crypto/Cipher;->getInstance",
]


class FeatureEncoder:
    """Encode a ``FeatureSet`` into a fixed-length numeric vector.

    The vector layout is:
        [23 permission bits] + [12 API bits] + [7 numeric metrics]
    Total: 42 features.
    """

    def __init__(self) -> None:
        self._perm_vocab = PERMISSION_VOCAB
        self._api_vocab = API_VOCAB

    @property
    def n_features(self) -> int:
        return len(self._perm_vocab) + len(self._api_vocab) + 7

    def get_feature_names(self) -> List[str]:
        """Return human-readable feature names aligned with ``encode`` output."""
        names: List[str] = []
        for perm in self._perm_vocab:
            names.append(f"perm:{perm.split('.')[-1]}")
        for api in self._api_vocab:
            names.append(f"api:{api.split(';')[0].split('/')[-1]}")
        names.extend([
            "file_size",
            "n_permissions",
            "n_native_libs",
            "n_assets",
            "max_asset_entropy",
            "n_quark_behaviors",
            "n_yara_matches",
        ])
        return names

    def encode(self, features: FeatureSet) -> List[float]:
        """Encode *features* into a fixed-size float vector."""
        vec: List[float] = []

        # ── permission bits ──
        present_perms = set(features.permission_names())
        for perm in self._perm_vocab:
            vec.append(1.0 if perm in present_perms else 0.0)

        # ── API bits ──
        present_apis = {a.api for a in features.apis}
        for api in self._api_vocab:
            hit = any(api in pa for pa in present_apis)
            vec.append(1.0 if hit else 0.0)

        # ── numeric metrics ──
        vec.append(float(features.sample.file_size))
        vec.append(float(len(features.permissions)))
        vec.append(float(len(features.native_libs)))
        vec.append(float(len(features.assets)))
        max_entropy = max((a.entropy or 0.0 for a in features.assets), default=0.0)
        vec.append(float(max_entropy))
        vec.append(float(len(features.quark_behaviors)))
        vec.append(float(len(features.yara_matches)))

        return vec

    def encode_np(self, features: FeatureSet) -> "np.ndarray":
        """Convenience: return a 1-D numpy array."""
        import numpy as np  # lazy
        return np.array(self.encode(features), dtype=np.float64)
