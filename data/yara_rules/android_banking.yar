/*
 * APKScan internal YARA rules — Android banking-malware triage indicators.
 *
 * These are coarse triage rules matched against the APK container (plaintext
 * strings in resources/DEX). They corroborate other evidence; per RISKS.md a
 * single YARA hit must never alone produce a Malicious verdict.
 */

rule android_accessibility_abuse
{
    meta:
        family = "generic_banker"
        description = "References Accessibility Service APIs commonly abused by bankers/RATs"
        attck = "T1453"
    strings:
        $a1 = "BIND_ACCESSIBILITY_SERVICE" ascii wide
        $a2 = "android.accessibilityservice.AccessibilityService" ascii wide
        $a3 = "onAccessibilityEvent" ascii wide
        $a4 = "performGlobalAction" ascii wide
    condition:
        2 of ($a*)
}

rule android_overlay_banker
{
    meta:
        family = "generic_banker"
        description = "Overlay/fake-login indicators (draw-over-other-apps)"
        attck = "T1417.002"
    strings:
        $o1 = "SYSTEM_ALERT_WINDOW" ascii wide
        $o2 = "TYPE_APPLICATION_OVERLAY" ascii wide
        $o3 = "addView" ascii wide
        $o4 = "WindowManager" ascii wide
    condition:
        3 of ($o*)
}

rule android_sms_interceptor
{
    meta:
        family = "generic_banker"
        description = "SMS/OTP interception indicators"
        attck = "T1636.004"
    strings:
        $s1 = "android.provider.Telephony.SMS_RECEIVED" ascii wide
        $s2 = "abortBroadcast" ascii wide
        $s3 = "getMessageBody" ascii wide
        $s4 = "SmsManager" ascii wide
    condition:
        2 of ($s*)
}

rule android_dropper_install
{
    meta:
        family = "generic_dropper"
        description = "Runtime package install / dynamic code loading (dropper)"
        attck = "T1407"
    strings:
        $d1 = "REQUEST_INSTALL_PACKAGES" ascii wide
        $d2 = "application/vnd.android.package-archive" ascii wide
        $d3 = "DexClassLoader" ascii wide
        $d4 = "InMemoryDexClassLoader" ascii wide
    condition:
        2 of ($d*)
}

rule android_firebase_c2
{
    meta:
        family = "generic_c2"
        description = "Firebase used as C2 / data exfil (seen in FatBoyPanel India campaign)"
        attck = "T1544"
    strings:
        $f1 = "firebaseio.com" ascii wide
        $f2 = "firebasedatabase.app" ascii wide
        $f3 = "google_api_key" ascii wide
    condition:
        any of ($f*)
}
