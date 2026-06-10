# Internal Threat Intel — Android Banking Malware (India-focused)

## SOVA
CERT-In flagged SOVA as targeting Indian banking customers. Capabilities:
keylogging, cookie theft, MFA/2FA interception, screenshots, overlay attacks.
Distributed via smishing (SMS phishing). Maps to accessibility abuse (T1453),
overlay/GUI input capture (T1417.002), and screen capture (T1513).

## Anatsa / TeaBot (Toddler)
Overlay attacks, screen streaming, accessibility abuse, app-specific keylogging.
Droppers published on Google Play (e.g. "Document Viewer – File Reader",
~90k installs). Decrypts each string at runtime with a dynamically generated DES
key; performs emulation checks and device-model verification to evade dynamic
analysis; conceals the final DEX payload inside asset files, decrypted at runtime
with a static embedded key. Strong reason static-only analysis is insufficient —
sets the packing/encryption escalation flag (T1406 / T1407).

## Octo / Octo2
Descendant of Exobot/Coper, sold as MaaS. Octo2 adds a Domain Generation
Algorithm (DGA) for C2, stronger obfuscation, remote-control stability for Device
Takeover (DTO). Distributed via Zombinder to bypass Android 13+ restrictions;
masquerades as Chrome/NordVPN. Remote access software (T1663), C2 (T1544).

## Medusa
RAT with VNC real-time screen sharing and accessibility abuse. 2024 variant uses
a lightweight permission set, full-screen overlays, and remote uninstall.

## GoldDigger / GoldPickaxe (GoldFactory, APAC)
Accessibility abuse, web-fake overlays of banks, and biometric face/ID-document
harvesting to create deepfakes that bypass facial recognition. GoldPickaxe spans
iOS + Android.

## FatBoyPanel (Zimperium zLabs) — India
~900 malware samples primarily targeting Indian bank users; spread via WhatsApp
as APKs; forwards SMS via ~1,000 live numbers; 222+ public Firebase storage
buckets holding 2.5 GB of stolen data (≈50,000 users). Impersonated banks: ICICI,
SBI, PNB, RBL, IndusInd, Union Bank. Permissions abused: READ_SMS/SEND_SMS/
RECEIVE_SMS, READ_PHONE_STATE, REQUEST_INSTALL_PACKAGES, QUERY_ALL_PACKAGES.
Firebase used as C2 / exfiltration sink (T1544) — a hardcoded firebaseio.com
endpoint is a high-signal indicator.

## SharkBot
Abuses Android "Direct Reply" notifications to self-propagate; uses ATS
(Automated Transfer System) to change the destination IBAN mid-transfer and
bypass MFA/biometrics; overlay injections, keylogging via accessibility events,
SMS intercept.

## Common technique cluster (banking trojans)
Overlay/fake-login (T1417.002), Accessibility Service abuse (T1453),
SMS/OTP interception (T1636.004 read, T1582 control), keylogging (T1417.001),
screen capture / VNC (T1513 / T1663), dynamic code loading (T1407),
dropper / ingress tool transfer (T1544), app enumeration (T1418),
obfuscation/packing (T1406 / T1406.002), smishing delivery (T1660).
