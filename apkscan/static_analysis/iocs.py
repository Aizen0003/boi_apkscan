"""IOC extraction from extracted strings (deterministic, pure).

Domains are taken from URLs and from standalone hostnames whose final label is a
real TLD — this filters out Java/Android package names and class identifiers
(e.g. ``com.sbi.secure.update`` ends in ``update``, not a TLD, so it is ignored)
which otherwise look like domains.
"""

import re
from typing import Iterable, List, Set
from urllib.parse import urlparse

from apkscan.schema import IOCSet

_URL_RE = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>\\]+", re.IGNORECASE)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b")
_CRYPTO_RE = re.compile(
    r"\b(?:AES|DESede|DES|RSA|Blowfish|RC4|ChaCha20|3DES)(?:/[A-Za-z0-9]+){0,3}\b"
)

# Curated set of plausible TLDs (kept tight to suppress package-name false
# positives). Banking-fraud-relevant ccTLDs (in/ru/cn) are included.
_TLDS: Set[str] = {
    "com", "net", "org", "info", "biz", "io", "co", "app", "dev", "xyz", "top",
    "online", "site", "club", "icu", "vip", "cc", "tk", "ml", "ga", "cf", "gq",
    "pw", "su", "ru", "cn", "in", "uk", "us", "de", "fr", "br", "ng", "pk", "bd",
    "id", "ir", "tr", "ua", "me", "live", "store", "shop", "fun", "work", "link",
    "googleapis", "firebaseio", "firebasedatabase",
}

_FIREBASE_MARKERS = ("firebaseio.com", "firebasedatabase.app", "firebasestorage.googleapis.com")


def _valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def extract_urls(text: str) -> List[str]:
    return [m.group(0).rstrip(".,);\"'") for m in _URL_RE.finditer(text)]


def extract_ips(text: str) -> List[str]:
    return [m.group(0) for m in _IP_RE.finditer(text) if _valid_ip(m.group(0))]


def extract_emails(text: str) -> List[str]:
    return [m.group(0) for m in _EMAIL_RE.finditer(text)]


def _is_real_domain(host: str) -> bool:
    host = host.strip(".")
    if not host or "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1].lower()
    return tld in _TLDS


def extract_domains(text: str) -> List[str]:
    out: List[str] = []
    for url in extract_urls(text):
        host = urlparse(url).hostname
        if host and not _valid_ip(host):
            out.append(host.lower())
    for m in _DOMAIN_RE.finditer(text):
        host = m.group(0).lower()
        if _is_real_domain(host) and not _valid_ip(host):
            out.append(host)
    return out


def extract_crypto(text: str) -> List[str]:
    return [m.group(0) for m in _CRYPTO_RE.finditer(text)]


def _dedupe_sorted(values: Iterable[str]) -> List[str]:
    return sorted({v for v in values if v})


def build_iocset(strings: Iterable[str], *, seed: IOCSet | None = None) -> IOCSet:
    """Mine an iterable of strings into a deduped, sorted IOCSet."""

    urls: Set[str] = set(seed.urls) if seed else set()
    ips: Set[str] = set(seed.ips) if seed else set()
    emails: Set[str] = set(seed.emails) if seed else set()
    domains: Set[str] = set(seed.domains) if seed else set()
    firebase: Set[str] = set(seed.firebase_urls) if seed else set()
    crypto: Set[str] = set(seed.crypto_constants) if seed else set()

    for s in strings:
        if not s:
            continue
        urls.update(extract_urls(s))
        ips.update(extract_ips(s))
        emails.update(extract_emails(s))
        domains.update(extract_domains(s))
        crypto.update(extract_crypto(s))

    for url in list(urls):
        if any(marker in url.lower() for marker in _FIREBASE_MARKERS):
            firebase.add(url)
    for dom in list(domains):
        if any(marker in dom.lower() for marker in _FIREBASE_MARKERS):
            firebase.add(dom)

    return IOCSet(
        domains=_dedupe_sorted(domains),
        urls=_dedupe_sorted(urls),
        ips=_dedupe_sorted(ips),
        emails=_dedupe_sorted(emails),
        firebase_urls=_dedupe_sorted(firebase),
        crypto_constants=_dedupe_sorted(crypto),
    )
