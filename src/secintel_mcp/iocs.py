"""Offline indicator-of-compromise extraction, defanging and refanging.

Nothing in this module touches the network: text goes in, indicators come out.
"""

from __future__ import annotations

import ipaddress
import re

MAX_TEXT_CHARS = 200_000
MAX_PER_TYPE = 500

# File extensions that look like TLDs in prose ("invoice.pdf", "setup.exe").
# ".zip", ".mov" and ".sh" are real TLDs too, but in incident text they are far
# more often filenames, so they are treated as such.
_FILE_EXTENSIONS = frozenset(
    "exe dll sys bat cmd ps1 vbs js jar py sh txt log pdf doc docx xls xlsx ppt pptx "
    "zip rar gz tar iso img lnk tmp dat bin cfg conf ini json xml yml yaml html htm "
    "php asp aspx png jpg jpeg gif svg mov mp4 csv md".split()
)

_REFANG_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bhxxp(s?)(?=\[?:)", re.IGNORECASE), r"http\1"),
    (re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{\.\}", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[(?:@|at)\]", re.IGNORECASE), "@"),
)

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`\]\)\}]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[\w.+-]{1,64}@(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b", re.IGNORECASE
)
_DOMAIN_RE = re.compile(
    r"(?<![\w@./-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])",
    re.IGNORECASE,
)
_HASH_RE = re.compile(
    r"(?<![0-9a-f])(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])", re.IGNORECASE
)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}


def _check_size(text: str) -> str:
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    if len(text) > MAX_TEXT_CHARS:
        raise ValueError(f"text is too long ({len(text)} chars; limit is {MAX_TEXT_CHARS})")
    return text


def refang(text: str) -> str:
    """Undo common defanging: hxxp -> http, [.] -> ., [:] -> :, [@] -> @."""
    text = _check_size(text)
    for pattern, replacement in _REFANG_RULES:
        text = pattern.sub(replacement, text)
    return text


def defang(text: str) -> str:
    """Make indicators safe to paste into tickets, email and chat.

    Only recognised indicators are touched; surrounding prose is left alone.
    """
    text = refang(text)  # normalise first so already-defanged input is not doubled

    def _dots(value: str) -> str:
        return value.replace(".", "[.]")

    def _url(match: re.Match[str]) -> str:
        scheme, rest = match.group(0).split("://", 1)
        host, sep, tail = rest.partition("/")
        return f"{scheme.lower().replace('http', 'hxxp')}[://]{_dots(host)}{sep}{tail}"

    # Substitute left to right in one pass so a URL's host is not defanged twice.
    combined = re.compile(
        f"(?P<url>{_URL_RE.pattern})|(?P<email>{_EMAIL_RE.pattern})|"
        f"(?P<ip>{_IPV4_RE.pattern})|(?P<domain>{_DOMAIN_RE.pattern})",
        re.IGNORECASE,
    )

    def _replace(match: re.Match[str]) -> str:
        value = match.group(0)
        kind = match.lastgroup
        if kind == "url":
            return _url(match)
        if kind == "email":
            local, _, domain = value.rpartition("@")
            return f"{local}[@]{_dots(domain)}"
        if kind == "ip":
            return _dots(value) if _valid_ipv4(value) else value
        if kind == "domain":
            return _dots(value) if _plausible_domain(value) else value
        return value

    return combined.sub(_replace, text)


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return True


def _plausible_domain(value: str) -> bool:
    tld = value.rsplit(".", 1)[-1].lower()
    return tld not in _FILE_EXTENSIONS and not value.replace(".", "").isdigit()


def _unique(values: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for value in values:
        seen.setdefault(value, None)
    return list(seen)[:MAX_PER_TYPE]


def extract_iocs(text: str) -> dict[str, object]:
    """Extract indicators from free text (defanged input is handled).

    Returns de-duplicated lists in first-seen order. Private, loopback and other
    non-routable IPv4 addresses are reported separately because they are rarely
    useful as external indicators.
    """
    clean = refang(text)

    urls = _unique([u.rstrip(".,;:!?") for u in _URL_RE.findall(clean)])
    emails = _unique([e.lower() for e in _EMAIL_RE.findall(clean)])

    public_ips: list[str] = []
    internal_ips: list[str] = []
    for candidate in _IPV4_RE.findall(clean):
        if not _valid_ipv4(candidate):
            continue
        (public_ips if ipaddress.IPv4Address(candidate).is_global else internal_ips).append(
            candidate
        )

    # Hosts that only appear inside a URL or an email are already represented
    # there, so blank those spans out before looking for bare domains.
    remainder = _EMAIL_RE.sub(" ", _URL_RE.sub(" ", clean))
    domains = _unique([d.lower() for d in _DOMAIN_RE.findall(remainder) if _plausible_domain(d)])

    hashes: dict[str, list[str]] = {"md5": [], "sha1": [], "sha256": []}
    for value in _HASH_RE.findall(clean):
        hashes[_HASH_TYPES[len(value)]].append(value.lower())

    result: dict[str, object] = {
        "urls": urls,
        "domains": domains,
        "ipv4": _unique(public_ips),
        "ipv4_internal": _unique(internal_ips),
        "emails": emails,
        "md5": _unique(hashes["md5"]),
        "sha1": _unique(hashes["sha1"]),
        "sha256": _unique(hashes["sha256"]),
        "cves": _unique([c.upper() for c in _CVE_RE.findall(clean)]),
    }
    result["total"] = sum(len(v) for v in result.values() if isinstance(v, list))
    return result
