"""HTTP clients for the public vulnerability data sources.

Design rules, since this code runs on behalf of an AI agent:

* Every request goes to a fixed, hard-coded host. Tool arguments are only ever
  used as validated query parameters or JSON body fields, never as URLs, so the
  server cannot be steered into fetching arbitrary addresses (SSRF).
* Every input is validated against a strict pattern before it leaves the process.
* Every request has a timeout and every response has a size cap.
* Responses are trimmed to the fields an analyst needs, which keeps untrusted
  upstream text in the model's context to a minimum.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any

import httpx

from . import __version__

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_URL = "https://api.osv.dev/v1/query"

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PACKAGE_RE = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9._\-/@:+]{0,213}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-+~:!]{0,63}$")

# Ecosystem names as OSV spells them (matching is case-insensitive on input).
OSV_ECOSYSTEMS = (
    "PyPI", "npm", "Go", "Maven", "crates.io", "NuGet", "RubyGems", "Packagist",
    "Hex", "Pub", "Debian", "Alpine", "Ubuntu", "GitHub Actions",
)  # fmt: skip
_ECOSYSTEM_LOOKUP = {name.lower(): name for name in OSV_ECOSYSTEMS}

MAX_RESPONSE_BYTES = 25 * 1024 * 1024  # the KEV catalogue is a few MB
DEFAULT_TIMEOUT = 20.0
KEV_TTL_SECONDS = 6 * 60 * 60
CACHE_TTL_SECONDS = 15 * 60
MAX_DESCRIPTION_CHARS = 1500
MAX_REFERENCES = 10
MAX_OSV_RESULTS = 50


class IntelError(Exception):
    """A lookup failed in a way worth reporting to the caller."""


def normalize_cve_id(cve_id: str) -> str:
    """Return the canonical upper-case CVE ID or raise ValueError."""
    candidate = str(cve_id).strip().upper()
    if not CVE_RE.fullmatch(candidate):
        raise ValueError(f"Not a valid CVE ID (expected CVE-YYYY-NNNN): {cve_id!r}")
    return candidate


def normalize_ecosystem(ecosystem: str) -> str:
    key = str(ecosystem).strip().lower()
    if key not in _ECOSYSTEM_LOOKUP:
        raise ValueError(
            f"Unsupported ecosystem {ecosystem!r}. Supported: {', '.join(OSV_ECOSYSTEMS)}"
        )
    return _ECOSYSTEM_LOOKUP[key]


def _truncate(text: str, limit: int = MAX_DESCRIPTION_CHARS) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class IntelClient:
    """Async client for NVD, FIRST EPSS, CISA KEV and OSV.dev."""

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        nvd_api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._nvd_api_key = nvd_api_key if nvd_api_key is not None else os.getenv("NVD_API_KEY")
        self._http = httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": f"secintel-mcp/{__version__}"},
        )
        self._cache: dict[str, tuple[float, Any]] = {}

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ helpers

    def _cache_get(self, key: str) -> Any | None:
        hit = self._cache.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        self._cache.pop(key, None)
        return None

    def _cache_put(self, key: str, value: Any, ttl: float = CACHE_TTL_SECONDS) -> None:
        self._cache[key] = (time.monotonic() + ttl, value)

    async def _request_json(self, method: str, url: str, source: str, **kwargs: Any) -> Any:
        try:
            async with self._http.stream(method, url, **kwargs) as response:
                if response.status_code in (403, 429):
                    raise IntelError(
                        f"{source} is rate limiting requests (HTTP {response.status_code}); retry shortly."
                    )
                if response.status_code >= 400:
                    raise IntelError(f"{source} returned HTTP {response.status_code}.")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise IntelError(f"{source} response exceeded the size limit.")
        except httpx.TimeoutException as exc:
            raise IntelError(f"{source} timed out.") from exc
        except httpx.HTTPError as exc:
            raise IntelError(f"{source} request failed: {type(exc).__name__}.") from exc
        try:
            return httpx.Response(200, content=bytes(body)).json()
        except ValueError as exc:
            raise IntelError(f"{source} returned a response that is not valid JSON.") from exc

    # ---------------------------------------------------------------------- NVD

    async def cve(self, cve_id: str) -> dict[str, Any]:
        """Core CVE record from the NVD: description, CVSS, CWEs, references."""
        cve_id = normalize_cve_id(cve_id)
        cached = self._cache_get(f"nvd:{cve_id}")
        if cached is not None:
            return cached

        headers = {"apiKey": self._nvd_api_key} if self._nvd_api_key else {}
        data = await self._request_json(
            "GET", NVD_URL, "NVD", params={"cveId": cve_id}, headers=headers
        )
        records = data.get("vulnerabilities") or []
        if not records:
            result: dict[str, Any] = {"cve_id": cve_id, "found": False}
        else:
            result = _parse_nvd_record(cve_id, records[0].get("cve") or {})
        self._cache_put(f"nvd:{cve_id}", result)
        return result

    # --------------------------------------------------------------------- EPSS

    async def epss(self, cve_id: str) -> dict[str, Any]:
        """Exploit Prediction Scoring System score from FIRST."""
        cve_id = normalize_cve_id(cve_id)
        cached = self._cache_get(f"epss:{cve_id}")
        if cached is not None:
            return cached

        data = await self._request_json("GET", EPSS_URL, "FIRST EPSS", params={"cve": cve_id})
        rows = data.get("data") or []
        if not rows:
            result: dict[str, Any] = {"cve_id": cve_id, "found": False}
        else:
            row = rows[0]
            try:
                result = {
                    "cve_id": cve_id,
                    "found": True,
                    "epss": float(row["epss"]),
                    "percentile": float(row["percentile"]),
                    "date": str(row.get("date", "")),
                }
            except (KeyError, TypeError, ValueError) as exc:
                raise IntelError("FIRST EPSS returned an unexpected record shape.") from exc
        self._cache_put(f"epss:{cve_id}", result)
        return result

    # ---------------------------------------------------------------------- KEV

    async def _kev_index(self) -> dict[str, dict[str, Any]]:
        cached = self._cache_get("kev:index")
        if cached is not None:
            return cached
        data = await self._request_json("GET", KEV_URL, "CISA KEV")
        entries = data.get("vulnerabilities")
        if not isinstance(entries, list):
            raise IntelError("CISA KEV returned an unexpected catalogue shape.")
        index = {
            str(e.get("cveID", "")).upper(): e
            for e in entries
            if isinstance(e, dict) and e.get("cveID")
        }
        self._cache_put("kev:index", index, KEV_TTL_SECONDS)
        return index

    async def kev(self, cve_id: str) -> dict[str, Any]:
        """Whether the CVE is in CISA's Known Exploited Vulnerabilities catalogue."""
        cve_id = normalize_cve_id(cve_id)
        entry = (await self._kev_index()).get(cve_id)
        if entry is None:
            return {"cve_id": cve_id, "in_kev": False}
        return {
            "cve_id": cve_id,
            "in_kev": True,
            "vendor": _truncate(entry.get("vendorProject", ""), 200),
            "product": _truncate(entry.get("product", ""), 200),
            "name": _truncate(entry.get("vulnerabilityName", ""), 300),
            "date_added": str(entry.get("dateAdded", "")),
            "due_date": str(entry.get("dueDate", "")),
            "required_action": _truncate(entry.get("requiredAction", ""), 600),
            "ransomware_use": str(entry.get("knownRansomwareCampaignUse", "Unknown")),
        }

    # ---------------------------------------------------------------------- OSV

    async def package_vulns(
        self, ecosystem: str, package: str, version: str | None = None
    ) -> dict[str, Any]:
        """Known vulnerabilities for an open-source package, from OSV.dev."""
        ecosystem = normalize_ecosystem(ecosystem)
        package = str(package).strip()
        if not PACKAGE_RE.fullmatch(package):
            raise ValueError(f"Not a valid package name: {package!r}")
        query: dict[str, Any] = {"package": {"name": package, "ecosystem": ecosystem}}
        if version is not None and str(version).strip():
            version = str(version).strip()
            if not VERSION_RE.fullmatch(version):
                raise ValueError(f"Not a valid version string: {version!r}")
            query["version"] = version
        else:
            version = None

        data = await self._request_json("POST", OSV_URL, "OSV.dev", json=query)
        vulns = data.get("vulns") or []
        return {
            "ecosystem": ecosystem,
            "package": package,
            "version": version,
            "vulnerability_count": len(vulns),
            "truncated": len(vulns) > MAX_OSV_RESULTS or bool(data.get("next_page_token")),
            "vulnerabilities": [_parse_osv_record(v) for v in vulns[:MAX_OSV_RESULTS]],
        }


def _parse_nvd_record(cve_id: str, cve: dict[str, Any]) -> dict[str, Any]:
    description = next(
        (d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"),
        "",
    )
    cvss: dict[str, Any] | None = None
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer the NVD's own ("Primary") assessment over a CNA's.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if isinstance(score, (int, float)):
            cvss = {
                "version": str(data.get("version", "")),
                "score": float(score),
                "severity": str(data.get("baseSeverity") or entry.get("baseSeverity") or ""),
                "vector": str(data.get("vectorString", "")),
            }
            break
    cwes = sorted(
        {
            d.get("value", "")
            for w in cve.get("weaknesses") or []
            for d in w.get("description") or []
            if str(d.get("value", "")).startswith("CWE-")
        }
    )
    references = [
        str(r.get("url")) for r in (cve.get("references") or [])[:MAX_REFERENCES] if r.get("url")
    ]
    return {
        "cve_id": cve_id,
        "found": True,
        "status": str(cve.get("vulnStatus", "")),
        "published": str(cve.get("published", "")),
        "last_modified": str(cve.get("lastModified", "")),
        "description": _truncate(description),
        "cvss": cvss,
        "cwes": cwes,
        "references": references,
    }


def _parse_osv_record(vuln: dict[str, Any]) -> dict[str, Any]:
    fixed = sorted(
        {
            str(event["fixed"])
            for affected in vuln.get("affected") or []
            for rng in affected.get("ranges") or []
            for event in rng.get("events") or []
            if isinstance(event, dict) and event.get("fixed")
        }
    )
    return {
        "id": str(vuln.get("id", "")),
        "aliases": [str(a) for a in (vuln.get("aliases") or [])[:10]],
        "summary": _truncate(vuln.get("summary") or vuln.get("details") or "", 400),
        "severity": str((vuln.get("database_specific") or {}).get("severity", "")),
        "published": str(vuln.get("published", "")),
        "fixed_versions": fixed[:20],
    }
