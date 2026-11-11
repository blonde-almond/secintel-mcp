"""Combine NVD, EPSS and KEV into one prioritisation verdict.

The rule set is deliberately simple and transparent, in the spirit of
"exploitation evidence first, severity second":

    P1  known exploited (CISA KEV)
    P2  EPSS >= 0.10, or CVSS >= 9.0
    P3  CVSS >= 7.0, or EPSS >= 0.01
    P4  everything else

It is a starting point for triage, not a substitute for knowing whether the
affected product is actually deployed and reachable in your environment.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .clients import IntelClient, IntelError, normalize_cve_id

EPSS_HIGH = 0.10
EPSS_ELEVATED = 0.01
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0

ACTIONS = {
    "P1": "Patch or mitigate immediately; exploitation in the wild is confirmed.",
    "P2": "Patch in the next emergency or expedited change window.",
    "P3": "Patch in the normal patch cycle.",
    "P4": "Track; patch with routine maintenance.",
    "unknown": "Not enough data to prioritise; review manually.",
}


def prioritise(
    cvss_score: float | None, epss: float | None, in_kev: bool | None
) -> tuple[str, list[str]]:
    """Return (priority, reasons). Pure function so the policy is easy to test."""
    reasons: list[str] = []
    if in_kev:
        return "P1", ["Listed in the CISA Known Exploited Vulnerabilities catalogue."]

    if cvss_score is None and epss is None:
        return "unknown", ["No CVSS score or EPSS score was available."]

    priority = "P4"
    if epss is not None and epss >= EPSS_HIGH:
        priority = "P2"
        reasons.append(f"EPSS {epss:.3f} is at or above {EPSS_HIGH:.2f}.")
    if cvss_score is not None and cvss_score >= CVSS_CRITICAL:
        priority = "P2"
        reasons.append(f"CVSS {cvss_score:.1f} is critical.")
    if priority == "P4":
        if cvss_score is not None and cvss_score >= CVSS_HIGH:
            priority = "P3"
            reasons.append(f"CVSS {cvss_score:.1f} is high.")
        if epss is not None and epss >= EPSS_ELEVATED:
            priority = "P3"
            reasons.append(f"EPSS {epss:.3f} is at or above {EPSS_ELEVATED:.2f}.")
    if priority == "P4":
        reasons.append("No exploitation evidence and severity is below high.")
    if in_kev is None:
        reasons.append("KEV status could not be checked, so this may be understated.")
    return priority, reasons


async def triage_cve(client: IntelClient, cve_id: str) -> dict[str, Any]:
    """Query all three sources concurrently; tolerate any one of them failing."""
    cve_id = normalize_cve_id(cve_id)
    results = await asyncio.gather(
        client.cve(cve_id), client.epss(cve_id), client.kev(cve_id), return_exceptions=True
    )
    errors: list[str] = []
    parts: list[dict[str, Any] | None] = []
    for result in results:
        if isinstance(result, IntelError):
            errors.append(str(result))
            parts.append(None)
        elif isinstance(result, BaseException):
            raise result
        else:
            parts.append(result)
    nvd, epss, kev = parts

    cvss = (nvd or {}).get("cvss") or {}
    cvss_score = cvss.get("score")
    epss_score = epss.get("epss") if epss and epss.get("found") else None
    in_kev = kev.get("in_kev") if kev else None

    priority, reasons = prioritise(cvss_score, epss_score, in_kev)
    return {
        "cve_id": cve_id,
        "priority": priority,
        "recommended_action": ACTIONS[priority],
        "reasons": reasons,
        "cvss": cvss or None,
        "epss": epss_score,
        "epss_percentile": epss.get("percentile") if epss and epss.get("found") else None,
        "in_kev": in_kev,
        "kev": kev if kev and kev.get("in_kev") else None,
        "description": (nvd or {}).get("description"),
        "source_errors": errors,
    }
