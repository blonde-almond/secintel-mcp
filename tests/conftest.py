"""Shared fixtures: a fake upstream so tests never touch the network."""

from __future__ import annotations

import json

import httpx
import pytest

from secintel_mcp import server
from secintel_mcp.clients import IntelClient

LOG4SHELL = "CVE-2021-44228"
BORING = "CVE-2020-0001"

NVD_RECORDS = {
    LOG4SHELL: {
        "id": LOG4SHELL,
        "vulnStatus": "Analyzed",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2025-04-03T20:53:22.977",
        "descriptions": [
            {"lang": "es", "value": "Descripción"},
            {
                "lang": "en",
                "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
            },
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Secondary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.0,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CNA",
                    },
                },
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 10.0,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    },
                },
            ]
        },
        "weaknesses": [
            {
                "description": [
                    {"lang": "en", "value": "CWE-502"},
                    {"lang": "en", "value": "NVD-CWE-Other"},
                ]
            }
        ],
        "references": [{"url": f"https://example.com/ref/{i}"} for i in range(30)],
    },
    BORING: {
        "id": BORING,
        "descriptions": [{"lang": "en", "value": "A low severity issue."}],
        "metrics": {
            "cvssMetricV2": [
                {
                    "baseSeverity": "LOW",
                    "cvssData": {"version": "2.0", "baseScore": 2.1, "vectorString": "AV:L"},
                }
            ]
        },
    },
}

EPSS_ROWS = {
    LOG4SHELL: {"cve": LOG4SHELL, "epss": "0.944", "percentile": "0.999", "date": "2026-11-10"},
    BORING: {"cve": BORING, "epss": "0.0004", "percentile": "0.1", "date": "2026-11-10"},
}

KEV_CATALOGUE = {
    "vulnerabilities": [
        {
            "cveID": LOG4SHELL,
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution Vulnerability",
            "dateAdded": "2021-12-10",
            "dueDate": "2021-12-24",
            "requiredAction": "Apply updates per vendor instructions.",
            "knownRansomwareCampaignUse": "Known",
        }
    ]
}

OSV_VULNS = [
    {
        "id": "GHSA-jfmj-5v4g-7637",
        "aliases": ["CVE-2021-44228"],
        "summary": "Remote code injection in Log4j",
        "published": "2021-12-10T00:40:56Z",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"ranges": [{"events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}]}],
    }
]


class FakeUpstream:
    """Routes requests by host and records what was asked for."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.fail_hosts: dict[str, int] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if host in self.fail_hosts:
            return httpx.Response(self.fail_hosts[host])
        if host == "services.nvd.nist.gov":
            record = NVD_RECORDS.get(request.url.params["cveId"])
            return httpx.Response(
                200, json={"vulnerabilities": [{"cve": record}] if record else []}
            )
        if host == "api.first.org":
            row = EPSS_ROWS.get(request.url.params["cve"])
            return httpx.Response(200, json={"data": [row] if row else []})
        if host == "www.cisa.gov":
            return httpx.Response(200, json=KEV_CATALOGUE)
        if host == "api.osv.dev":
            body = json.loads(request.content)
            hit = body["package"]["name"] == "org.apache.logging.log4j:log4j-core"
            return httpx.Response(200, json={"vulns": OSV_VULNS} if hit else {})
        return httpx.Response(404)

    def count(self, host: str) -> int:
        return sum(1 for r in self.requests if r.url.host == host)


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
async def client(upstream: FakeUpstream):
    intel = IntelClient(transport=httpx.MockTransport(upstream.handler), nvd_api_key="")
    server.set_client(intel)
    yield intel
    server.set_client(None)
    await intel.aclose()
