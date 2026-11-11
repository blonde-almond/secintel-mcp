from __future__ import annotations

import httpx
import pytest

from secintel_mcp.clients import IntelClient, IntelError, normalize_cve_id, normalize_ecosystem

from .conftest import BORING, LOG4SHELL


@pytest.mark.parametrize("raw", ["cve-2021-44228", "  CVE-2021-44228 "])
def test_cve_id_is_normalised(raw):
    assert normalize_cve_id(raw) == LOG4SHELL


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "CVE-21-1",
        "CVE-2021-44228&apiKey=x",
        "CVE-2021-44228/../x",
        "CVE-2021-44228\nX",
        "log4shell",
    ],
)
def test_bad_cve_ids_are_rejected(raw):
    with pytest.raises(ValueError):
        normalize_cve_id(raw)


def test_ecosystem_is_case_insensitive_and_closed():
    assert normalize_ecosystem("pypi") == "PyPI"
    with pytest.raises(ValueError):
        normalize_ecosystem("https://evil.example")


async def test_cve_record_is_parsed_and_trimmed(client):
    record = await client.cve(LOG4SHELL)
    assert record["found"] is True
    assert record["description"].startswith("Apache Log4j2")
    assert record["cvss"]["score"] == 10.0  # Primary beats Secondary
    assert record["cvss"]["severity"] == "CRITICAL"
    assert record["cwes"] == ["CWE-502"]
    assert len(record["references"]) == 10


async def test_cvss_v2_fallback(client):
    record = await client.cve(BORING)
    assert record["cvss"] == {"version": "2.0", "score": 2.1, "severity": "LOW", "vector": "AV:L"}


async def test_unknown_cve_is_not_an_error(client):
    assert await client.cve("CVE-1999-9999") == {"cve_id": "CVE-1999-9999", "found": False}
    assert (await client.epss("CVE-1999-9999"))["found"] is False
    assert (await client.kev("CVE-1999-9999"))["in_kev"] is False


async def test_epss_values_are_floats(client):
    score = await client.epss(LOG4SHELL)
    assert score["epss"] == pytest.approx(0.944)
    assert score["percentile"] == pytest.approx(0.999)


async def test_kev_hit_and_catalogue_is_cached(client, upstream):
    hit = await client.kev(LOG4SHELL)
    assert hit["in_kev"] is True
    assert hit["ransomware_use"] == "Known"
    assert hit["due_date"] == "2021-12-24"
    await client.kev(BORING)
    assert upstream.count("www.cisa.gov") == 1


async def test_nvd_lookups_are_cached(client, upstream):
    await client.cve(LOG4SHELL)
    await client.cve(LOG4SHELL)
    assert upstream.count("services.nvd.nist.gov") == 1


async def test_api_key_header_only_sent_to_nvd(upstream):
    intel = IntelClient(transport=httpx.MockTransport(upstream.handler), nvd_api_key="secret")
    try:
        await intel.cve(LOG4SHELL)
        await intel.epss(LOG4SHELL)
    finally:
        await intel.aclose()
    by_host = {r.url.host: r for r in upstream.requests}
    assert by_host["services.nvd.nist.gov"].headers["apiKey"] == "secret"
    assert "apiKey" not in by_host["api.first.org"].headers


async def test_package_vulns(client, upstream):
    result = await client.package_vulns("maven", "org.apache.logging.log4j:log4j-core", "2.14.1")
    assert result["ecosystem"] == "Maven"
    assert result["vulnerability_count"] == 1
    vuln = result["vulnerabilities"][0]
    assert vuln["aliases"] == ["CVE-2021-44228"]
    assert vuln["fixed_versions"] == ["2.15.0"]
    assert vuln["severity"] == "CRITICAL"


async def test_package_with_no_vulns(client):
    result = await client.package_vulns("PyPI", "requests")
    assert result["vulnerability_count"] == 0
    assert result["version"] is None


@pytest.mark.parametrize(
    ("package", "version"),
    [
        ("../../etc/passwd", None),
        ("requests; rm -rf /", None),
        ("requests", "1.0 OR 1=1"),
        ("", None),
    ],
)
async def test_bad_package_input_never_reaches_the_network(client, upstream, package, version):
    with pytest.raises(ValueError):
        await client.package_vulns("PyPI", package, version)
    assert upstream.requests == []


@pytest.mark.parametrize(
    ("status", "fragment"), [(429, "rate limiting"), (403, "rate limiting"), (500, "HTTP 500")]
)
async def test_upstream_errors_become_intel_errors(client, upstream, status, fragment):
    upstream.fail_hosts["services.nvd.nist.gov"] = status
    with pytest.raises(IntelError, match=fragment):
        await client.cve(LOG4SHELL)


async def test_timeouts_and_bad_json_are_reported_cleanly():
    def timeout(request):
        raise httpx.ReadTimeout("slow", request=request)

    intel = IntelClient(transport=httpx.MockTransport(timeout))
    with pytest.raises(IntelError, match="timed out"):
        await intel.epss(LOG4SHELL)
    await intel.aclose()

    intel = IntelClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="<html>")))
    with pytest.raises(IntelError, match="not valid JSON"):
        await intel.epss(LOG4SHELL)
    await intel.aclose()


async def test_redirects_are_not_followed():
    intel = IntelClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(302, headers={"Location": "http://169.254.169.254/"})
        )
    )
    # A 3xx yields no JSON body, so it surfaces as an error rather than a second request.
    with pytest.raises(IntelError):
        await intel.epss(LOG4SHELL)
    await intel.aclose()
