from __future__ import annotations

import pytest

from secintel_mcp.triage import prioritise, triage_cve

from .conftest import BORING, LOG4SHELL


@pytest.mark.parametrize(
    ("cvss", "epss", "kev", "expected"),
    [
        (2.0, 0.0001, True, "P1"),  # KEV wins regardless of score
        (5.0, 0.10, False, "P2"),
        (9.0, 0.001, False, "P2"),
        (7.0, 0.001, False, "P3"),
        (5.0, 0.01, False, "P3"),
        (6.9, 0.009, False, "P4"),
        (None, None, False, "unknown"),
        (None, 0.5, False, "P2"),
        (8.0, None, None, "P3"),
    ],
)
def test_priority_policy(cvss, epss, kev, expected):
    assert prioritise(cvss, epss, kev)[0] == expected


def test_unknown_kev_status_is_flagged():
    _, reasons = prioritise(8.0, 0.02, None)
    assert any("KEV status could not be checked" in r for r in reasons)


async def test_triage_known_exploited(client):
    result = await triage_cve(client, LOG4SHELL.lower())
    assert result["priority"] == "P1"
    assert result["in_kev"] is True
    assert result["kev"]["product"] == "Log4j2"
    assert result["cvss"]["score"] == 10.0
    assert result["epss"] == pytest.approx(0.944)
    assert result["source_errors"] == []


async def test_triage_low_risk(client):
    result = await triage_cve(client, BORING)
    assert result["priority"] == "P4"
    assert result["kev"] is None


async def test_triage_survives_one_source_failing(client, upstream):
    upstream.fail_hosts["www.cisa.gov"] = 503
    result = await triage_cve(client, LOG4SHELL)
    assert result["priority"] == "P2"  # falls back to CVSS/EPSS
    assert result["in_kev"] is None
    assert len(result["source_errors"]) == 1
    assert "CISA KEV" in result["source_errors"][0]


async def test_triage_with_every_source_down(client, upstream):
    for host in ("www.cisa.gov", "api.first.org", "services.nvd.nist.gov"):
        upstream.fail_hosts[host] = 500
    result = await triage_cve(client, LOG4SHELL)
    assert result["priority"] == "unknown"
    assert len(result["source_errors"]) == 3


async def test_triage_rejects_bad_id_before_any_request(client, upstream):
    with pytest.raises(ValueError):
        await triage_cve(client, "not-a-cve")
    assert upstream.requests == []
