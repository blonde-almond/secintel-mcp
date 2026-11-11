from __future__ import annotations

import pytest

from secintel_mcp.iocs import MAX_TEXT_CHARS, defang, extract_iocs, refang

REPORT = """
The phishing email from billing[@]evil-corp[.]com linked to
hxxps[://]login.evil-corp[.]com/reset?id=1 and dropped invoice.pdf.exe
(SHA256 E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855,
md5 d41d8cd98f00b204e9800998ecf8427e). Beaconing went to 8.8.8.8 and
185.220.101[.]5, with lateral movement from 10.0.0.12. Second stage hosted
at cdn.badhost.net. Exploits CVE-2021-44228 and cve-2023-4863.
Version 1.2.3.4567 and 999.1.1.1 are not addresses. See setup.exe and notes.txt.
"""


def test_extracts_each_indicator_type():
    found = extract_iocs(REPORT)
    assert found["urls"] == ["https://login.evil-corp.com/reset?id=1"]
    assert found["emails"] == ["billing@evil-corp.com"]
    assert found["ipv4"] == ["8.8.8.8", "185.220.101.5"]
    assert found["ipv4_internal"] == ["10.0.0.12"]
    assert found["domains"] == ["cdn.badhost.net"]
    assert found["sha256"] == ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    assert found["md5"] == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert found["sha1"] == []
    assert found["cves"] == ["CVE-2021-44228", "CVE-2023-4863"]
    assert found["total"] == 10


def test_filenames_and_version_numbers_are_not_indicators():
    found = extract_iocs("Run setup.exe, read notes.txt, upgrade to 1.2.3.4567 from 999.1.1.1")
    assert found["total"] == 0


def test_results_are_deduplicated_in_first_seen_order():
    found = extract_iocs("b.example.org a.example.org B.EXAMPLE.ORG 1.1.1.1 1.1.1.1")
    assert found["domains"] == ["b.example.org", "a.example.org"]
    assert found["ipv4"] == ["1.1.1.1"]


def test_url_trailing_punctuation_is_stripped():
    assert extract_iocs("Visit http://example.org/a.")["urls"] == ["http://example.org/a"]


def test_empty_text():
    assert extract_iocs("")["total"] == 0


def test_refang():
    assert refang("hxxps[://]a[.]b(.)c[dot]d") == "https://a.b.c.d"
    assert refang("hxxp://x[.]y") == "http://x.y"
    assert refang("user[at]mail[.]com") == "user@mail.com"


def test_defang_touches_only_indicators():
    out = defang(
        "Blocked http://evil.example.com/a.php?x=1 and 8.8.8.8. Mail bad@evil.example.com now."
    )
    assert out == (
        "Blocked hxxp[://]evil[.]example[.]com/a.php?x=1 and 8[.]8[.]8[.]8. "
        "Mail bad[@]evil[.]example[.]com now."
    )


def test_defang_is_idempotent():
    once = defang("https://evil.example.com and cdn.badhost.net")
    assert defang(once) == once
    assert once == "hxxps[://]evil[.]example[.]com and cdn[.]badhost[.]net"


def test_defang_then_extract_round_trips():
    original = extract_iocs(refang(REPORT))
    assert extract_iocs(defang(REPORT)) == original


def test_oversized_input_is_rejected():
    with pytest.raises(ValueError, match="too long"):
        extract_iocs("a" * (MAX_TEXT_CHARS + 1))


def test_pathological_input_is_fast():
    import time

    start = time.perf_counter()
    extract_iocs(("a." * 50 + " ") * 1000 + "-" * 20000 + "0" * 20000 + "a" * 9000 + "@")
    assert time.perf_counter() - start < 5
