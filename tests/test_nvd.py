"""NVD -> local advisory conversion (no network: HTTP is faked)."""

from __future__ import annotations

import functools
import io
import json
from pathlib import Path

import pytest

from secassess.cli import Deps, main
from secassess.models import Severity
from secassess.risk.advisories import load_advisories
from secassess.risk.nvd import (
    build_advisory_file,
    convert_cve,
    sanitize_advisory,
    urllib_get,
)
from tests.conftest import FakeRunner


def _cve(cve_id: str, matches: list[dict[str, object]], sev: str = "HIGH") -> dict[str, object]:
    return {
        "id": cve_id,
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": f"desc {cve_id}"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": sev}}]},
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": matches}]}],
        "references": [{"url": "https://example.org/a"}],
    }


SSH = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"


def test_convert_ranges_exact_and_skips() -> None:
    cve = _cve(
        "CVE-1",
        [
            {"vulnerable": True, "criteria": SSH, "versionStartIncluding": "8.5p1",
             "versionEndExcluding": "9.8p1"},
            {"vulnerable": True, "criteria": SSH, "versionEndIncluding": "4.3"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:openbsd:openssh:7.7:p1:*:*:*:*:*:*"},
            {"vulnerable": True, "criteria": "cpe:2.3:a:other:thing:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "1"},
            {"vulnerable": False, "criteria": SSH, "versionEndExcluding": "99"},
        ],
    )  # fmt: skip
    adv = convert_cve(cve, "OpenSSH", ["openbsd:openssh"])
    assert adv is not None
    assert adv["affected"] == [
        {"introduced": "8.5p1", "fixed": "9.8p1"},
        {"last_affected": "4.3"},
    ]
    assert adv["versions"] == ["7.7p1"]
    assert adv["severity"] == "high"
    # all-versions wildcard and rejected CVEs cannot be correlated
    assert convert_cve(_cve("CVE-2", [{"vulnerable": True, "criteria": SSH}]), "OpenSSH",
                       ["openbsd:openssh"]) is None  # fmt: skip
    rejected = _cve("CVE-3", [{"vulnerable": True, "criteria": SSH, "versionEndExcluding": "2"}])
    rejected["vulnStatus"] = "Rejected"
    assert convert_cve(rejected, "OpenSSH", ["openbsd:openssh"]) is None


def test_non_numeric_bounds_are_dropped() -> None:
    plus = "cpe:2.3:a:f5:nginx:*:*:*:*:plus:*:*:*"
    cve = _cve(
        "CVE-2022-41741",
        [
            {"vulnerable": True, "criteria": plus, "versionStartIncluding": "r22",
             "versionEndIncluding": "r27"},
            {"vulnerable": True, "criteria": plus, "versionStartIncluding": "r22",
             "versionEndExcluding": "1.23.2"},
        ],
    )  # fmt: skip
    adv = convert_cve(cve, "nginx", ["f5:nginx"])
    assert adv is not None and adv["affected"] == [{"fixed": "1.23.2"}]
    only_plus = _cve(
        "CVE-X", [{"vulnerable": True, "criteria": plus, "versionEndIncluding": "r27"}]
    )
    assert convert_cve(only_plus, "nginx", ["f5:nginx"]) is None
    assert (
        sanitize_advisory({"id": "x", "affected": [{"introduced": "r1", "last_affected": "r2"}]})
        is None
    )


def test_build_file_is_loadable_and_matches(tmp_path: Path) -> None:
    pages = {
        "CVE-A": _cve("CVE-A", [{"vulnerable": True, "criteria": SSH,
                                 "versionStartIncluding": "8.5p1",
                                 "versionEndExcluding": "9.8p1"}]),
        "CVE-B": _cve("CVE-B", [{"vulnerable": True, "criteria": SSH,
                                 "versionEndIncluding": "7.7"}], sev="LOW"),
    }  # fmt: skip
    urls: list[str] = []

    def fake_get(url: str, headers: dict[str, str]) -> bytes:
        urls.append(url)
        assert "User-Agent" in headers
        body = {"totalResults": 2, "resultsPerPage": 2000, "startIndex": 0,
                "vulnerabilities": [{"cve": c} for c in pages.values()]}  # fmt: skip
        return json.dumps(body).encode()

    doc = build_advisory_file(["OpenSSH"], fake_get, Severity.MEDIUM, sleep=lambda _s: None)
    assert [a["id"] for a in doc["advisories"]] == ["CVE-A"]  # LOW filtered out
    assert "virtualMatchString=cpe%3A2.3%3A%2A%3Aopenbsd%3Aopenssh" in urls[0]
    path = tmp_path / "nvd.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    db = load_advisories([path])
    assert db.match("OpenSSH", "9.6p1")
    assert not db.match("OpenSSH", "9.8p1")

    doc_all = build_advisory_file(["OpenSSH"], fake_get, Severity.LOW, sleep=lambda _s: None)
    path.write_text(json.dumps(doc_all), encoding="utf-8")
    db = load_advisories([path])
    assert [m.advisory.id for m in db.match("OpenSSH", "7.7")] == ["CVE-B"]  # inclusive bound
    assert [m.advisory.id for m in db.match("OpenSSH", "7.6p1")] == ["CVE-B"]
    # as in NVD, 7.7p1 is a later release than 7.7 (e.g. CVE-2024-6387: <= 9.8, fixed in 9.8p1)
    assert not [m for m in db.match("OpenSSH", "7.7p1") if m.advisory.id == "CVE-B"]
    assert not [m for m in db.match("OpenSSH", "7.8p1") if m.advisory.id == "CVE-B"]


def test_urllib_get_refuses_other_hosts() -> None:
    from secassess.errors import ToolError

    with pytest.raises(ToolError):
        urllib_get("https://evil.example/x", {})
    with pytest.raises(ToolError):
        urllib_get("http://services.nvd.nist.gov/x", {})


def test_cli_fetch_and_show(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_get(url: str, headers: dict[str, str]) -> bytes:
        cve = _cve("CVE-Z", [{"vulnerable": True, "criteria": SSH, "versionEndExcluding": "9"}])
        return json.dumps({"totalResults": 1, "resultsPerPage": 2000,
                           "vulnerabilities": [{"cve": cve}]}).encode()  # fmt: skip

    out = io.StringIO()
    deps = Deps(runner=FakeRunner(), out=out, http_get=fake_get)
    target = tmp_path / "adv" / "nvd.json"
    monkeypatch.setattr(
        "secassess.cli.build_advisory_file",
        functools.partial(build_advisory_file, sleep=lambda _s: None),
    )
    rc = main(["advisories", "fetch", "--product", "OpenSSH", "--out", str(target)], deps)
    assert rc == 0 and target.exists()
    assert main(["advisories", "show", str(target)], deps) == 0
    assert "OpenSSH" in out.getvalue() and "total: 1" in out.getvalue()
