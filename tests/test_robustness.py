"""Regression tests: malformed input, slow tools, IPv6 plans and unwritable outputs."""

from __future__ import annotations

import io
import json
import urllib.request
from pathlib import Path

import pytest

from secassess.cli import Deps, main
from secassess.config import NetworkSettings, load_settings, parse_settings
from secassess.errors import ConfigError, ToolError
from secassess.models import CheckStatus
from secassess.network.nmap_scanner import build_plan, execute_plan
from secassess.project_review.reviewer import review_project
from secassess.redact import redact_text
from secassess.risk.advisories import load_advisories
from secassess.risk.nvd import _NoRedirect, convert_cve
from secassess.runner import CommandResult, ToolInfo, detect_tool
from secassess.scope import ScopePolicy
from tests.conftest import FakeRunner

NMAP = ToolInfo("nmap", True, "nmap", "7.95", "")


def _xml(addr: str, kind: str) -> str:
    return (
        '<nmaprun version="7.95"><host><status state="up"/>'
        f'<address addr="{addr}" addrtype="{kind}"/><ports/></host></nmaprun>'
    )


def test_config_with_bom_is_accepted(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    cfg.write_bytes(b'\xef\xbb\xbf[scope]\nallowed_cidrs = ["10.0.0.0/24"]\n')
    assert load_settings(cfg).scope.max_hosts == 256


@pytest.mark.parametrize("section", ["network", "advisories", "audit"])
def test_scalar_sections_are_config_errors(section: str) -> None:
    with pytest.raises(ConfigError, match="must be a table"):
        parse_settings({"scope": {"allowed_cidrs": ["10.0.0.0/24"]}, section: 3})


def test_undecodable_json_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "utf16.json"
    bad.write_bytes("{}".encode("utf-16"))
    assert main(["advisories", "show", str(bad)], Deps(runner=FakeRunner())) == 2
    assert main(["report", str(bad), "--docx", str(tmp_path / "o.docx")], Deps()) == 2
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("affected", [3, [{"introduced": "1.0", "fixed": "r2"}]])
def test_bad_advisory_ranges_rejected(tmp_path: Path, affected: object) -> None:
    doc = {
        "schema_version": 1,
        "advisories": [
            {"id": "X", "product": "p", "severity": "high", "summary": "s", "affected": affected}
        ],
    }
    path = tmp_path / "a.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_advisories([path])


def test_nvd_exclusive_start_is_exclusive(tmp_path: Path) -> None:
    cve = {
        "id": "CVE-E",
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                                "versionStartExcluding": "8.0",
                                "versionEndExcluding": "9.0",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    adv = convert_cve(cve, "OpenSSH", ["openbsd:openssh"])
    assert adv is not None and adv["affected"] == [{"introduced_after": "8.0", "fixed": "9.0"}]
    path = tmp_path / "a.json"
    path.write_text(json.dumps({"schema_version": 1, "advisories": [adv]}), encoding="utf-8")
    db = load_advisories([path])
    assert not db.match("OpenSSH", "8.0")
    assert db.match("OpenSSH", "8.1")
    assert not db.match("OpenSSH", "9.0")


def test_nvd_redirects_are_not_followed() -> None:
    req = urllib.request.Request("https://services.nvd.nist.gov/x")
    result = _NoRedirect().redirect_request(req, None, 302, "Found", {}, "https://evil.example/")
    assert result is None


def test_unwritable_report_path_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "dir.docx"
    target.mkdir()
    argv = ["--audit-log", str(tmp_path / "a.log"), "hardware", "--quiet", "--docx", str(target)]
    assert main(argv, Deps(runner=FakeRunner(), out=io.StringIO())) == 2
    assert "error:" in capsys.readouterr().err


def test_slow_starting_semgrep_gets_a_longer_detection_timeout() -> None:
    seen: list[float] = []

    class Recorder(FakeRunner):
        def run(self, argv: list[str], timeout: float) -> CommandResult:
            seen.append(timeout)
            return CommandResult(tuple(argv), 0, "1.187.0", "")

    assert detect_tool(Recorder({"semgrep": "semgrep"}), "semgrep").available
    assert seen[0] >= 60


def test_ipv4_and_ipv6_run_separately_and_ipv6_gets_flag() -> None:
    s = NetworkSettings()
    policy = ScopePolicy.build(["10.0.0.0/24", "fd00::/64"])
    plan = build_plan(["10.0.0.1", "fd00::1"], s, NMAP, False, False)
    assert len(plan.discovery_argvs) == 2
    runner = FakeRunner()
    for addr, kind in (("10.0.0.1", "ipv4"), ("fd00::1", "ipv6")) * 2:
        runner.queue(_xml(addr, kind))
    result = execute_plan(plan, s, policy, runner, "nmap")
    assert [h.address for h in result.hosts] == ["10.0.0.1", "fd00::1"]
    for argv in runner.calls:
        assert ("-6" in argv) == ("fd00::1" in argv)
        assert not ("10.0.0.1" in argv and "fd00::1" in argv)


def test_one_failing_family_keeps_the_other_and_is_reported() -> None:
    s = NetworkSettings()
    policy = ScopePolicy.build(["10.0.0.0/24", "fd00::/64"])
    plan = build_plan(["10.0.0.1", "fd00::1"], s, NMAP, False, False)
    runner = FakeRunner()
    runner.queue(_xml("10.0.0.1", "ipv4"))
    runner.queue_error(ToolError("no IPv6 route"))
    runner.queue(_xml("10.0.0.1", "ipv4"))
    result = execute_plan(plan, s, policy, runner, "nmap")
    assert [h.address for h in result.hosts] == ["10.0.0.1"]
    failed = [c for c in result.checks if c.status is CheckStatus.FAILED]
    assert len(failed) == 1 and "no IPv6 route" in failed[0].detail


def test_timed_out_host_is_not_reported_as_clean() -> None:
    s = NetworkSettings()
    policy = ScopePolicy.build(["10.0.0.0/24"])
    plan = build_plan(["10.0.0.0/30"], s, NMAP, False, False)
    two = _xml("10.0.0.1", "ipv4").replace(
        "</nmaprun>",
        '<host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/></host></nmaprun>',
    )
    runner = FakeRunner()
    runner.queue(two)
    runner.queue(two)
    result = execute_plan(plan, s, policy, runner, "nmap")
    assert [h.address for h in result.hosts] == ["10.0.0.1", "10.0.0.2"]
    failed = [c for c in result.checks if c.status is CheckStatus.FAILED]
    assert len(failed) == 1 and failed[0].detail.endswith(": 10.0.0.2")
    scanned = [c for c in result.checks if c.name == "network.portscan" and c not in failed]
    assert [c.detail for c in scanned] == ["1 host(s) scanned"]


@pytest.mark.parametrize(
    "line",
    [
        "DB_PASSWORD = 'abcdefgh1'",
        '"password": "abcdefgh1"',
        "SECRET_KEY = 'abcdefgh1'",
        "access_token: 'abcdefgh1'",
    ],
)
def test_prefixed_and_quoted_secret_names_detected(tmp_path: Path, line: str) -> None:
    (tmp_path / "conf.py").write_text(line + "\n", encoding="utf-8")
    assert any(f.category == "secrets" for f in review_project(tmp_path).findings)


@pytest.mark.parametrize("line", ["password_hint = 'abcdefgh1'", "notapassword = 'abcdefgh1'"])
def test_unrelated_names_not_flagged(tmp_path: Path, line: str) -> None:
    (tmp_path / "conf.py").write_text(line + "\n", encoding="utf-8")
    assert not review_project(tmp_path).findings


def test_redaction_covers_json_style_keys() -> None:
    assert "abcdefgh1" not in redact_text('{"password": "abcdefgh1"}')
