"""Dry-run behaviour, confirmation and mocked active scans through the CLI."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from secassess.cli import Deps, main
from secassess.config import NetworkSettings
from secassess.errors import ToolError
from secassess.network.nmap_scanner import assert_safe_argv, build_port_argv, parse_nmap_xml
from tests.conftest import NMAP_DISCOVERY_XML, NMAP_PORTS_XML, FakeRunner


def make_deps(runner: FakeRunner, answer: str = "", tty: bool = False) -> Deps:
    return Deps(
        runner=runner,
        resolver=lambda _h: ["10.10.0.7"],
        prompt=lambda _p: answer,
        stdin_is_tty=lambda: tty,
        privileged=lambda: False,
        out=io.StringIO(),
    )


def scope_id(config: Path, *targets: str) -> str:
    from secassess.config import load_settings

    s = load_settings(config)
    return s.scope.fingerprint(s.scope.validate(list(targets)))


def test_dry_run_is_default_and_sends_nothing(config_file: Path, tmp_path: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    deps = make_deps(runner)
    out = tmp_path / "r.json"
    rc = main(["network", "-c", str(config_file), "-t", "192.0.2.0/28", "--json", str(out)], deps)
    assert rc == 0
    # Only the local version probe ran; no scan argv was executed.
    assert runner.calls == [["/usr/bin/nmap", "--version"]]
    data = json.loads(out.read_text())
    assert data["mode"] == "dry-run"
    assert {c["status"] for c in data["checks"]} <= {"planned", "skipped"}
    assert all(c["impact"] for c in data["checks"] if c["active"])
    assert "documentation" in data["sections"]["next_step"]["to_run_actively"]


def test_dry_run_private_range_suggests_confirm(config_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    deps = make_deps(FakeRunner({"nmap": "/usr/bin/nmap"}))
    assert (
        main(["network", "-c", str(config_file), "-t", "10.10.0.0/28", "--json", str(out)], deps)
        == 0
    )
    data = json.loads(out.read_text())
    assert (
        f"--confirm-scope {data['scope']['scope_id']}"
        in (data["sections"]["next_step"]["to_run_actively"])
    )


def test_dry_run_without_nmap_reports_skip(config_file: Path) -> None:
    deps = make_deps(FakeRunner({}))
    assert main(["network", "-c", str(config_file), "-t", "192.0.2.1"], deps) == 0
    text = deps.out.getvalue()  # type: ignore[union-attr]
    assert "nmap unavailable" in text


def test_out_of_scope_rejected_exit_2(
    config_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    rc = main(
        ["network", "-c", str(config_file), "-t", "8.8.8.8", "--active", "--confirm-scope", "x"],
        make_deps(runner),
    )
    assert rc == 2
    assert "outside the approved scope" in capsys.readouterr().err
    assert runner.calls == []


def test_active_requires_confirmation(config_file: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    rc = main(
        ["network", "-c", str(config_file), "-t", "10.10.0.0/28", "--active"],
        make_deps(runner, tty=False),
    )
    assert rc == 3
    assert not any("-sn" in c for c in runner.calls)


def test_active_wrong_interactive_answer(config_file: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    rc = main(
        ["network", "-c", str(config_file), "-t", "10.10.0.0/28", "--active"],
        make_deps(runner, answer="yes", tty=True),
    )
    assert rc == 3


def test_active_wrong_scope_id(config_file: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    rc = main(
        [
            "network",
            "-c",
            str(config_file),
            "-t",
            "10.10.0.0/28",
            "--active",
            "--confirm-scope",
            "000000000000",
        ],
        make_deps(runner),
    )
    assert rc == 3


def test_active_refuses_documentation_range(config_file: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    sid = scope_id(config_file, "192.0.2.0/28")
    rc = main(
        [
            "network",
            "-c",
            str(config_file),
            "-t",
            "192.0.2.0/28",
            "--active",
            "--confirm-scope",
            sid,
        ],
        make_deps(runner),
    )
    assert rc == 2


def test_active_without_nmap_errors(config_file: Path) -> None:
    sid = scope_id(config_file, "10.10.0.0/28")
    rc = main(
        [
            "network",
            "-c",
            str(config_file),
            "-t",
            "10.10.0.0/28",
            "--active",
            "--confirm-scope",
            sid,
        ],
        make_deps(FakeRunner({})),
    )
    assert rc == 4


def test_active_scan_mocked_end_to_end(config_file: Path, tmp_path: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    runner.queue(NMAP_DISCOVERY_XML)
    runner.queue(NMAP_PORTS_XML)
    sid = scope_id(config_file, "10.10.0.0/28", "web01.example.com")
    out = tmp_path / "r.json"
    rc = main(
        [
            "network",
            "-c",
            str(config_file),
            "-t",
            "10.10.0.0/28",
            "-t",
            "web01.example.com",
            "--active",
            "--confirm-scope",
            sid,
            "--json",
            str(out),
            "--fail-on",
            "high",
        ],
        make_deps(runner),
    )
    assert rc == 1  # telnet => high
    discovery, ports = runner.calls[1], runner.calls[2]
    assert "-sn" in discovery and "10.10.0.7" in discovery  # hostname resolved to IP
    assert "web01.example.com" not in discovery
    assert ports[-1] == "10.10.0.5"  # only the in-scope host found up
    assert "203.0.113.99" not in ports
    data = json.loads(out.read_text())
    assert data["mode"] == "active"
    ids = {f["id"].split(":")[0] for f in data["findings"]}
    assert "EXP-TELNET" in ids
    assert "EXP-HTTP-CLEARTEXT" not in ids  # TLS-wrapped http is not flagged
    assert "EXP-DATASTORE" not in ids  # closed port is not flagged
    assert any("out-of-scope" in e for e in data["errors"])
    assert data["attack_paths"][0]["status"] == "explained_only_not_tested"
    audit = (config_file.parent / "audit.log").read_text().splitlines()
    events = [json.loads(line)["event"] for line in audit]
    assert events[0] == "run_start" and "confirmed" in events and events[-1] == "run_end"


def test_active_scan_tool_failure_reported(config_file: Path, tmp_path: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    runner.queue_error(ToolError("nmap timed out after 1800s"))
    sid = scope_id(config_file, "10.10.0.0/28")
    out = tmp_path / "r.json"
    rc = main(
        [
            "network",
            "-c",
            str(config_file),
            "-t",
            "10.10.0.0/28",
            "--active",
            "--confirm-scope",
            sid,
            "--json",
            str(out),
        ],
        make_deps(runner),
    )
    assert rc == 4  # a failed scan is not a clean result
    data = json.loads(out.read_text())
    failed = {c["name"] for c in data["skipped_or_failed_checks"] if c["status"] == "failed"}
    assert "network.discovery" in failed
    assert data["findings"] == []


def test_os_detect_without_privileges_is_skipped_not_substituted(
    config_file: Path, tmp_path: Path
) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})
    runner.queue(NMAP_DISCOVERY_XML)
    runner.queue(NMAP_PORTS_XML)
    sid = scope_id(config_file, "10.10.0.0/28")
    out = tmp_path / "r.json"
    main(
        [
            "network",
            "-c",
            str(config_file),
            "-t",
            "10.10.0.0/28",
            "--active",
            "--os-detect",
            "--confirm-scope",
            sid,
            "--json",
            str(out),
        ],
        make_deps(runner),
    )
    assert all("-O" not in c for c in runner.calls)
    data = json.loads(out.read_text())
    osfp = next(c for c in data["checks"] if c["name"] == "network.os_fingerprint")
    assert osfp["status"] == "skipped" and "privileges" in osfp["detail"]


def test_argv_safety_guard() -> None:
    s = NetworkSettings()
    argv = build_port_argv("/usr/bin/nmap", s, ["10.0.0.1"], os_detect=False)
    assert_safe_argv(argv, s)
    assert "--script" not in " ".join(argv)
    for bad in (["--script", "vuln"], ["-A"], ["-T5"], ["--script=default"]):
        with pytest.raises(ToolError):
            assert_safe_argv([*argv, *bad], s)
    with pytest.raises(ToolError):
        build_port_argv("/usr/bin/nmap", s, ["-oN/etc/passwd"], os_detect=False)


def test_xml_parser_rejects_entities_and_garbage() -> None:
    with pytest.raises(ToolError):
        parse_nmap_xml('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>')
    with pytest.raises(ToolError):
        parse_nmap_xml("not xml")
    with pytest.raises(ToolError):
        parse_nmap_xml("<other/>")
    hosts, version = parse_nmap_xml(NMAP_PORTS_XML)
    assert version == "7.95" and hosts[0].services[0].product == "OpenSSH"


def test_scope_preview(config_file: Path) -> None:
    deps = make_deps(FakeRunner())
    assert main(["scope-preview", "-c", str(config_file), "-t", "192.0.2.0/30"], deps) == 0
    assert "scope_id" in deps.out.getvalue()  # type: ignore[union-attr]


def test_dry_run_with_hostname_makes_no_dns_lookup(config_file: Path) -> None:
    runner = FakeRunner({"nmap": "/usr/bin/nmap"})

    def no_dns(_h: str) -> list[str]:
        raise AssertionError("dry-run must not resolve hostnames")

    deps = make_deps(runner)
    deps.resolver = no_dns
    assert main(["network", "-c", str(config_file), "-t", "web01.example.com"], deps) == 0
    assert "resolved and each address" in deps.out.getvalue()  # type: ignore[union-attr]
