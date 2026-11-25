"""Risk severity handling and advisory correlation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secassess.errors import ConfigError
from secassess.models import Confidence, FindingKind, Host, Service, Severity
from secassess.risk.advisories import AdvisoryDB, load_advisories, parse_version
from secassess.risk.analyzer import analyze_hosts, exceeds_threshold, max_severity


def write_adv(tmp_path: Path, entries: list[dict[str, object]]) -> Path:
    p = tmp_path / "adv.json"
    p.write_text(
        json.dumps({"schema_version": 1, "source": "unit-test fixture", "advisories": entries})
    )
    return p


ADV = {
    "id": "TEST-0001",
    "product": "ExampleD",
    "severity": "critical",
    "summary": "test advisory",
    "affected": [{"introduced": "1.0", "fixed": "1.4.2"}],
    "versions": ["2.0.0"],
}


def host(*services: Service) -> Host:
    return Host("10.0.0.1", "up", list(services))


def test_severity_parse_and_order() -> None:
    assert Severity.parse("HIGH") is Severity.HIGH
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO
    with pytest.raises(ValueError):
        Severity.parse("urgent")


def test_threshold() -> None:
    f = analyze_hosts([host(Service(21, "tcp", "open", "ftp"))], AdvisoryDB())
    assert max_severity(f) is Severity.MEDIUM
    assert exceeds_threshold(f, Severity.MEDIUM)
    assert not exceeds_threshold(f, Severity.HIGH)
    assert not exceeds_threshold([], Severity.INFO)
    assert not exceeds_threshold(f, None)


def test_version_parse() -> None:
    assert parse_version("8.9p1 Ubuntu") == (8, 9, 1)
    assert parse_version("1.18.0") == (1, 18, 0)
    assert parse_version("unknown") is None
    assert parse_version("") is None


def test_version_match_is_never_confirmed(tmp_path: Path) -> None:
    db = load_advisories([write_adv(tmp_path, [ADV])])
    svc = Service(8080, "tcp", "open", "http-alt", "ExampleD", "1.4.1")
    (adv,) = [f for f in analyze_hosts([host(svc)], db) if f.category == "advisory"]
    assert adv.kind is FindingKind.POTENTIAL_VULNERABILITY
    assert adv.confidence is Confidence.LOW  # range match
    assert adv.severity is Severity.CRITICAL  # advisory severity kept, confidence separate
    assert "not confirmed" in adv.rationale
    assert "Potentially" in adv.title


def test_exact_match_medium_and_backport_low(tmp_path: Path) -> None:
    db = load_advisories([write_adv(tmp_path, [ADV])])
    exact = Service(80, "tcp", "open", "http", "exampled", "2.0.0")
    backport = Service(81, "tcp", "open", "http", "ExampleD", "2.0.0", "Ubuntu 1ubuntu2")
    found = {
        f.target: f for f in analyze_hosts([host(exact, backport)], db) if f.category == "advisory"
    }
    assert found["10.0.0.1:80/tcp"].confidence is Confidence.MEDIUM
    assert found["10.0.0.1:81/tcp"].confidence is Confidence.LOW
    assert all(f.confidence < Confidence.HIGH for f in found.values())


def test_fixed_version_not_matched(tmp_path: Path) -> None:
    db = load_advisories([write_adv(tmp_path, [ADV])])
    svc = Service(80, "tcp", "open", "http", "ExampleD", "1.4.2")
    assert not [f for f in analyze_hosts([host(svc)], db) if f.category == "advisory"]


def test_port_only_match_lowers_confidence() -> None:
    (f,) = analyze_hosts([host(Service(23, "tcp", "open"))], AdvisoryDB())
    assert f.severity is Severity.HIGH and f.confidence is Confidence.MEDIUM
    # A different service on a "telnet" port is not flagged.
    assert analyze_hosts([host(Service(23, "tcp", "open", "ssh"))], AdvisoryDB()) == []


def test_findings_sorted_by_severity() -> None:
    f = analyze_hosts(
        [host(Service(80, "tcp", "open", "http"), Service(23, "tcp", "open", "telnet"))],
        AdvisoryDB(),
    )
    assert [x.severity for x in f] == sorted((x.severity for x in f), reverse=True)


def test_invalid_advisory_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_advisories([tmp_path / "missing.json"])
    bad = tmp_path / "bad.json"
    bad.write_text("{")
    with pytest.raises(ConfigError):
        load_advisories([bad])
    with pytest.raises(ConfigError, match="unknown severity"):
        load_advisories([write_adv(tmp_path, [{**ADV, "severity": "urgent"}])])
    with pytest.raises(ConfigError):
        load_advisories([write_adv(tmp_path, [{**ADV, "affected": [], "versions": []}])])
