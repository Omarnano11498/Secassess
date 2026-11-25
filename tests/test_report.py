"""JSON report generation and redaction."""

from __future__ import annotations

import json
from pathlib import Path

from secassess.models import (
    CheckRecord,
    CheckStatus,
    Confidence,
    Finding,
    FindingKind,
    Host,
    Service,
    Severity,
)
from secassess.redact import redact
from secassess.reporting.report import Report, render_text, write_json


def sample_report() -> Report:
    r = Report(command="network", run_id="abc", mode="active", started_at="t0", finished_at="t1")
    r.scope = {"allowed_cidrs": ["10.0.0.0/24"], "targets": ["10.0.0.1"]}
    r.hosts = [Host("10.0.0.1", "up", [Service(23, "tcp", "open", "telnet")])]
    r.findings = [
        Finding(
            "LOW1",
            "low",
            "x",
            Severity.LOW,
            Confidence.HIGH,
            FindingKind.OBSERVED,
            "10.0.0.1",
            ["e"],
            "r",
            "fix",
        ),
        Finding(
            "HIGH1",
            "high",
            "x",
            Severity.HIGH,
            Confidence.MEDIUM,
            FindingKind.INFERRED,
            "10.0.0.1",
            ["password=hunter2hunter2"],
            "r",
            "fix",
        ),
    ]
    r.checks = [
        CheckRecord("a", CheckStatus.COMPLETED),
        CheckRecord("b", CheckStatus.SKIPPED, "missing tool"),
    ]
    return r


def test_json_report_structure(tmp_path: Path) -> None:
    out = tmp_path / "sub" / "report.json"
    write_json(sample_report(), out)
    data = json.loads(out.read_text())
    for key in (
        "schema_version",
        "tool",
        "run_id",
        "mode",
        "started_at",
        "finished_at",
        "scope",
        "methodology",
        "tool_versions",
        "summary",
        "hosts",
        "findings",
        "checks",
        "skipped_or_failed_checks",
        "errors",
        "limitations",
        "environment",
    ):
        assert key in data
    assert data["findings"][0]["id"] == "HIGH1"  # sorted most severe first
    assert data["summary"]["findings_by_severity"] == {"high": 1, "low": 1}
    assert data["skipped_or_failed_checks"][0]["name"] == "b"
    assert "hunter2" not in out.read_text()  # inline secret redacted


def test_redact_keys_and_inline() -> None:
    data = redact(
        {
            "snmp_community": "public",
            "api_key": "x",
            "nested": [{"token": "y"}],
            "note": "Bearer abcdefghijklmnop",
            "fine": "ok",
        }
    )
    assert data["snmp_community"] == "[REDACTED]" and data["api_key"] == "[REDACTED]"
    assert data["nested"][0]["token"] == "[REDACTED]"
    assert "abcdefghijklmnop" not in data["note"]
    assert data["fine"] == "ok"


def test_text_rendering() -> None:
    text = render_text(sample_report())
    assert "FINDINGS (2)" in text and "10.0.0.1" in text and "SKIPPED" in text


def test_empty_findings_text() -> None:
    r = Report(command="project", run_id="x", mode="local", started_at="t")
    assert "not proof of security" in render_text(r)
