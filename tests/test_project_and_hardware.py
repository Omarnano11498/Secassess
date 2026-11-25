"""Project review and hardware-health tests (no real tools, no real sensors required)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from secassess.cli import Deps, main
from secassess.errors import SecAssessError
from secassess.hardware.health import (
    Measurement,
    MeasurementStatus,
    collect_battery,
    collect_smart,
    collect_temperatures,
    interpret_smart,
    summarize,
)
from secassess.project_review.reviewer import review_project
from tests.conftest import FakeRunner


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / "src" / "app").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "src" / "app" / "main.py").write_text('API_KEY = "abcd1234efgh5678"\nprint("hi")\n')
    (root / "node_modules" / "x" / "index.js").write_text("ignored")
    (root / "requirements.txt").write_text("flask>=2.0\nrequests==2.31.0\n# comment\n")
    (root / ".env").write_text("SECRET=xyz\n")
    (root / "Dockerfile").write_text("FROM python:3.12\n")
    return root


def test_project_review(project: Path) -> None:
    rep = review_project(project)
    assert rep.languages == {"Python": 1}  # node_modules skipped
    assert "requirements.txt" in rep.manifests
    names = {d.name: d.pinned for d in rep.dependencies}
    assert names == {"flask": False, "requests": True}
    ids = {f.id.split(":")[0] for f in rep.findings}
    assert {"SECRET", "SENSFILE", "NOLOCK", "UNPINNED"} <= ids
    secret = next(f for f in rep.findings if f.id.startswith("SECRET"))
    assert "abcd1234" not in json.dumps(secret.to_dict())
    elements = {a["element"] for a in rep.architecture}
    assert {
        "src/ layout",
        "dedicated test suite",
        "containerized build",
        "Flask web framework",
    } <= elements
    bandit = next(c for c in rep.checks if c.name == "project.bandit")
    assert bandit.status.value == "skipped"


def test_project_bandit_mocked(project: Path) -> None:
    runner = FakeRunner({"bandit": "/usr/bin/bandit"})
    runner.queue(
        json.dumps(
            {
                "results": [
                    {
                        "filename": str(project / "src/app/main.py"),
                        "line_number": 1,
                        "test_id": "B105",
                        "test_name": "hardcoded_password_string",
                        "issue_text": "Possible hardcoded password",
                        "issue_severity": "LOW",
                        "issue_confidence": "MEDIUM",
                        "more_info": "https://x",
                    }
                ]
            }
        ),
        returncode=1,
    )
    rep = review_project(project, runner, run_bandit=True)
    assert runner.calls[0][0] == "/usr/bin/bandit" and "-r" in runner.calls[0]
    assert any(f.id.startswith("BANDIT:B105:src/app/main.py") for f in rep.findings)


def test_project_bandit_missing_and_failure(project: Path) -> None:
    rep = review_project(project, FakeRunner({}), run_bandit=True)
    assert "not installed" in next(c for c in rep.checks if c.name == "project.bandit").detail
    runner = FakeRunner({"bandit": "/usr/bin/bandit"})
    runner.queue("", returncode=2, stderr="boom")
    rep = review_project(project, runner, run_bandit=True)
    assert next(c for c in rep.checks if c.name == "project.bandit").status.value == "failed"


def test_project_bad_path(tmp_path: Path) -> None:
    with pytest.raises(SecAssessError):
        review_project(tmp_path / "nope")


def test_semgrep_requires_local_file(project: Path) -> None:
    rep = review_project(
        project, FakeRunner({"semgrep": "/usr/bin/semgrep"}), semgrep_config=Path("p/ci")
    )
    assert next(c for c in rep.checks if c.name == "project.semgrep").status.value == "failed"


def test_summary_no_data_is_not_healthy() -> None:
    s = summarize(
        [
            Measurement("x", MeasurementStatus.UNAVAILABLE, "s"),
            Measurement("y", MeasurementStatus.UNSUPPORTED, "s"),
        ]
    )
    assert s["overall"] == "no_data" and "UNKNOWN" in s["explanation"]
    s2 = summarize([Measurement("x", MeasurementStatus.OK, "s")])
    assert s2["overall"] == "no_issues_in_available_indicators"
    assert "does not guarantee" in s2["explanation"]
    s3 = summarize(
        [
            Measurement("x", MeasurementStatus.OK, "s"),
            Measurement("y", MeasurementStatus.CRITICAL, "s"),
        ]
    )
    assert s3["overall"] == "critical_indicator_present"


def test_smart_interpretation() -> None:
    ok = interpret_smart(
        "/dev/sda",
        {
            "smart_status": {"passed": True},
            "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 8}}]},
        },
        0,
    )
    statuses = {m.name: m.status for m in ok}
    assert statuses["smart_overall:/dev/sda"] is MeasurementStatus.OK
    assert statuses["smart_reallocated_sectors:/dev/sda"] is MeasurementStatus.WARNING
    failed = interpret_smart("/dev/sda", {"smart_status": {"passed": False}}, 8)
    assert failed[0].status is MeasurementStatus.CRITICAL
    denied = interpret_smart("/dev/sda", {}, 2)
    assert denied[0].status is MeasurementStatus.UNAVAILABLE


def test_smart_missing_tool_and_bad_device() -> None:
    assert collect_smart(FakeRunner({}))[0].status is MeasurementStatus.UNAVAILABLE
    runner = FakeRunner({"smartctl": "/usr/sbin/smartctl"})
    runner.queue(json.dumps({"devices": [{"name": "/dev/sda; rm -rf /", "type": "sat"}]}))
    (m,) = collect_smart(runner)
    assert m.status is MeasurementStatus.ERROR and len(runner.calls) == 1


def test_battery_sysfs(tmp_path: Path) -> None:
    bat = tmp_path / "BAT0"
    bat.mkdir()
    (bat / "energy_full").write_text("40000000")
    (bat / "energy_full_design").write_text("50000000")
    ms = collect_battery(
        psutil_mod=SimpleNamespace(sensors_battery=lambda: None), sysfs=tmp_path, system="Linux"
    )
    wear = next(m for m in ms if m.name.startswith("battery_capacity"))
    assert wear.value == 80.0 and wear.status is MeasurementStatus.OK
    assert any(m.status is MeasurementStatus.UNAVAILABLE for m in ms)


def test_temperatures_none_available(tmp_path: Path) -> None:
    ms = collect_temperatures(
        psutil_mod=SimpleNamespace(sensors_temperatures=lambda: {}), thermal=tmp_path / "none"
    )
    assert ms[0].status is MeasurementStatus.UNAVAILABLE


def test_hardware_cli(tmp_path: Path) -> None:
    out = tmp_path / "hw.json"
    deps = Deps(runner=FakeRunner({}), out=io.StringIO())
    rc = main(["--audit-log", str(tmp_path / "a.log"), "hardware", "--json", str(out)], deps)
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["sections"]["hardware"]["summary"]["overall"]
    smart = next(m for m in data["sections"]["hardware"]["measurements"] if m["name"] == "smart")
    assert smart["status"] == "unavailable" and smart["timestamp"]


def test_project_cli_dry_run_runs_nothing(project: Path, tmp_path: Path) -> None:
    runner = FakeRunner({"bandit": "/usr/bin/bandit"})
    deps = Deps(runner=runner, out=io.StringIO())
    rc = main(
        ["--audit-log", str(tmp_path / "a.log"), "project", str(project), "--bandit", "--dry-run"],
        deps,
    )
    assert rc == 0 and runner.calls == []


def test_capacity_only_readings_do_not_count_as_health() -> None:
    s = summarize(
        [
            Measurement("disk_usage:/", MeasurementStatus.OK, "shutil", 10, health_indicator=False),
            Measurement("smart", MeasurementStatus.UNAVAILABLE, "smartctl"),
        ]
    )
    assert s["overall"] == "no_data"
