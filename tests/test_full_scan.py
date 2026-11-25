"""`secassess full`: runs every part, tolerates missing tools and failing parts."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

from secassess.cli import DEFAULT_SEMGREP_RULES, Deps, main
from tests.conftest import FakeRunner


def _deps() -> tuple[Deps, io.StringIO]:
    out = io.StringIO()
    return Deps(runner=FakeRunner(), privileged=lambda: False, out=out), out


def _project(tmp_path: Path) -> Path:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "app.py").write_text("print('hi')\n", encoding="utf-8")
    return proj


def test_bundled_semgrep_rules_exist() -> None:
    assert DEFAULT_SEMGREP_RULES.is_file()
    assert "rules:" in DEFAULT_SEMGREP_RULES.read_text(encoding="utf-8")


def test_project_runs_semgrep_by_default(tmp_path: Path) -> None:
    runner = FakeRunner({"semgrep": "/opt/semgrep"})
    runner.queue('{"results": [], "errors": []}')
    out = io.StringIO()
    deps = Deps(runner=runner, privileged=lambda: False, out=out)
    rc = main(["--audit-log", str(tmp_path / "a.log"), "project", str(_project(tmp_path))], deps)
    assert rc == 0
    scan = next(c for c in runner.calls if "scan" in c)
    assert scan[scan.index("--config") + 1] == str(DEFAULT_SEMGREP_RULES.resolve())
    assert "--metrics=off" in scan
    assert "project.semgrep [ACTIVE]: 0 match(es)" in out.getvalue()

    runner.calls.clear()
    rc = main(
        ["--audit-log", str(tmp_path / "a.log"), "project", str(tmp_path / "proj"), "--no-semgrep"],
        deps,
    )
    assert rc == 0
    assert not any("scan" in c for c in runner.calls)


def test_full_runs_all_parts_and_writes_word(tmp_path: Path, config_file: Path) -> None:
    deps, out = _deps()
    out_dir = tmp_path / "reports"
    rc = main(
        [
            "--audit-log", str(tmp_path / "a.log"),
            "full",
            "--project", str(_project(tmp_path)),
            "-c", str(config_file),
            "-t", "192.0.2.0/28",
            "--out-dir", str(out_dir),
        ],
        deps,
    )  # fmt: skip
    assert rc == 0
    names = sorted(p.name.split("-")[0] for p in out_dir.glob("*.json"))
    assert names == ["hardware", "network", "project"]
    docx = next(out_dir.glob("secassess-full-*.docx"))
    with zipfile.ZipFile(docx) as zf:
        assert "word/document.xml" in zf.namelist()
    text = out.getvalue()
    assert "SUMMARY" in text and "WORD REPORT" in text
    assert "semgrep" in text  # tools table printed
    assert "SMART usually needs Administrator" in text


def test_full_without_network_args_skips_network(tmp_path: Path) -> None:
    deps, out = _deps()
    rc = main(
        [
            "--audit-log", str(tmp_path / "a.log"),
            "full", "--project", str(_project(tmp_path)), "--no-smart",
            "--out-dir", str(tmp_path / "r"), "--docx", str(tmp_path / "x.docx"),
        ],
        deps,
    )  # fmt: skip
    assert rc == 0
    assert (tmp_path / "x.docx").exists()
    assert "network   skipped" in out.getvalue()


def test_full_continues_when_a_part_fails(tmp_path: Path) -> None:
    deps, out = _deps()
    rc = main(
        [
            "--audit-log", str(tmp_path / "a.log"),
            "full", "--project", str(_project(tmp_path)),
            "-c", str(tmp_path / "missing.toml"), "-t", "192.0.2.1",
            "--out-dir", str(tmp_path / "r"),
        ],
        deps,
    )  # fmt: skip
    assert rc == 2
    text = out.getvalue()
    assert "network   error:" in text
    assert list((tmp_path / "r").glob("project-*.json"))
    assert list((tmp_path / "r").glob("secassess-full-*.docx"))
