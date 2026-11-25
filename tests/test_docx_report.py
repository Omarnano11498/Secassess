"""Word export: well-formed OOXML, RTL handling, redaction and CLI wiring."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from secassess.cli import Deps, main
from secassess.reporting.docx import build_document_xml, recommendations, runs, write_docx
from tests.conftest import FakeRunner

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _report(command: str, **extra: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": "1.0",
        "tool": {"name": "secassess", "version": "0.1.0"},
        "run_id": f"{command}-run",
        "command": command,
        "mode": "local",
        "started_at": "2026-01-02T03:04:05+00:00",
        "finished_at": "2026-01-02T03:04:06+00:00",
        "environment": {"python": "3.12", "platform": "Windows", "platform_release": "11"},
        "scope": {},
        "methodology": ["method A"],
        "tool_versions": {},
        "summary": {"checks_by_status": {"completed": 1}},
        "hosts": [],
        "findings": [],
        "attack_paths": [],
        "checks": [
            {"name": f"{command}.x", "status": "completed", "detail": "ok", "active": False}
        ],
        "skipped_or_failed_checks": [],
        "sections": {},
        "errors": [],
        "limitations": ["limit B"],
    }
    base.update(extra)
    return base


def _finding(sev: str, title: str, target: str) -> dict[str, object]:
    return {
        "id": title,
        "title": title,
        "category": "c",
        "severity": sev,
        "confidence": "high",
        "kind": "inferred",
        "target": target,
        "evidence": ["e"],
        "rationale": "r",
        "remediation": "fix it",
        "references": [],
    }


def _text(docx: Path) -> str:
    with zipfile.ZipFile(docx) as zf:
        names = set(zf.namelist())
        assert {"[Content_Types].xml", "word/document.xml", "word/styles.xml"} <= names
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                ET.fromstring(zf.read(name))  # every part must be well-formed XML
        root = ET.fromstring(zf.read("word/document.xml"))
    return "".join(t.text or "" for t in root.iter(f"{W}t"))


def test_runs_keep_latin_tokens_ltr() -> None:
    xml = runs("النطاق 192.0.2.0/28 فقط مع --active")
    root = ET.fromstring(f'<x xmlns:w="{W[1:-1]}">{xml}</x>')
    pieces = [
        (r.find(f"{W}t").text, r.find(f"{W}rPr/{W}rtl") is not None)  # type: ignore[union-attr]
        for r in root.iter(f"{W}r")
    ]
    assert ("192.0.2.0/28", False) in pieces
    assert ("--active", False) in pieces
    assert any(rtl for _, rtl in pieces)


def test_write_docx_merges_reports(tmp_path: Path) -> None:
    hw = _report(
        "hardware",
        sections={
            "hardware": {
                "summary": {"overall": "no_data", "explanation": "unknown"},
                "measurements": [
                    {
                        "name": "disk_usage:C:\\",
                        "status": "warning",
                        "source": "s",
                        "value": 93.1,
                        "unit": "% used",
                        "note": "capacity",
                    }
                ],
            }
        },
    )
    proj = _report(
        "project",
        findings=[
            _finding("medium", "Weak thing", "src/a.py:3"),
            *[_finding("low", "Assert used", f"tests/t.py:{i}") for i in range(6)],
        ],
        tool_versions={"semgrep": {"available": False, "purpose": "static analysis"}},
    )
    out = tmp_path / "r.docx"
    write_docx([hw, proj], out)
    text = _text(out)
    assert "Weak thing" in text and "Assert used" in text
    assert "tests/t.py (6×)" in text
    assert "93.1" in text
    # project section comes before hardware regardless of input order
    assert text.index("مراجعة المشروع البرمجي") < text.index("مؤشرات صحة العتاد")
    recs = recommendations([hw, proj])
    assert any("93.1" in r for r in recs)
    assert any("semgrep" in r for r in recs)


def test_docx_redacts_and_strips_control_chars(tmp_path: Path) -> None:
    rep = _report("project", errors=["password=hunter2 \x07bell"])
    xml = build_document_xml([rep])
    assert "\x07" not in xml
    out = tmp_path / "r.docx"
    write_docx([rep], out)
    text = _text(out)
    assert "hunter2" not in text
    assert "[REDACTED]" in text


def test_write_docx_requires_reports(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        write_docx([], tmp_path / "x.docx")


def test_cli_hardware_docx_and_report_merge(tmp_path: Path) -> None:
    deps = Deps(runner=FakeRunner())
    audit = ["--audit-log", str(tmp_path / "a.log")]
    hw_json, hw_docx = tmp_path / "hw.json", tmp_path / "hw.docx"
    rc = main([*audit, "hardware", "--quiet", "--json", str(hw_json), "--docx", str(hw_docx)], deps)
    assert rc == 0 and hw_docx.exists()
    assert "مؤشرات صحة العتاد" in _text(hw_docx)

    proj_json = tmp_path / "p.json"
    (tmp_path / "proj").mkdir()
    (tmp_path / "proj" / "a.py").write_text("x = 1\n", encoding="utf-8")
    rc = main(
        [*audit, "project", str(tmp_path / "proj"), "--quiet", "--json", str(proj_json)], deps
    )
    assert rc == 0

    merged = tmp_path / "all.docx"
    rc = main(["report", str(hw_json), str(proj_json), "--docx", str(merged)], deps)
    assert rc == 0
    text = _text(merged)
    assert "مؤشرات صحة العتاد" in text and "مراجعة المشروع البرمجي" in text


def test_cli_report_rejects_non_report(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"hello": 1}), encoding="utf-8")
    assert main(["report", str(bad), "--docx", str(tmp_path / "o.docx")]) == 2
    assert main(["report", str(tmp_path / "missing.json"), "--docx", str(tmp_path / "o.docx")]) == 2
    assert not (tmp_path / "o.docx").exists()
