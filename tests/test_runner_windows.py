"""Tool discovery outside PATH (relevant mainly on Windows)."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

from secassess import runner
from secassess.runner import OPTIONAL_TOOLS, SubprocessRunner


def test_bandit_version_regex_accepts_windows_exe_name() -> None:
    pattern = OPTIONAL_TOOLS["bandit"][1]
    out = r"python.exe C:\venv\Scripts\bandit.EXE 1.9.4"
    m = re.search(pattern, out)
    assert m and m.group(1) == "1.9.4"
    m = re.search(pattern, "bandit 1.7.5\n  python version = 3.12")
    assert m and m.group(1) == "1.7.5"


@pytest.mark.skipif(os.name != "nt", reason="Windows install locations")
def test_which_falls_back_to_program_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nmap_dir = tmp_path / "Nmap"
    nmap_dir.mkdir()
    (nmap_dir / "nmap.exe").write_bytes(b"")
    monkeypatch.setenv("PATH", "")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.delenv("ProgramW6432", raising=False)
    found = SubprocessRunner().which("nmap")
    assert found is not None
    assert Path(found).parent == nmap_dir


def test_fallback_includes_interpreter_dir() -> None:
    dirs = runner._fallback_dirs("bandit")
    assert Path(sys.executable).resolve().parent in dirs
