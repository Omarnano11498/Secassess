"""Safe external-command execution and optional-tool detection.

All external tools are invoked through :class:`CommandRunner` with an argv list (never a shell
string), an explicit timeout and a minimal, predictable environment. Tests replace the runner with
a fake so no real tool is ever executed during the test suite.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from secassess.errors import ToolError

log = logging.getLogger(__name__)

MAX_OUTPUT_BYTES = 50 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Result of one external command."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """Anything that can run an argv list with a timeout."""

    def which(self, name: str) -> str | None:
        """Return the absolute path of ``name`` or None."""
        ...

    def run(self, argv: list[str], timeout: float) -> CommandResult:
        """Run ``argv`` and return its result. Must raise ToolError on timeout/launch failure."""
        ...


class SubprocessRunner:
    """Production runner using :func:`subprocess.run` with ``shell=False``."""

    def which(self, name: str) -> str | None:
        """Locate an executable on PATH, then in well-known install locations.

        The fallback matters mostly on Windows, where the Nmap and smartmontools installers do
        not always add themselves to PATH, and where tools installed into a virtual environment
        (e.g. bandit) are not on PATH unless the venv is activated.
        """
        found = shutil.which(name)
        if found:
            return found
        for directory in _fallback_dirs(name):
            found = shutil.which(name, path=str(directory))
            if found:
                return found
        return None

    def run(self, argv: list[str], timeout: float) -> CommandResult:
        """Execute ``argv`` safely; never uses a shell."""
        if not argv or not all(isinstance(a, str) for a in argv):
            raise ToolError("argv must be a non-empty list of strings")
        if any("\x00" in a for a in argv):
            raise ToolError("argv contains NUL bytes")
        log.debug("running external tool: %s", argv[0])
        env = {k: v for k, v in os.environ.items() if k in _SAFE_ENV_KEYS}
        env["LC_ALL"] = "C"
        try:
            proc = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                timeout=timeout,
                check=False,
                stdin=subprocess.DEVNULL,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"{os.path.basename(argv[0])} timed out after {timeout:.0f}s") from exc
        except OSError as exc:
            raise ToolError(f"could not launch {os.path.basename(argv[0])}: {exc}") from exc
        stdout = proc.stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        stderr = proc.stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        return CommandResult(tuple(argv), proc.returncode, stdout, stderr)


_SAFE_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
    }
)

# Default install sub-directories of optional tools on Windows (relative to Program Files).
_WINDOWS_INSTALL_SUBDIRS: dict[str, tuple[str, ...]] = {
    "nmap": ("Nmap",),
    "smartctl": ("smartmontools\\bin",),
}


def _fallback_dirs(name: str) -> list[Path]:
    """Directories searched when ``name`` is not on PATH."""
    dirs: list[Path] = []
    # Scripts/bin directory of the running interpreter (virtual environment without activation).
    dirs.append(Path(sys.executable).resolve().parent)
    # Per-user tool installs (uv tool / pipx), e.g. semgrep installed with `uv tool install`.
    dirs.append(Path.home() / ".local" / "bin")
    if os.name == "nt":
        dirs.append(Path(sys.executable).parent / "Scripts")
        roots = {
            os.environ.get(var) for var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")
        }
        for root in sorted(r for r in roots if r):
            for sub in _WINDOWS_INSTALL_SUBDIRS.get(name, ()):
                dirs.append(Path(root) / sub)
    return [d for d in dirs if d.is_dir()]


@dataclass(frozen=True, slots=True)
class ToolInfo:
    """Availability and version of an optional external tool."""

    name: str
    available: bool
    path: str | None
    version: str | None
    purpose: str
    note: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize for reports."""
        return {
            "name": self.name,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "purpose": self.purpose,
            "note": self.note,
        }


OPTIONAL_TOOLS: dict[str, tuple[list[str], str, str]] = {
    # name: (version argv suffix, version regex, purpose)
    "nmap": (["--version"], r"Nmap version ([\w.\-]+)", "host/port/service discovery"),
    "bandit": (
        ["--version"],
        r"(?i)bandit(?:\.exe)? (\d[\w.\-]*)",
        "Python static security analysis",
    ),
    "semgrep": (["--version"], r"([\d.]+)", "multi-language static analysis (local rules)"),
    "smartctl": (["--version"], r"smartctl ([\w.\-]+)", "read-only SMART disk health"),
}


DEFAULT_DETECT_TIMEOUT = 15.0
# Semgrep is a large Python application: its first start (cold disk cache, antivirus scan) can take
# far longer than a native tool, and must not be mistaken for a missing installation.
_DETECT_TIMEOUTS: dict[str, float] = {"semgrep": 90.0, "bandit": 45.0}


def detect_tool(runner: CommandRunner, name: str, timeout: float | None = None) -> ToolInfo:
    """Detect an optional tool and its version without failing if it is missing."""
    version_args, pattern, purpose = OPTIONAL_TOOLS[name]
    if timeout is None:
        timeout = _DETECT_TIMEOUTS.get(name, DEFAULT_DETECT_TIMEOUT)
    path = runner.which(name)
    if path is None:
        return ToolInfo(
            name, False, None, None, purpose, "not found on PATH or default install locations"
        )
    try:
        result = runner.run([path, *version_args], timeout=timeout)
    except ToolError as exc:
        return ToolInfo(name, False, path, None, purpose, f"found but not runnable: {exc}")
    match = re.search(pattern, result.stdout + "\n" + result.stderr)
    version = match.group(1) if match else None
    return ToolInfo(name, True, path, version, purpose, "" if version else "version unknown")


def detect_all(runner: CommandRunner) -> dict[str, ToolInfo]:
    """Detect all optional tools."""
    return {name: detect_tool(runner, name) for name in OPTIONAL_TOOLS}
