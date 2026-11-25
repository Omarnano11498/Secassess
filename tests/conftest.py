"""Test fixtures. Network and subprocess access are blocked for the entire suite."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path

import pytest

from secassess.errors import ToolError
from secassess.runner import CommandResult


class FakeRunner:
    """Records argv lists and returns canned results; never executes anything."""

    def __init__(self, tools: dict[str, str] | None = None) -> None:
        self.tools = tools or {}
        self.calls: list[list[str]] = []
        self.responses: list[CommandResult | Exception] = []

    def which(self, name: str) -> str | None:
        return self.tools.get(name)

    def queue(self, stdout: str = "", returncode: int = 0, stderr: str = "") -> None:
        self.responses.append(CommandResult(("fake",), returncode, stdout, stderr))

    def queue_error(self, exc: Exception) -> None:
        self.responses.append(exc)

    def run(self, argv: list[str], timeout: float) -> CommandResult:
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
        assert timeout > 0
        self.calls.append(argv)
        if argv[-1] == "--version":
            name = Path(argv[0]).name
            return CommandResult(tuple(argv), 0, f"Nmap version 7.95 ( {name} )", "")
        if not self.responses:
            raise ToolError("FakeRunner: no response queued")
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp


@pytest.fixture(autouse=True)
def _no_network_or_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_a: object, **_k: object) -> None:
        raise RuntimeError("network/subprocess access attempted during tests")

    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(subprocess, "Popen", blocked)


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    path = tmp_path / "cfg.toml"
    path.write_text(
        """
[scope]
allowed_cidrs = ["192.0.2.0/24", "10.10.0.0/24", "2001:db8::/48"]
allowed_hostnames = ["web01.example.com"]
max_hosts = 512

[network]
max_rate = 20
top_ports = 50

[audit]
log_path = "audit.log"
""",
        encoding="utf-8",
    )
    return path


NMAP_DISCOVERY_XML = """<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" version="7.95">
  <host><status state="up"/><address addr="10.10.0.5" addrtype="ipv4"/></host>
  <host><status state="down"/><address addr="10.10.0.6" addrtype="ipv4"/></host>
  <host><status state="up"/><address addr="203.0.113.99" addrtype="ipv4"/></host>
</nmaprun>"""

NMAP_PORTS_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95">
  <host><status state="up"/><address addr="10.10.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu 3ubuntu0.1"/></port>
      <port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="http" tunnel="ssl" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="6379"><state state="closed"/><service name="redis"/></port>
    </ports>
  </host>
</nmaprun>"""
