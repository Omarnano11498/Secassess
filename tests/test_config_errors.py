"""Configuration validation and error-path tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from secassess.cli import main
from secassess.config import load_settings, parse_settings
from secassess.errors import ConfigError, ScopeError, ToolError
from secassess.runner import SubprocessRunner, detect_tool
from tests.conftest import FakeRunner


def base(**network: object) -> dict[str, object]:
    return {"scope": {"allowed_cidrs": ["10.0.0.0/24"]}, "network": network}


@pytest.mark.parametrize(
    "net",
    [
        {"max_rate": 10000},
        {"timing_template": 4},
        {"top_ports": 0},
        {"max_retries": "1"},
        {"version_detection": "yes"},
    ],
)
def test_unsafe_network_settings_rejected(net: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        parse_settings(base(**net))


def test_missing_scope_and_unknown_section() -> None:
    with pytest.raises(ConfigError, match=r"\[scope\]"):
        parse_settings({})
    with pytest.raises(ConfigError, match="unknown"):
        parse_settings({**base(), "attack": {}})
    with pytest.raises(ScopeError):
        parse_settings({"scope": {"allowed_cidrs": ["not-a-cidr"]}})


def test_bad_files(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_settings(tmp_path / "nope.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[scope\n")
    with pytest.raises(ConfigError):
        load_settings(bad)


def test_cli_config_error_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["network", "-c", str(tmp_path / "missing.toml"), "-t", "10.0.0.1"])
    assert rc == 2 and "cannot read configuration" in capsys.readouterr().err


def test_example_config_is_valid() -> None:
    cfg = Path(__file__).resolve().parents[1] / "config" / "example.toml"
    s = load_settings(cfg)
    assert all(
        str(n).startswith(("192.0.2.", "198.51.100.", "2001:db8")) for n in s.scope.allowed_networks
    )


def test_detect_tool_missing() -> None:
    info = detect_tool(FakeRunner({}), "nmap")
    assert not info.available and "not found" in info.note


def test_subprocess_runner_validates_argv() -> None:
    with pytest.raises(ToolError):
        SubprocessRunner().run([], timeout=1)
    with pytest.raises(ToolError):
        SubprocessRunner().run(["x\x00y"], timeout=1)


def test_mutually_exclusive_modes(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["network", "-c", "x", "-t", "10.0.0.1", "--dry-run", "--active"])
