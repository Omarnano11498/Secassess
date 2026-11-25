"""Configuration loading and validation (TOML, stdlib ``tomllib``)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secassess.errors import ConfigError
from secassess.scope import ScopePolicy

# Hard ceilings: configuration may lower these, never exceed them.
MAX_RATE_CEILING = 500
TOP_PORTS_CEILING = 1000
MAX_TIMING_TEMPLATE = 3  # T4/T5 are aggressive and therefore not allowed


@dataclass(slots=True)
class NetworkSettings:
    """Conservative scanner parameters."""

    top_ports: int = 100
    max_rate: int = 20  # packets per second
    max_retries: int = 1
    host_timeout_seconds: int = 120
    scan_timeout_seconds: int = 1800
    timing_template: int = 2  # T2 "polite"
    version_detection: bool = True
    version_intensity: int = 2  # 0-9; low intensity = fewer probes


@dataclass(slots=True)
class Settings:
    """Fully validated configuration."""

    scope: ScopePolicy
    network: NetworkSettings = field(default_factory=NetworkSettings)
    advisory_paths: list[Path] = field(default_factory=list)
    audit_log_path: Path = Path("secassess-audit.log")
    source_path: Path | None = None


def _int_in_range(section: dict[str, Any], key: str, default: int, lo: int, hi: int) -> int:
    value = section.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer")
    if not lo <= value <= hi:
        raise ConfigError(f"{key}={value} out of allowed range [{lo}, {hi}]")
    return value


def _str_list(section: dict[str, Any], key: str) -> list[str]:
    value = section.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key} must be a list of strings")
    return value


def _table(data: dict[str, Any], name: str) -> dict[str, Any]:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a table")
    return value


def parse_settings(data: dict[str, Any], base_dir: Path | None = None) -> Settings:
    """Validate a parsed TOML document into :class:`Settings`."""
    base = base_dir or Path.cwd()
    known = {"scope", "network", "advisories", "audit"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown configuration sections: {', '.join(sorted(unknown))}")

    scope_raw = data.get("scope")
    if not isinstance(scope_raw, dict):
        raise ConfigError("missing [scope] section")
    allow_public = scope_raw.get("allow_public_targets", False)
    if not isinstance(allow_public, bool):
        raise ConfigError("allow_public_targets must be true or false")
    scope = ScopePolicy.build(
        allowed_cidrs=_str_list(scope_raw, "allowed_cidrs"),
        allowed_hostnames=_str_list(scope_raw, "allowed_hostnames"),
        allow_public_targets=allow_public,
        max_hosts=_int_in_range(scope_raw, "max_hosts", 256, 1, 65536),
    )

    net_raw = _table(data, "network")
    version_detection = net_raw.get("version_detection", True)
    if not isinstance(version_detection, bool):
        raise ConfigError("version_detection must be true or false")
    network = NetworkSettings(
        top_ports=_int_in_range(net_raw, "top_ports", 100, 1, TOP_PORTS_CEILING),
        max_rate=_int_in_range(net_raw, "max_rate", 20, 1, MAX_RATE_CEILING),
        max_retries=_int_in_range(net_raw, "max_retries", 1, 0, 3),
        host_timeout_seconds=_int_in_range(net_raw, "host_timeout_seconds", 120, 10, 3600),
        scan_timeout_seconds=_int_in_range(net_raw, "scan_timeout_seconds", 1800, 30, 86400),
        timing_template=_int_in_range(net_raw, "timing_template", 2, 0, MAX_TIMING_TEMPLATE),
        version_detection=version_detection,
        version_intensity=_int_in_range(net_raw, "version_intensity", 2, 0, 5),
    )

    adv_raw = _table(data, "advisories")
    advisory_paths = [_resolve(base, p) for p in _str_list(adv_raw, "paths")]

    audit_raw = _table(data, "audit")
    log_path = audit_raw.get("log_path", "secassess-audit.log")
    if not isinstance(log_path, str) or not log_path.strip():
        raise ConfigError("audit.log_path must be a non-empty string")

    return Settings(
        scope=scope,
        network=network,
        advisory_paths=advisory_paths,
        audit_log_path=_resolve(base, log_path),
    )


def load_settings(path: Path) -> Settings:
    """Read and validate a TOML configuration file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read configuration {path}: {exc.strerror}") from exc
    try:
        # utf-8-sig: Windows editors and PowerShell 5.1 often add a BOM, which TOML rejects.
        data = tomllib.loads(raw.decode("utf-8-sig"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    settings = parse_settings(data, base_dir=path.resolve().parent)
    settings.source_path = path.resolve()
    return settings


def _resolve(base: Path, value: str) -> Path:
    p = Path(value).expanduser()
    return p if p.is_absolute() else (base / p)
