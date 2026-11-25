"""Conservative Nmap wrapper: plan building, safety checks, execution and XML parsing.

Design constraints:

* Only TCP connect scans (``-sT``), host discovery (``-sn``), light version detection (``-sV``
  with low intensity) and, if separately opted-in *and* privileged, OS detection (``-O``).
* The Nmap Scripting Engine is never used, and aggressive timing templates are refused.
* Every argv is checked by :func:`assert_safe_argv` immediately before execution.
* If a requested capability is unavailable (e.g. OS detection without privileges) it is skipped
  and reported; a different or more aggressive technique is never substituted.
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from secassess.config import MAX_RATE_CEILING, MAX_TIMING_TEMPLATE, NetworkSettings
from secassess.errors import ToolError
from secassess.models import CheckRecord, CheckStatus, Host, OSGuess, Service
from secassess.runner import CommandRunner, ToolInfo
from secassess.scope import ScopePolicy, address_in_scope

log = logging.getLogger(__name__)

FORBIDDEN_FLAGS = frozenset(
    {
        "--script",
        "-sC",
        "-A",
        "--script-args",
        "--script-updatedb",
        "-T4",
        "-T5",
        "--min-rate",
        "-D",
        "-S",
        "--spoof-mac",
        "-f",
        "--mtu",
        "--data-length",
        "--badsum",
        "--proxies",
        "-sI",
        "-b",
        "--source-port",
        "-g",
        "-iR",
    }
)
_ALLOWED_TARGET = re.compile(r"^[0-9a-fA-F:.]+(/\d{1,3})?$")

DISCOVERY_IMPACT = (
    "Sends host-discovery probes (ICMP echo/timestamp, TCP SYN/ACK to 80/443, or ARP on local "
    "segments; unprivileged runs use TCP connect to 80/443) to every in-scope address. May be "
    "logged by IDS/firewalls. Rate-limited."
)
PORTSCAN_IMPACT = (
    "Opens full TCP connections to the top-N ports on hosts found up. Services will log "
    "connection attempts; fragile embedded devices may react poorly to many connections. "
    "Rate-limited, single retry, per-host timeout."
)
VERSION_IMPACT = (
    "Sends a small number of low-intensity protocol probes to open ports to identify the "
    "service and version. No scripts, no authentication attempts."
)
OS_IMPACT = (
    "Sends a set of unusual TCP/UDP/ICMP probes for OS fingerprinting. Requires raw-socket "
    "privileges. Results are statistical estimates."
)


def has_raw_socket_privileges() -> bool:
    """Best-effort check for privileges Nmap needs for OS detection."""
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    else:
        return os.geteuid() == 0


def assert_safe_argv(argv: list[str], settings: NetworkSettings) -> None:
    """Refuse any argv containing forbidden flags or values beyond conservative ceilings."""
    for arg in argv[1:]:
        flag = arg.split("=", 1)[0]
        if flag in FORBIDDEN_FLAGS or flag.startswith("--script"):
            raise ToolError(f"refusing unsafe nmap option {arg!r}")
    if "--max-rate" not in argv:
        raise ToolError("refusing nmap invocation without --max-rate")
    rate = int(argv[argv.index("--max-rate") + 1])
    if not 1 <= rate <= MAX_RATE_CEILING:
        raise ToolError(f"max-rate {rate} exceeds ceiling {MAX_RATE_CEILING}")
    timing = [a for a in argv if re.fullmatch(r"-T\d", a)]
    if any(int(t[2]) > MAX_TIMING_TEMPLATE for t in timing):
        raise ToolError("refusing aggressive timing template")
    if settings.max_rate != rate:
        raise ToolError("argv rate does not match configured rate")


def _base_args(nmap_path: str, s: NetworkSettings) -> list[str]:
    return [
        nmap_path,
        "-n",  # no reverse DNS: we already resolved and scope-checked addresses
        f"-T{s.timing_template}",
        "--max-rate",
        str(s.max_rate),
        "--max-retries",
        str(s.max_retries),
        "--host-timeout",
        f"{s.host_timeout_seconds}s",
        "-oX",
        "-",
    ]


def _check_targets(targets: list[str]) -> list[str]:
    for t in targets:
        if not _ALLOWED_TARGET.match(t):
            raise ToolError(f"refusing non-IP target in scanner argv: {t!r}")
        ipaddress.ip_network(t, strict=False)
    return targets


def split_families(targets: list[str]) -> list[list[str]]:
    """Group targets by IP version: Nmap needs ``-6`` for IPv6 and cannot mix both in one run."""
    v6 = [t for t in targets if ":" in t]
    v4 = [t for t in targets if ":" not in t]
    return [group for group in (v4, v6) if group]


def _family_args(targets: list[str]) -> list[str]:
    return ["-6"] if targets and all(":" in t for t in targets) else []


def build_discovery_argv(
    nmap_path: str, s: NetworkSettings, targets: list[str], check: bool = True
) -> list[str]:
    """Argv for host discovery only (no port scan). ``check=False`` is for display only."""
    return [
        *_base_args(nmap_path, s),
        *_family_args(targets),
        "-sn",
        *(_check_targets(targets) if check else targets),
    ]


def build_port_argv(
    nmap_path: str, s: NetworkSettings, targets: list[str], os_detect: bool, check: bool = True
) -> list[str]:
    """Argv for a TCP connect scan of top ports, with optional light version/OS detection."""
    argv = [*_base_args(nmap_path, s), *_family_args(targets)]
    argv += ["-Pn", "-sT", "--top-ports", str(s.top_ports)]
    if s.version_detection:
        argv += ["-sV", "--version-intensity", str(s.version_intensity)]
    if os_detect:
        argv += ["-O", "--osscan-limit"]
    return [*argv, *(_check_targets(targets) if check else targets)]


@dataclass(slots=True)
class ScanPlan:
    """Everything a run would do. Built identically for dry-run and active modes."""

    addresses: list[str]
    checks: list[CheckRecord] = field(default_factory=list)
    # One argv per IP family (IPv4 and IPv6 need separate Nmap runs).
    discovery_argvs: list[list[str]] = field(default_factory=list)
    port_argv_templates: list[list[str]] = field(default_factory=list)
    os_detect: bool = False
    resolved: bool = True  # False when targets may still contain unresolved hostnames


def build_plan(
    addresses: list[str],
    settings: NetworkSettings,
    nmap: ToolInfo,
    want_os_detect: bool,
    privileged: bool,
    resolved: bool = True,
) -> ScanPlan:
    """Build the scan plan and record skipped capabilities truthfully.

    With ``resolved=False`` (dry-run/preview) hostnames may appear in the displayed argv; such a
    plan is for display only and :func:`execute_plan` refuses it.
    """
    plan = ScanPlan(addresses=addresses, resolved=resolved)
    if not nmap.available or nmap.path is None:
        plan.checks.append(
            CheckRecord(
                "network.discovery",
                CheckStatus.SKIPPED,
                f"nmap unavailable ({nmap.note}); install Nmap to enable network inventory",
            )
        )
        plan.checks.append(CheckRecord("network.portscan", CheckStatus.SKIPPED, "nmap unavailable"))
        return plan

    os_detect = False
    if want_os_detect and not privileged:
        plan.checks.append(
            CheckRecord(
                "network.os_fingerprint",
                CheckStatus.SKIPPED,
                "OS detection requested but raw-socket privileges are missing; "
                "not substituting another technique",
                active=True,
                impact=OS_IMPACT,
            )
        )
    elif want_os_detect:
        os_detect = True

    plan.os_detect = os_detect
    groups = split_families(addresses)
    plan.discovery_argvs = [
        build_discovery_argv(nmap.path, settings, g, check=resolved) for g in groups
    ]
    # The real port-scan argv is restricted at run time to the subset of hosts found up.
    plan.port_argv_templates = [
        build_port_argv(nmap.path, settings, g, os_detect, check=resolved) for g in groups
    ]
    plan.checks.append(
        CheckRecord(
            "network.discovery",
            CheckStatus.PLANNED,
            " | ".join(" ".join(a[1:]) for a in plan.discovery_argvs),
            active=True,
            impact=DISCOVERY_IMPACT,
        )
    )
    plan.checks.append(
        CheckRecord(
            "network.portscan",
            CheckStatus.PLANNED,
            "applied only to hosts found up: "
            + " | ".join(" ".join(a[1:]) for a in plan.port_argv_templates),
            active=True,
            impact=PORTSCAN_IMPACT,
        )
    )
    if settings.version_detection:
        plan.checks.append(
            CheckRecord(
                "network.version_detection",
                CheckStatus.PLANNED,
                f"-sV --version-intensity {settings.version_intensity}",
                active=True,
                impact=VERSION_IMPACT,
            )
        )
    else:
        plan.checks.append(
            CheckRecord("network.version_detection", CheckStatus.SKIPPED, "disabled in config")
        )
    if os_detect:
        plan.checks.append(
            CheckRecord(
                "network.os_fingerprint",
                CheckStatus.PLANNED,
                "-O --osscan-limit",
                active=True,
                impact=OS_IMPACT,
            )
        )
    elif not want_os_detect:
        plan.checks.append(
            CheckRecord(
                "network.os_fingerprint", CheckStatus.SKIPPED, "not requested (--os-detect)"
            )
        )
    return plan


def parse_nmap_xml(xml_text: str) -> tuple[list[Host], str | None]:
    """Parse Nmap XML output into hosts. Returns (hosts, nmap_version)."""
    if "<!ENTITY" in xml_text:
        raise ToolError("refusing to parse XML containing entity declarations")
    try:
        # Local tool output; entity declarations were rejected above.
        root = ET.fromstring(xml_text)  # noqa: S314  # nosec B314
    except ET.ParseError as exc:
        raise ToolError(f"could not parse nmap XML output: {exc}") from exc
    if root.tag != "nmaprun":
        raise ToolError("unexpected XML root; not nmap output")
    hosts: list[Host] = []
    for h in root.findall("host"):
        addr_el = next(
            (a for a in h.findall("address") if a.get("addrtype") in {"ipv4", "ipv6"}), None
        )
        if addr_el is None or not addr_el.get("addr"):
            continue
        status_el = h.find("status")
        host = Host(
            address=str(addr_el.get("addr")),
            status=status_el.get("state", "unknown") if status_el is not None else "unknown",
            ports_reported=h.find("ports") is not None and h.get("timedout") != "true",
        )
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            svc = p.find("service")
            try:
                port = int(p.get("portid", "0"))
            except ValueError:
                continue
            host.services.append(
                Service(
                    port=port,
                    protocol=p.get("protocol", "tcp"),
                    state=state_el.get("state", "unknown") if state_el is not None else "unknown",
                    name=svc.get("name", "") if svc is not None else "",
                    product=svc.get("product", "") if svc is not None else "",
                    version=svc.get("version", "") if svc is not None else "",
                    extra_info=svc.get("extrainfo", "") if svc is not None else "",
                    tunnel=svc.get("tunnel", "") if svc is not None else "",
                )
            )
        for m in h.findall("os/osmatch"):
            try:
                accuracy = int(m.get("accuracy", "0"))
            except ValueError:
                accuracy = 0
            host.os_guesses.append(OSGuess(m.get("name", "unknown"), accuracy))
        hosts.append(host)
    return hosts, root.get("version")


@dataclass(slots=True)
class NetworkResult:
    """Outcome of network checks."""

    hosts: list[Host] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)
    dropped_out_of_scope: list[str] = field(default_factory=list)
    nmap_version: str | None = None


def execute_plan(
    plan: ScanPlan,
    settings: NetworkSettings,
    policy: ScopePolicy,
    runner: CommandRunner,
    nmap_path: str,
) -> NetworkResult:
    """Run an already-confirmed plan. Callers must have enforced confirmation beforehand."""
    if not plan.resolved:
        raise ToolError("internal error: refusing to execute a display-only (unresolved) plan")
    result = NetworkResult()
    result.checks = [c for c in plan.checks if c.status is CheckStatus.SKIPPED]
    if not plan.discovery_argvs:
        return result

    # Phase 1: discovery
    discovered: list[Host] = []
    errors: list[str] = []
    for argv in plan.discovery_argvs:
        assert_safe_argv(argv, settings)
        try:
            hosts, version = _run_nmap(argv, settings, runner, "discovery")
        except ToolError as exc:
            errors.append(str(exc))
            continue
        discovered += hosts
        result.nmap_version = version or result.nmap_version
    if errors:
        result.checks.append(
            CheckRecord(
                "network.discovery", CheckStatus.FAILED, "; ".join(errors), True, DISCOVERY_IMPACT
            )
        )
    if len(errors) == len(plan.discovery_argvs):
        result.checks.append(
            CheckRecord("network.portscan", CheckStatus.SKIPPED, "discovery failed")
        )
        return result
    up = [h.address for h in discovered if h.status == "up"]
    up = _filter_scope(up, policy, result)
    result.checks.append(
        CheckRecord(
            "network.discovery",
            CheckStatus.COMPLETED,
            f"{len(up)} in-scope host(s) up of {len(plan.addresses)} target entries",
            True,
            DISCOVERY_IMPACT,
        )
    )
    if not up:
        result.checks.append(
            CheckRecord("network.portscan", CheckStatus.SKIPPED, "no hosts found up")
        )
        return result

    # Phase 2: port/service scan on hosts found up only
    groups = split_families(up)
    errors = []
    scanned_count = 0
    for group in groups:
        argv = build_port_argv(nmap_path, settings, group, plan.os_detect)
        assert_safe_argv(argv, settings)
        try:
            scanned, _ = _run_nmap(argv, settings, runner, "port scan")
        except ToolError as exc:
            errors.append(str(exc))
            result.hosts += [h for h in discovered if h.address in group]
            continue
        allowed = set(_filter_scope([h.address for h in scanned], policy, result))
        kept = [h for h in scanned if h.address in allowed]
        result.hosts += kept
        # Nmap omits the port table of a host that hit --host-timeout. Without this check such a
        # host would look like one with no open ports.
        done = {h.address for h in kept if h.ports_reported}
        scanned_count += len(done)
        missing = [a for a in group if a not in done]
        if missing:
            errors.append(
                f"no port results for {len(missing)} host(s), probably host_timeout_seconds="
                f"{settings.host_timeout_seconds} was reached (raise it, or raise timing_template/"
                f"max_rate): {', '.join(missing)}"
            )
        reported = {h.address for h in kept}
        result.hosts += [h for h in discovered if h.address in group and h.address not in reported]
    if errors:
        result.checks.append(
            CheckRecord(
                "network.portscan", CheckStatus.FAILED, "; ".join(errors), True, PORTSCAN_IMPACT
            )
        )
    if not scanned_count:
        return result
    result.checks.append(
        CheckRecord(
            "network.portscan",
            CheckStatus.COMPLETED,
            f"{scanned_count} host(s) scanned",
            True,
            PORTSCAN_IMPACT,
        )
    )
    for name in ("network.version_detection", "network.os_fingerprint"):
        planned = next(
            (c for c in plan.checks if c.name == name and c.status is CheckStatus.PLANNED), None
        )
        if planned:
            result.checks.append(
                CheckRecord(name, CheckStatus.COMPLETED, planned.detail, True, planned.impact)
            )
    return result


def _run_nmap(
    argv: list[str], settings: NetworkSettings, runner: CommandRunner, label: str
) -> tuple[list[Host], str | None]:
    """Execute one already-guarded argv and parse its XML."""
    out = runner.run(argv, timeout=settings.scan_timeout_seconds)
    if out.returncode != 0:
        raise ToolError(f"nmap {label} exited {out.returncode}: {out.stderr.strip()[:300]}")
    return parse_nmap_xml(out.stdout)


def _filter_scope(addresses: list[str], policy: ScopePolicy, result: NetworkResult) -> list[str]:
    kept: list[str] = []
    for a in addresses:
        if address_in_scope(policy, a):
            kept.append(a)
        else:
            log.warning("dropping out-of-scope address reported by scanner: %s", a)
            result.dropped_out_of_scope.append(a)
    return kept
