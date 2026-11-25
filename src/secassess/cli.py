"""Command-line interface.

Exit codes: 0 success, 1 findings at/above --fail-on, 2 configuration/scope/usage error,
3 active run not confirmed, 4 external-tool error, 130 interrupted.
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from secassess import __version__
from secassess.audit import AuditLog
from secassess.config import Settings, load_settings
from secassess.errors import ConfigError, ConfirmationError, ScopeError, SecAssessError, ToolError
from secassess.hardware.health import collect_local, summarize
from secassess.logging_setup import configure_logging
from secassess.models import CheckRecord, CheckStatus, Severity, utc_now_iso
from secassess.network.nmap_scanner import build_plan, execute_plan, has_raw_socket_privileges
from secassess.project_review.reviewer import review_project
from secassess.reporting.docx import write_docx
from secassess.reporting.report import Report, print_text, write_json
from secassess.risk.advisories import load_advisories
from secassess.risk.analyzer import analyze_hosts, exceeds_threshold, explain_attack_paths
from secassess.risk.nvd import PRODUCT_CPES, HttpGet, build_advisory_file, urllib_get
from secassess.runner import CommandRunner, SubprocessRunner, detect_all, detect_tool
from secassess.scope import (
    Resolver,
    ScopePolicy,
    Target,
    is_documentation,
    is_public,
    resolve_to_addresses,
    system_resolver,
)

log = logging.getLogger("secassess")
DEFAULT_AUDIT = Path.home() / ".secassess" / "audit.log"
DEFAULT_SEMGREP_RULES = Path(__file__).resolve().parent / "rules" / "semgrep-local.yml"


@dataclass(slots=True)
class Deps:
    """Injectable side-effecting dependencies (replaced by fakes in tests)."""

    runner: CommandRunner = field(default_factory=SubprocessRunner)
    resolver: Resolver = system_resolver
    prompt: Callable[[str], str] = input
    stdin_is_tty: Callable[[], bool] = lambda: sys.stdin.isatty()
    privileged: Callable[[], bool] = has_raw_socket_privileges
    out: TextIO | None = None
    http_get: HttpGet = urllib_get


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    p = argparse.ArgumentParser(
        prog="secassess",
        description="Defensive, scope-enforced security assessment for systems you are "
        "authorized to assess. Network checks default to dry-run.",
    )
    p.add_argument("--version", action="version", version=f"secassess {__version__}")
    p.add_argument("--log-level", default="WARNING", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    p.add_argument("--log-format", default="text", choices=["text", "json"])
    p.add_argument("--audit-log", type=Path, help="audit log path (overrides config)")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("check-tools", help="show optional external tools and their versions")

    sp = sub.add_parser("scope-preview", help="validate targets against scope; sends no traffic")
    sp.add_argument("-c", "--config", type=Path, required=True)
    sp.add_argument("-t", "--target", action="append", required=True, dest="targets")

    n = sub.add_parser("network", help="network inventory and risk assessment (dry-run default)")
    n.add_argument("-c", "--config", type=Path, required=True)
    n.add_argument(
        "-t",
        "--target",
        action="append",
        required=True,
        dest="targets",
        help="IP, CIDR or allow-listed hostname; repeatable",
    )
    mode = n.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="show what would be checked without sending traffic (default)",
    )
    mode.add_argument(
        "--active", action="store_true", help="send scan traffic after explicit confirmation"
    )
    n.add_argument(
        "--confirm-scope",
        metavar="SCOPE_ID",
        help="non-interactive confirmation; must equal the scope ID from the preview",
    )
    n.add_argument(
        "--os-detect",
        action="store_true",
        help="opt-in OS fingerprinting (needs admin/root; estimates only)",
    )
    _common_output(n)

    pr = sub.add_parser("project", help="static, read-only review of a local source tree")
    pr.add_argument("path", type=Path)
    pr.add_argument("--bandit", action="store_true", help="run Bandit if installed")
    pr.add_argument(
        "--semgrep-config",
        type=Path,
        default=DEFAULT_SEMGREP_RULES,
        help="local Semgrep rules file (default: bundled rules; runs when semgrep is installed)",
    )
    pr.add_argument("--no-semgrep", action="store_true", help="do not run Semgrep")
    pr.add_argument("--dry-run", action="store_true", help="list checks without running them")
    _common_output(pr)

    hw = sub.add_parser("hardware", help="read-only local hardware-health indicators")
    hw.add_argument("--smart", action="store_true", help="query SMART via smartctl (read-only)")
    hw.add_argument("--dry-run", action="store_true", help="list checks without running them")
    _common_output(hw)

    rp = sub.add_parser(
        "report", help="merge JSON reports (network/project/hardware) into one Word document"
    )
    rp.add_argument("inputs", type=Path, nargs="+", help="JSON reports written with --json")
    rp.add_argument("--docx", type=Path, dest="docx_path", required=True, help="output .docx")

    ad = sub.add_parser("advisories", help="build or inspect local advisory (CVE) files")
    adsub = ad.add_subparsers(dest="advisories_command", required=True)
    af = adsub.add_parser(
        "fetch",
        help="download CVEs from NIST NVD into a local advisory file (contacts NVD only)",
        description="Queries services.nvd.nist.gov for the CPEs of common network services and "
        "writes a local advisory file. Only public product identifiers are sent. Set the "
        "NVD_API_KEY environment variable for faster downloads.",
    )
    af.add_argument(
        "--out",
        type=Path,
        default=Path("advisories") / "nvd.json",
        help="output file (default: advisories/nvd.json)",
    )
    af.add_argument(
        "--product",
        action="append",
        dest="products",
        choices=sorted(PRODUCT_CPES),
        metavar="NAME",
        help="Nmap product name to fetch; repeatable (default: all known products)",
    )
    af.add_argument(
        "--min-severity",
        default="medium",
        choices=[s.label for s in Severity],
        help="drop advisories below this severity (default: medium)",
    )
    af.add_argument("--list-products", action="store_true", help="list known products and exit")
    ash = adsub.add_parser("show", help="validate advisory files and summarize them")
    ash.add_argument("files", type=Path, nargs="+")

    f = sub.add_parser(
        "full",
        help="run every assessment with all available tools; write JSON + one Word report",
        description="Runs project review (inventory, secrets, Bandit, Semgrep with bundled local "
        "rules), hardware indicators (with SMART) and, when -c and -t are given, network checks "
        "(dry-run unless --active). Missing tools are skipped and reported, never fatal.",
    )
    f.add_argument(
        "--project", type=Path, default=Path("."), help="source tree to review (default: .)"
    )
    f.add_argument("--no-project", action="store_true", help="skip the project review")
    f.add_argument("--no-hardware", action="store_true", help="skip hardware indicators")
    f.add_argument("-c", "--config", type=Path, help="scope config (network runs only with -c/-t)")
    f.add_argument(
        "-t", "--target", action="append", default=[], dest="targets", help="network target"
    )
    f.add_argument("--active", action="store_true", help="send network traffic after confirmation")
    f.add_argument("--confirm-scope", metavar="SCOPE_ID", help="non-interactive confirmation")
    f.add_argument("--os-detect", action="store_true", help="opt-in OS fingerprinting (admin)")
    f.add_argument("--no-bandit", action="store_true", help="do not run Bandit")
    f.add_argument("--no-semgrep", action="store_true", help="do not run Semgrep")
    f.add_argument(
        "--semgrep-config",
        type=Path,
        default=DEFAULT_SEMGREP_RULES,
        help="local Semgrep rules file (default: bundled rules)",
    )
    f.add_argument("--no-smart", action="store_true", help="do not query SMART")
    f.add_argument(
        "--out-dir", type=Path, default=Path("reports"), help="output directory (default: reports)"
    )
    f.add_argument(
        "--docx", type=Path, dest="docx_path", help="Word report path (default: in --out-dir)"
    )
    f.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        help="exit 1 if any finding is at or above this severity",
    )
    return p


def _common_output(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", type=Path, dest="json_path", help="write JSON report to this path")
    p.add_argument(
        "--docx", type=Path, dest="docx_path", help="write a Word (.docx) report to this path"
    )
    p.add_argument("--quiet", action="store_true", help="suppress terminal report")
    p.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        help="exit 1 if any finding is at or above this severity",
    )


def _emit(report: Report, args: argparse.Namespace, deps: Deps) -> None:
    report.finished_at = utc_now_iso()
    if getattr(args, "json_path", None):
        write_json(report, args.json_path)
    if getattr(args, "docx_path", None):
        write_docx([report.to_dict()], args.docx_path)
    if not getattr(args, "quiet", False):
        if deps.out is not None:
            from secassess.reporting.report import render_text

            deps.out.write(render_text(report) + "\n")
        else:
            print_text(report)


def _say(deps: Deps, text: str) -> None:
    stream = deps.out if deps.out is not None else sys.stdout
    stream.write(text + "\n")


def _scope_summary(policy: ScopePolicy, targets: list[Target]) -> dict[str, object]:
    notes: list[str] = []
    for t in targets:
        if t.network is not None and is_documentation(t.network):
            notes.append(f"{t.display}: documentation-only range (dry-run examples only)")
        elif t.network is not None and is_public(t.network):
            notes.append(f"{t.display}: PUBLIC address space (explicitly allowed by config)")
        elif t.hostname:
            notes.append(f"{t.hostname}: resolved at run time; every address re-checked")
    return {
        "allowed_cidrs": [str(n) for n in policy.allowed_networks],
        "allowed_hostnames": sorted(policy.allowed_hostnames),
        "allow_public_targets": policy.allow_public_targets,
        "max_hosts": policy.max_hosts,
        "targets": [t.display for t in targets],
        "scope_id": policy.fingerprint(targets),
        "notes": notes,
    }


def _audit_path(args: argparse.Namespace, settings: Settings | None) -> Path:
    if args.audit_log:
        return Path(args.audit_log)
    return settings.audit_log_path if settings else DEFAULT_AUDIT


def cmd_check_tools(args: argparse.Namespace, deps: Deps) -> int:
    """Print optional-tool availability."""
    for name, info in detect_all(deps.runner).items():
        state = f"{info.version or '?'} at {info.path}" if info.available else info.note
        _say(
            deps,
            f"{name:<9} {'available' if info.available else 'missing':<10} "
            f"{state}  ({info.purpose})",
        )
    _say(
        deps,
        f"psutil    {'available' if _has_psutil() else 'missing':<10} "
        "(optional, battery/temperature indicators)",
    )
    return 0


def _has_psutil() -> bool:
    import importlib.util

    return importlib.util.find_spec("psutil") is not None


def cmd_scope_preview(args: argparse.Namespace, deps: Deps) -> int:
    """Validate targets and show the scope ID without sending any traffic."""
    settings = load_settings(args.config)
    targets = settings.scope.validate(args.targets)
    summary = _scope_summary(settings.scope, targets)
    _say(deps, "Scope preview (no network traffic sent, no DNS lookups performed)")
    for k, v in summary.items():
        _say(deps, f"  {k}: {', '.join(map(str, v)) if isinstance(v, list) else v}")
    return 0


def cmd_network(args: argparse.Namespace, deps: Deps) -> int:
    """Network inventory: dry-run by default, active only after confirmation."""
    settings = load_settings(args.config)
    audit = AuditLog(_audit_path(args, settings))
    active = bool(args.active)
    report = Report(
        command="network",
        run_id=audit.run_id,
        mode="active" if active else "dry-run",
        started_at=utc_now_iso(),
    )
    try:
        targets = settings.scope.validate(args.targets)
    except ScopeError as exc:
        audit.record("scope_rejected", targets=args.targets, reason=str(exc))
        raise
    report.scope = _scope_summary(settings.scope, targets)
    scope_id = str(report.scope["scope_id"])
    nmap = detect_tool(deps.runner, "nmap")
    report.tools = {"nmap": nmap.to_dict()}
    advisories = load_advisories(settings.advisory_paths)
    report.tools["advisory_sources"] = {
        "available": bool(advisories.sources),
        "version": "; ".join(advisories.sources) or None,
        "note": "" if advisories.sources else "no local advisory files configured",
    }
    report.methodology = [
        "Targets validated against approved CIDRs/hostnames before any traffic.",
        "Hostnames resolved once; resolved IPs re-checked against scope; scanner gets IPs only.",
        f"Nmap host discovery (-sn), then TCP connect scan of top {settings.network.top_ports} "
        f"ports on hosts found up; T{settings.network.timing_template}, max "
        f"{settings.network.max_rate} pkt/s, {settings.network.max_retries} retry, "
        f"{settings.network.host_timeout_seconds}s per-host timeout.",
        "No NSE scripts, no exploitation, no brute force, no DoS, no evasion.",
        "Findings from service-exposure rules and local advisory version correlation; "
        "version matches are never treated as confirmed vulnerabilities.",
    ]
    audit.record(
        "run_start",
        command="network",
        mode=report.mode,
        scope=report.scope,
        os_detect=args.os_detect,
        settings_file=str(settings.source_path),
    )

    if not active:
        plan = build_plan(
            [t.display for t in targets],
            settings.network,
            nmap,
            args.os_detect,
            deps.privileged(),
            resolved=False,
        )
        report.checks = plan.checks
        report.limitations.append("Dry-run: no packets were sent and no DNS lookups were made.")
        if any(t.hostname for t in targets):
            report.limitations.append(
                "Hostname targets are shown unresolved; in active mode they are resolved and "
                "each address must be inside allowed_cidrs."
            )
        doc_targets = [
            t.display for t in targets if t.network is not None and is_documentation(t.network)
        ]
        if doc_targets:
            report.sections["next_step"] = {
                "to_run_actively": "replace documentation-only ranges "
                f"({', '.join(doc_targets)}) with ranges you are authorized to assess; "
                "active mode refuses documentation ranges"
            }
        else:
            report.sections["next_step"] = {
                "to_run_actively": f"secassess network -c {args.config} "
                + " ".join(f"-t {t}" for t in args.targets)
                + f" --active --confirm-scope {scope_id}"
            }
        audit.record("run_end", outcome="dry_run_completed")
        _emit(report, args, deps)
        return 0

    doc = [t.display for t in targets if t.network is not None and is_documentation(t.network)]
    if doc:
        audit.record("run_end", outcome="refused_documentation_range", targets=doc)
        raise ScopeError(f"documentation-only ranges cannot be scanned actively: {', '.join(doc)}")
    if not nmap.available or nmap.path is None:
        audit.record("run_end", outcome="nmap_unavailable")
        raise ToolError(f"nmap is required for active network checks ({nmap.note})")

    preview = build_plan(
        [t.display for t in targets],
        settings.network,
        nmap,
        args.os_detect,
        deps.privileged(),
        resolved=False,
    )
    _confirm(args, deps, scope_id, preview.checks, report.scope)
    audit.record(
        "confirmed", scope_id=scope_id, method="flag" if args.confirm_scope else "interactive"
    )

    addresses = resolve_to_addresses(settings.scope, targets, deps.resolver)
    plan = build_plan(addresses, settings.network, nmap, args.os_detect, deps.privileged())
    try:
        result = execute_plan(plan, settings.network, settings.scope, deps.runner, nmap.path)
    except KeyboardInterrupt:
        audit.record("run_end", outcome="interrupted")
        raise
    except ToolError as exc:
        audit.record("run_end", outcome="tool_error", reason=str(exc))
        raise
    report.hosts = result.hosts
    report.checks = result.checks
    if result.dropped_out_of_scope:
        report.errors.append(
            f"scanner reported {len(result.dropped_out_of_scope)} out-of-scope "
            "address(es); they were discarded"
        )
    report.findings = analyze_hosts(result.hosts, advisories)
    report.attack_paths = explain_attack_paths(report.findings)
    report.checks.append(
        CheckRecord("risk.analysis", CheckStatus.COMPLETED, f"{len(report.findings)} finding(s)")
    )
    report.limitations += [
        "Only TCP was scanned; UDP services (e.g. SNMP, DNS) are not inventoried in this MVP.",
        "Authentication, configuration files and patch levels were not inspected on hosts.",
        "Firewalls/IDS may hide services or alter fingerprints.",
    ]
    failed = [c.name for c in report.checks if c.status is CheckStatus.FAILED]
    audit.record(
        "run_end",
        outcome="failed_checks" if failed else "completed",
        hosts=len(report.hosts),
        findings=len(report.findings),
        failed=failed,
    )
    _emit(report, args, deps)
    # A failed scan must never look like a clean result to automation.
    return _exit_for(report, args) or (4 if failed else 0)


def _confirm(
    args: argparse.Namespace,
    deps: Deps,
    scope_id: str,
    checks: list[CheckRecord],
    scope: dict[str, object],
) -> None:
    _say(deps, "ACTIVE CHECKS REQUESTED. The following will send traffic:")
    for c in checks:
        if c.active and c.status is CheckStatus.PLANNED:
            _say(deps, f"  - {c.name}: {c.impact}")
    raw_targets = scope.get("targets")
    shown = ", ".join(str(t) for t in raw_targets) if isinstance(raw_targets, list) else ""
    _say(deps, f"Targets: {shown}   scope ID: {scope_id}")
    if args.confirm_scope is not None:
        if args.confirm_scope != scope_id:
            raise ConfirmationError(
                "--confirm-scope does not match this scope; run "
                "'secassess scope-preview' (or a dry run) to get the ID"
            )
        return
    if not deps.stdin_is_tty():
        raise ConfirmationError("active mode needs interactive confirmation or --confirm-scope")
    try:
        answer = deps.prompt(f"Type the scope ID ({scope_id}) to confirm you are authorized: ")
    except EOFError as exc:
        raise ConfirmationError("no confirmation was entered; nothing was scanned") from exc
    if answer.strip() != scope_id:
        raise ConfirmationError("confirmation did not match; nothing was scanned")


def cmd_project(args: argparse.Namespace, deps: Deps) -> int:
    """Static review of a local project."""
    audit = AuditLog(_audit_path(args, None))
    report = Report(
        command="project",
        run_id=audit.run_id,
        mode="dry-run" if args.dry_run else "local",
        started_at=utc_now_iso(),
    )
    semgrep_config: Path | None = (
        None if getattr(args, "no_semgrep", False) else args.semgrep_config
    )
    report.scope = {"project_path": str(Path(args.path).expanduser().resolve())}
    report.methodology = [
        "Read-only file walk (symlinks not followed; VCS/dependency/build dirs skipped).",
        "Manifest and lockfile parsing; architecture inferred heuristically with confidence.",
        "Regex secret-pattern scan; matched values are never written to reports.",
        "Semgrep with local rules (bundled by default, metrics off) when installed; "
        "Bandit when requested.",
        "The target project is never executed, imported, built or tested.",
    ]
    audit.record(
        "run_start",
        command="project",
        path=report.scope["project_path"],
        bandit=args.bandit,
        semgrep=bool(semgrep_config),
        dry_run=args.dry_run,
    )
    if args.dry_run:
        report.checks = [
            CheckRecord("project.inventory", CheckStatus.PLANNED, "file/language inventory"),
            CheckRecord("project.manifests", CheckStatus.PLANNED, "dependency manifests"),
            CheckRecord("project.secret_patterns", CheckStatus.PLANNED, "secret patterns"),
            CheckRecord(
                "project.bandit",
                CheckStatus.PLANNED if args.bandit else CheckStatus.SKIPPED,
                "bandit -r <path> -f json" if args.bandit else "not requested",
            ),
            CheckRecord(
                "project.semgrep",
                CheckStatus.PLANNED if semgrep_config else CheckStatus.SKIPPED,
                f"semgrep scan --config {semgrep_config} --metrics=off"
                if semgrep_config
                else "disabled (--no-semgrep)",
            ),
        ]
        audit.record("run_end", outcome="dry_run_completed")
        _emit(report, args, deps)
        return 0
    pr = review_project(args.path, deps.runner, args.bandit, semgrep_config)
    report.findings = pr.findings
    report.checks = pr.checks
    report.limitations = pr.limitations
    report.sections["project"] = pr.to_dict()
    report.tools = {
        k: v.to_dict() for k, v in detect_all(deps.runner).items() if k in ("bandit", "semgrep")
    }
    audit.record("run_end", outcome="completed", findings=len(pr.findings))
    _emit(report, args, deps)
    return _exit_for(report, args)


def cmd_hardware(args: argparse.Namespace, deps: Deps) -> int:
    """Local hardware-health indicators."""
    audit = AuditLog(_audit_path(args, None))
    report = Report(
        command="hardware",
        run_id=audit.run_id,
        mode="dry-run" if args.dry_run else "local",
        started_at=utc_now_iso(),
    )
    report.methodology = [
        "Read-only OS/firmware indicators: filesystem capacity, battery, temperatures.",
        "SMART via 'smartctl -H -A -i -j' only with --smart (read-only; no self-tests).",
        "No stress, benchmark or write tests. Missing data is reported as unavailable.",
    ]
    report.limitations = [
        "Indicators cannot predict remaining lifespan; 'ok' means 'no issue reported'.",
        "VMs and containers usually expose no real hardware sensors.",
        "Remote hardware inspection (e.g. SNMP) is an interface only in this MVP.",
    ]
    audit.record("run_start", command="hardware", smart=args.smart, dry_run=args.dry_run)
    if args.dry_run:
        report.checks = [
            CheckRecord("hardware.disk_usage", CheckStatus.PLANNED, "shutil.disk_usage"),
            CheckRecord("hardware.battery", CheckStatus.PLANNED, "sysfs / psutil"),
            CheckRecord("hardware.temperatures", CheckStatus.PLANNED, "psutil / sysfs"),
            CheckRecord(
                "hardware.smart",
                CheckStatus.PLANNED if args.smart else CheckStatus.SKIPPED,
                "smartctl --scan -j; smartctl -H -A -i -j <dev>"
                if args.smart
                else "not requested (--smart)",
                active=args.smart,
                impact="read-only SMART queries" if args.smart else "",
            ),
        ]
        audit.record("run_end", outcome="dry_run_completed")
        _emit(report, args, deps)
        return 0
    measurements = collect_local(deps.runner, args.smart)
    report.sections["hardware"] = {
        "summary": summarize(measurements),
        "measurements": [m.to_dict() for m in measurements],
    }
    report.checks = [
        CheckRecord("hardware.collect", CheckStatus.COMPLETED, f"{len(measurements)} indicator(s)")
    ]
    if args.smart:
        report.tools = {"smartctl": detect_tool(deps.runner, "smartctl").to_dict()}
    audit.record(
        "run_end", outcome="completed", overall=report.sections["hardware"]["summary"]["overall"]
    )
    _emit(report, args, deps)
    return 0


def cmd_report(args: argparse.Namespace, deps: Deps) -> int:
    """Merge existing JSON reports into a single Word document. Runs no checks."""
    reports: list[dict[str, Any]] = []
    for path in args.inputs:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        except OSError as exc:
            raise ConfigError(f"cannot read report {path}: {exc}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
        if not isinstance(data, dict) or "command" not in data or "schema_version" not in data:
            raise ConfigError(f"{path} is not a secassess JSON report")
        reports.append(data)
    write_docx(reports, args.docx_path)
    _say(deps, f"wrote {args.docx_path} ({len(reports)} report(s))")
    return 0


def cmd_advisories(args: argparse.Namespace, deps: Deps) -> int:
    """Build (fetch) or inspect (show) local advisory files."""
    if args.advisories_command == "show":
        db = load_advisories(list(args.files))
        for src in db.sources:
            _say(deps, f"source: {src}")
        per_product: dict[str, dict[str, int]] = {}
        for a in db.advisories:
            counts = per_product.setdefault(a.product, {})
            counts[a.severity.label] = counts.get(a.severity.label, 0) + 1
        for product, counts in sorted(per_product.items()):
            detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            _say(deps, f"  {product:<24} {sum(counts.values()):>5}  ({detail})")
        _say(deps, f"total: {len(db.advisories)} advisories (valid)")
        return 0
    if args.list_products:
        for name, cpes in PRODUCT_CPES.items():
            _say(deps, f"{name:<24} {', '.join(cpes)}")
        return 0
    products = args.products or list(PRODUCT_CPES)
    api_key = os.environ.get("NVD_API_KEY") or None
    _say(
        deps,
        f"Fetching {len(products)} product(s) from NVD "
        f"({'with' if api_key else 'without'} API key; public rate limit applies)",
    )
    doc = build_advisory_file(
        products,
        deps.http_get,
        Severity.parse(args.min_severity),
        api_key=api_key,
        progress=lambda m: _say(deps, m),
    )
    out: Path = args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    load_advisories([tmp])  # validate before replacing the previous file
    os.replace(tmp, out)
    _say(deps, f"wrote {out}: {len(doc['advisories'])} advisories")
    _say(deps, f'use it: add  paths = ["{out.resolve().as_posix()}"]  under [advisories]')
    return 0


@dataclass(slots=True)
class _PartResult:
    name: str
    rc: int
    json_path: Path | None
    note: str = ""


def cmd_full(args: argparse.Namespace, deps: Deps) -> int:
    """Run every assessment with every available tool and write JSON + one Word report."""
    stamp = utc_now_iso()[:19].replace("-", "").replace(":", "")
    out_dir: Path = args.out_dir
    _say(deps, f"secassess full scan  ({stamp})")
    _say(deps, "TOOLS")
    cmd_check_tools(args, deps)

    common = {"audit_log": args.audit_log, "quiet": True, "docx_path": None}
    plan: list[tuple[str, Callable[[argparse.Namespace, Deps], int], argparse.Namespace]] = []
    results: list[_PartResult] = []

    if args.config and args.targets:
        plan.append(
            (
                "network",
                cmd_network,
                argparse.Namespace(
                    **common,
                    config=args.config,
                    targets=args.targets,
                    active=args.active,
                    dry_run=not args.active,
                    confirm_scope=args.confirm_scope,
                    os_detect=args.os_detect,
                    fail_on=args.fail_on,
                    json_path=out_dir / f"network-{stamp}.json",
                ),
            )
        )
    else:
        results.append(
            _PartResult("network", 0, None, "skipped: pass -c CONFIG and -t TARGET to include it")
        )
    if not args.no_project:
        plan.append(
            (
                "project",
                cmd_project,
                argparse.Namespace(
                    **common,
                    path=args.project,
                    bandit=not args.no_bandit,
                    semgrep_config=None if args.no_semgrep else args.semgrep_config,
                    dry_run=False,
                    fail_on=args.fail_on,
                    json_path=out_dir / f"project-{stamp}.json",
                ),
            )
        )
    if not args.no_hardware:
        if not args.no_smart and not deps.privileged():
            _say(deps, "note: SMART usually needs Administrator/root; readings may be unavailable")
        plan.append(
            (
                "hardware",
                cmd_hardware,
                argparse.Namespace(
                    **common,
                    smart=not args.no_smart,
                    dry_run=False,
                    fail_on=args.fail_on,
                    json_path=out_dir / f"hardware-{stamp}.json",
                ),
            )
        )

    for name, func, ns in plan:
        _say(deps, f"running {name} ...")
        try:
            rc = func(ns, deps)
            results.append(_PartResult(name, rc, ns.json_path))
        except SecAssessError as exc:
            results.append(_PartResult(name, _error_code(exc), None, f"error: {exc}"))
        except OSError as exc:
            results.append(_PartResult(name, 2, None, f"error: {_os_error(exc)}"))

    reports: list[dict[str, Any]] = []
    for r in results:
        if r.json_path is not None and r.json_path.exists():
            reports.append(json.loads(r.json_path.read_text(encoding="utf-8")))

    _say(deps, "SUMMARY")
    by_name = {str(d.get("command")): d for d in reports}
    for r in sorted(results, key=lambda x: ["network", "project", "hardware"].index(x.name)):
        d = by_name.get(r.name)
        if d is None:
            _say(deps, f"  {r.name:<9} {r.note}")
            continue
        sev = d["summary"]["findings_by_severity"]
        checks = d["summary"]["checks_by_status"]
        sev_text = ", ".join(f"{k}={v}" for k, v in sev.items()) or "none"
        _say(
            deps,
            f"  {r.name:<9} mode={d['mode']}  checks: completed={checks.get('completed', 0)} "
            f"skipped={checks.get('skipped', 0)} failed={checks.get('failed', 0)}  "
            f"findings: {sev_text}",
        )
        hw = (d.get("sections") or {}).get("hardware")
        if hw:
            _say(deps, f"            hardware overall: {hw['summary']['overall']}")
        _say(deps, f"            json: {r.json_path}")
    if reports:
        docx_path = args.docx_path or out_dir / f"secassess-full-{stamp}.docx"
        write_docx(reports, docx_path)
        _say(deps, f"WORD REPORT: {docx_path}")
    else:
        _say(deps, "no report produced (every part was skipped or failed)")
    return max((r.rc for r in results), default=0)


def _os_error(exc: OSError) -> str:
    hint = " (is the file open in another program?)" if isinstance(exc, PermissionError) else ""
    return f"{exc}{hint}"


def _error_code(exc: SecAssessError) -> int:
    if isinstance(exc, ConfirmationError):
        return 3
    if isinstance(exc, ToolError):
        return 4
    return 2


def _exit_for(report: Report, args: argparse.Namespace) -> int:
    threshold = Severity.parse(args.fail_on) if getattr(args, "fail_on", None) else None
    return 1 if exceeds_threshold(report.findings, threshold) else 0


COMMANDS: dict[str, Callable[[argparse.Namespace, Deps], int]] = {
    "check-tools": cmd_check_tools,
    "scope-preview": cmd_scope_preview,
    "network": cmd_network,
    "project": cmd_project,
    "hardware": cmd_hardware,
    "report": cmd_report,
    "full": cmd_full,
    "advisories": cmd_advisories,
}


def main(argv: Sequence[str] | None = None, deps: Deps | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = build_parser().parse_args(argv)
    configure_logging(args.log_level, args.log_format)
    if deps is None:
        deps = Deps()
        # Legacy Windows code pages cannot encode every path or banner; never crash on output.
        for stream in (sys.stdout, sys.stderr):
            if isinstance(stream, io.TextIOWrapper):
                stream.reconfigure(errors="replace")
    try:
        return COMMANDS[args.command](args, deps)
    except (ConfigError, ScopeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ConfirmationError as exc:
        print(f"not confirmed: {exc}", file=sys.stderr)
        return 3
    except ToolError as exc:
        print(f"tool error: {exc}", file=sys.stderr)
        return 4
    except SecAssessError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {_os_error(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
