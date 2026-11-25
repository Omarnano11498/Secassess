"""Report assembly, JSON serialization and human-readable terminal rendering."""

from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secassess import __version__
from secassess.models import CheckRecord, CheckStatus, Finding, Host
from secassess.redact import redact
from secassess.risk.analyzer import sort_findings

SCHEMA_VERSION = "1.0"


@dataclass(slots=True)
class Report:
    """Everything one run produced. ``hosts`` and ``sections`` are optional per command."""

    command: str
    run_id: str
    mode: str  # "dry-run" | "active" | "local"
    started_at: str
    finished_at: str = ""
    scope: dict[str, Any] = field(default_factory=dict)
    methodology: list[str] = field(default_factory=list)
    tools: dict[str, Any] = field(default_factory=dict)
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    sections: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a redacted JSON-compatible dict."""
        findings = sort_findings(self.findings)
        data = {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": "secassess", "version": __version__},
            "run_id": self.run_id,
            "command": self.command,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "environment": {
                "python": platform.python_version(),
                "platform": platform.system(),
                "platform_release": platform.release(),
            },
            "scope": self.scope,
            "methodology": self.methodology,
            "tool_versions": self.tools,
            "summary": {
                "findings_by_severity": _count(findings, "severity"),
                "findings_by_kind": _count(findings, "kind"),
                "checks_by_status": {
                    s.value: sum(1 for c in self.checks if c.status is s) for s in CheckStatus
                },
                "hosts": len(self.hosts),
            },
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in findings],
            "attack_paths": self.attack_paths,
            "checks": [c.to_dict() for c in self.checks],
            "skipped_or_failed_checks": [
                c.to_dict()
                for c in self.checks
                if c.status in (CheckStatus.SKIPPED, CheckStatus.FAILED)
            ],
            "sections": self.sections,
            "errors": self.errors,
            "limitations": self.limitations,
        }
        result: dict[str, Any] = redact(data)
        return result


def _count(findings: list[Finding], attr: str) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        value = getattr(f, attr)
        key = getattr(value, "label", None) or str(getattr(value, "value", value))
        out[key] = out.get(key, 0) + 1
    return out


def write_json(report: Report, path: Path) -> None:
    """Write the JSON report with owner-only permissions where supported."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=False)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text + "\n")


def render_text(report: Report) -> str:
    """Human-readable plain-text rendering (no colors, safe for logs and pipes)."""
    d = report.to_dict()
    lines: list[str] = []
    bar = "=" * 72
    lines += [
        bar,
        f"secassess {d['tool']['version']}  |  {d['command']}  |  mode: {d['mode']}",
        f"run {d['run_id']}  started {d['started_at']}  finished {d['finished_at']}",
        bar,
    ]
    if d["scope"]:
        lines.append("SCOPE")
        for k, v in d["scope"].items():
            lines.append(f"  {k}: {', '.join(map(str, v)) if isinstance(v, list) else v}")
    if d["methodology"]:
        lines.append("METHODOLOGY")
        lines += [f"  - {m}" for m in d["methodology"]]
    if d["tool_versions"]:
        lines.append("TOOLS")
        for name, info in d["tool_versions"].items():
            state = info.get("version") or info.get("note") or ""
            lines.append(
                f"  {name:<9} {'available' if info.get('available') else 'missing':<10} {state}"
            )
    lines.append("CHECKS")
    for c in d["checks"]:
        flag = " [ACTIVE]" if c["active"] else ""
        lines.append(f"  [{c['status'].upper():<9}] {c['name']}{flag}: {c['detail']}")
        if c["active"] and c["impact"] and c["status"] == "planned":
            lines.append(f"      impact: {c['impact']}")
    if d["hosts"]:
        lines.append("HOSTS")
        for h in d["hosts"]:
            lines.append(f"  {h['address']} ({h['status']})")
            for s in h["services"]:
                desc = " ".join(x for x in (s["name"], s["product"], s["version"]) if x)
                lines.append(f"    {s['port']}/{s['protocol']:<4} {s['state']:<9} {desc}")
            for g in h["os_guesses"][:1]:
                lines.append(f"    OS estimate: {g['name']} ({g['accuracy_percent']}%, estimate)")
    for name, section in d["sections"].items():
        lines.append(name.upper())
        lines += _render_section(section)
    lines.append(f"FINDINGS ({len(d['findings'])})")
    if not d["findings"]:
        lines.append("  none (absence of findings is not proof of security)")
    for f in d["findings"]:
        lines.append(
            f"  [{f['severity'].upper():<8}|conf:{f['confidence']:<6}|{f['kind']}] {f['title']}"
        )
        lines.append(f"      target: {f['target']}")
        for e in f["evidence"]:
            lines.append(f"      evidence: {e}")
        lines.append(f"      why: {f['rationale']}")
        lines.append(f"      fix: {f['remediation']}")
    if d["attack_paths"]:
        lines.append("ATTACK PATHS (explanations only - nothing was attempted)")
        for p in d["attack_paths"]:
            lines.append(f"  {p['target']}: " + " -> ".join(p["steps"]))
    if d["errors"]:
        lines.append("ERRORS")
        lines += [f"  - {e}" for e in d["errors"]]
    if d["limitations"]:
        lines.append("LIMITATIONS")
        lines += [f"  - {x}" for x in d["limitations"]]
    lines.append(bar)
    return "\n".join(lines)


def _render_section(section: Any) -> list[str]:
    if isinstance(section, dict):
        out = []
        for k, v in section.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                out.append(f"  {k}:")
                for item in v[:50]:
                    out.append(
                        "    - "
                        + ", ".join(f"{ik}={iv}" for ik, iv in item.items() if iv not in ("", None))
                    )
                if len(v) > 50:
                    out.append(f"    ... {len(v) - 50} more (see JSON report)")
            elif isinstance(v, list):
                out.append(f"  {k}: {', '.join(map(str, v)) or '-'}")
            elif isinstance(v, dict):
                out.append(f"  {k}: " + ", ".join(f"{a}={b}" for a, b in v.items()))
            else:
                out.append(f"  {k}: {v}")
        return out
    return [f"  {section}"]


def print_text(report: Report) -> None:
    """Print the text rendering, tolerating terminals that cannot encode some characters."""
    text = render_text(report)
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.write(text.encode(encoding, errors="replace").decode(encoding) + "\n")
