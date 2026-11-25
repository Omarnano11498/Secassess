"""Turn observed hosts/services into findings, and explain (never execute) attack paths."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from secassess.models import Confidence, Finding, FindingKind, Host, Service, Severity
from secassess.risk.advisories import AdvisoryDB


@dataclass(frozen=True, slots=True)
class ExposureRule:
    """A service-exposure rule keyed by service names and/or ports."""

    rule_id: str
    names: frozenset[str]
    ports: frozenset[int]
    title: str
    severity: Severity
    rationale: str
    remediation: str
    skip_if_tls: bool = False


EXPOSURE_RULES: tuple[ExposureRule, ...] = (
    ExposureRule(
        "EXP-TELNET",
        frozenset({"telnet"}),
        frozenset({23}),
        "Telnet remote login service exposed",
        Severity.HIGH,
        "Telnet transmits credentials and session data unencrypted; anyone on the network path "
        "can capture them.",
        "Disable Telnet and use SSH; if it cannot be removed, restrict it to a management VLAN.",
    ),
    ExposureRule(
        "EXP-RSERVICES",
        frozenset({"login", "shell", "exec", "rlogin", "rsh"}),
        frozenset({512, 513, 514}),
        "Legacy r-services (rlogin/rsh/rexec) exposed",
        Severity.HIGH,
        "r-services use host-based trust and cleartext transport.",
        "Disable r-services and replace them with SSH.",
    ),
    ExposureRule(
        "EXP-DOCKER-API",
        frozenset({"docker"}),
        frozenset({2375}),
        "Unencrypted Docker Engine API port exposed",
        Severity.HIGH,
        "Port 2375 is the conventional unauthenticated, unencrypted Docker API; if it is the "
        "Docker API, access usually equals root on the host.",
        "Bind the Docker API to a local socket or enable TLS client authentication on 2376.",
    ),
    ExposureRule(
        "EXP-FTP",
        frozenset({"ftp"}),
        frozenset({21}),
        "FTP service exposed",
        Severity.MEDIUM,
        "Plain FTP sends credentials in cleartext unless explicit TLS is enforced.",
        "Use SFTP/FTPS with TLS required, or disable the service.",
        skip_if_tls=True,
    ),
    ExposureRule(
        "EXP-RDP",
        frozenset({"ms-wbt-server", "rdp"}),
        frozenset({3389}),
        "Remote Desktop (RDP) exposed",
        Severity.MEDIUM,
        "RDP is a frequent target for password guessing and has a history of serious flaws.",
        "Restrict RDP to VPN/management networks, require NLA and MFA, keep hosts patched.",
    ),
    ExposureRule(
        "EXP-VNC",
        frozenset({"vnc"}),
        frozenset({5900, 5901, 5902, 5903}),
        "VNC remote desktop exposed",
        Severity.MEDIUM,
        "Many VNC deployments use weak passwords and unencrypted transport.",
        "Tunnel VNC over SSH/VPN and restrict source addresses.",
    ),
    ExposureRule(
        "EXP-SMB",
        frozenset({"microsoft-ds", "netbios-ssn", "smb"}),
        frozenset({139, 445}),
        "SMB/NetBIOS file sharing exposed",
        Severity.MEDIUM,
        "SMB exposure widens the attack surface for credential relay and wormable flaws.",
        "Limit SMB to required internal segments, disable SMBv1, require signing.",
    ),
    ExposureRule(
        "EXP-DATASTORE",
        frozenset(
            {
                "mysql",
                "postgresql",
                "ms-sql-s",
                "mongodb",
                "redis",
                "elasticsearch",
                "memcached",
                "couchdb",
                "cassandra",
            }
        ),
        frozenset({3306, 5432, 1433, 27017, 6379, 9200, 11211, 5984, 9042}),
        "Database or cache service reachable over the network",
        Severity.MEDIUM,
        "Datastores reachable beyond application hosts risk data exposure if authentication is "
        "weak or disabled (authentication was NOT tested).",
        "Restrict datastore ports to application hosts with firewall rules; verify auth and TLS.",
    ),
    ExposureRule(
        "EXP-HTTP-CLEARTEXT",
        frozenset({"http", "http-proxy", "http-alt"}),
        frozenset({80, 8080, 8000, 8008}),
        "Cleartext HTTP service",
        Severity.LOW,
        "HTTP without TLS exposes traffic to interception; it may only redirect to HTTPS "
        "(not verified).",
        "Serve over HTTPS and redirect HTTP; enable HSTS where appropriate.",
        skip_if_tls=True,
    ),
)

LARGE_SURFACE_THRESHOLD = 20


def _matches(rule: ExposureRule, svc: Service) -> bool:
    if svc.state != "open":
        return False
    if rule.skip_if_tls and svc.tunnel == "ssl":
        return False
    if svc.name:
        return svc.name in rule.names
    return svc.port in rule.ports


def _service_label(svc: Service) -> str:
    parts = [f"{svc.port}/{svc.protocol}", svc.state]
    if svc.name:
        parts.append(f"service={svc.name}" + ("(ssl)" if svc.tunnel == "ssl" else ""))
    if svc.product:
        parts.append(f"product={svc.product}")
    if svc.version:
        parts.append(f"version={svc.version}")
    return " ".join(parts)


def analyze_hosts(hosts: Iterable[Host], advisories: AdvisoryDB) -> list[Finding]:
    """Produce findings from observed hosts. Purely offline; sends no traffic."""
    findings: list[Finding] = []
    for host in hosts:
        open_services = [s for s in host.services if s.state == "open"]
        for svc in open_services:
            for rule in EXPOSURE_RULES:
                if not _matches(rule, svc):
                    continue
                # Name-based matches are better evidence than port-number guesses.
                conf = Confidence.HIGH if svc.name in rule.names else Confidence.MEDIUM
                findings.append(
                    Finding(
                        id=f"{rule.rule_id}:{host.address}:{svc.port}",
                        title=rule.title,
                        category="exposure",
                        severity=rule.severity,
                        confidence=conf,
                        kind=FindingKind.INFERRED,
                        target=f"{host.address}:{svc.port}/{svc.protocol}",
                        evidence=[f"observed: {_service_label(svc)}"],
                        rationale=rule.rationale
                        + (
                            ""
                            if conf is Confidence.HIGH
                            else " Service identity inferred from port number only."
                        ),
                        remediation=rule.remediation,
                    )
                )
            for m in advisories.match(svc.product, svc.version, svc.extra_info):
                conf = Confidence.MEDIUM if (m.exact and not m.backport_hint) else Confidence.LOW
                caveats = [
                    "Version-based correlation only; not confirmed and exploitability not tested.",
                ]
                if m.backport_hint:
                    caveats.append(
                        "Banner suggests a distribution package; fixes may be backported "
                        "without changing the upstream version."
                    )
                findings.append(
                    Finding(
                        id=f"ADV:{m.advisory.id}:{host.address}:{svc.port}",
                        title=f"Potentially affected by {m.advisory.id}: {m.advisory.summary}",
                        category="advisory",
                        severity=m.advisory.severity,
                        confidence=conf,
                        kind=FindingKind.POTENTIAL_VULNERABILITY,
                        target=f"{host.address}:{svc.port}/{svc.protocol}",
                        evidence=[
                            f"observed: {_service_label(svc)}",
                            f"advisory source: {m.advisory.source}",
                            "match type: " + ("exact version" if m.exact else "version range"),
                        ],
                        rationale=(
                            f"Severity '{m.advisory.severity.label}' is taken from the advisory. "
                            + " ".join(caveats)
                        ),
                        remediation=m.advisory.remediation
                        + " Verify the installed package version on the host before acting.",
                        references=list(m.advisory.references),
                    )
                )
        if len(open_services) > LARGE_SURFACE_THRESHOLD:
            findings.append(
                Finding(
                    id=f"SURFACE:{host.address}",
                    title="Large number of open TCP ports",
                    category="configuration",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    kind=FindingKind.OBSERVED,
                    target=host.address,
                    evidence=[f"observed: {len(open_services)} open ports in scanned set"],
                    rationale="Each exposed service adds attack surface and patching burden.",
                    remediation="Review which services are required and firewall the rest.",
                )
            )
        if host.os_guesses:
            best = max(host.os_guesses, key=lambda g: g.accuracy)
            findings.append(
                Finding(
                    id=f"OSFP:{host.address}",
                    title=f"OS fingerprint estimate: {best.name}",
                    category="inventory",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM if best.accuracy >= 95 else Confidence.LOW,
                    kind=FindingKind.OBSERVED,
                    target=host.address,
                    evidence=[f"nmap osmatch accuracy {best.accuracy}% (statistical estimate)"],
                    rationale="OS fingerprints are estimates; NAT or firewalls can mislead them.",
                    remediation="Confirm the OS from asset inventory before relying on this.",
                )
            )
    return sort_findings(findings)


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Most severe first, then highest confidence, then stable by id."""
    return sorted(findings, key=lambda f: (-f.severity, -f.confidence, f.id))


def max_severity(findings: Iterable[Finding]) -> Severity | None:
    """Highest severity present, or None if there are no findings."""
    return max((f.severity for f in findings), default=None)


def exceeds_threshold(findings: Iterable[Finding], threshold: Severity | None) -> bool:
    """True if any finding is at or above ``threshold``."""
    if threshold is None:
        return False
    top = max_severity(findings)
    return top is not None and top >= threshold


def explain_attack_paths(findings: Iterable[Finding]) -> list[dict[str, Any]]:
    """Describe plausible attack paths from findings. Explanation only, nothing is executed."""
    paths: list[dict[str, Any]] = []
    templates = {
        "EXP-TELNET": [
            "attacker with network path to the host",
            "passively captures cleartext Telnet credentials",
            "logs in as the captured user",
        ],
        "EXP-RSERVICES": [
            "attacker on a trusted network segment",
            "abuses host-based trust of r-services",
            "obtains a shell without a password",
        ],
        "EXP-DOCKER-API": [
            "attacker reaches the Docker API port",
            "starts a privileged container mounting the host filesystem",
            "gains root-equivalent control of the host",
        ],
        "EXP-DATASTORE": [
            "attacker reaches the datastore port",
            "connects if authentication is weak or absent (untested)",
            "reads or modifies stored data",
        ],
        "EXP-RDP": [
            "attacker reaches RDP",
            "attempts credential guessing or a known RDP flaw",
            "obtains an interactive desktop session",
        ],
    }
    for f in findings:
        rule_id = f.id.split(":", 1)[0]
        if rule_id in templates and f.severity >= Severity.MEDIUM:
            paths.append(
                {
                    "based_on_finding": f.id,
                    "target": f.target,
                    "steps": templates[rule_id],
                    "status": "explained_only_not_tested",
                    "preconditions_verified": False,
                }
            )
    return paths
