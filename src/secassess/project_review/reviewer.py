"""Read-only software-project review.

Never executes, imports, builds or tests the target project. Optional analyzers (Bandit,
Semgrep) are static tools invoked with argv lists and timeouts, only when the operator opts in.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secassess.errors import SecAssessError, ToolError
from secassess.models import CheckRecord, CheckStatus, Confidence, Finding, FindingKind, Severity
from secassess.runner import CommandRunner

log = logging.getLogger(__name__)

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "env",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "target",
        ".idea",
        ".vscode",
    }
)
MAX_FILES = 20000
MAX_SCAN_BYTES = 1_000_000  # per file, for secret-pattern scanning

LANGUAGES = {
    ".py": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".kt": "Kotlin",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".c": "C",
    ".h": "C/C++ header",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".swift": "Swift",
    ".sh": "Shell",
    ".ps1": "PowerShell",
    ".sql": "SQL",
    ".scala": "Scala",
    ".dart": "Dart",
}
MANIFESTS = {
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "setup.py": "python",
    "setup.cfg": "python",
    "Pipfile": "python",
    "package.json": "node",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "pom.xml": "java-maven",
    "build.gradle": "java-gradle",
    "build.gradle.kts": "java-gradle",
    "Gemfile": "ruby",
    "composer.json": "php",
}
LOCKFILES = {
    "python": {"poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.lock"},
    "node": {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"},
    "go": {"go.sum"},
    "rust": {"Cargo.lock"},
    "ruby": {"Gemfile.lock"},
    "php": {"composer.lock"},
}
FRAMEWORK_HINTS = {
    "django": "Django web framework",
    "flask": "Flask web framework",
    "fastapi": "FastAPI web framework",
    "express": "Express (Node.js) web framework",
    "react": "React front-end",
    "vue": "Vue front-end",
    "next": "Next.js",
    "@angular/core": "Angular front-end",
    "spring-boot": "Spring Boot",
    "gin-gonic/gin": "Gin (Go) web framework",
    "actix-web": "Actix (Rust) web framework",
    "rails": "Ruby on Rails",
    "laravel/framework": "Laravel",
}
SECRET_PATTERNS = (
    ("private key block", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "generic hard-coded credential",
        re.compile(
            # The name may be prefixed (DB_PASSWORD) and quoted ("password": "...").
            r"(?i)(?<![a-z0-9])(password|passwd|secret([_-]?key)?|api[_-]?key|token)\b['\"]?"
            r"\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"
        ),
    ),
)
SENSITIVE_FILENAMES = re.compile(r"(^\.env(\..+)?$|^id_(rsa|dsa|ecdsa|ed25519)$|\.p12$|\.pfx$)")
_TEXT_EXT = set(LANGUAGES) | {
    ".env",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".xml",
    ".txt",
    "",
}


@dataclass(slots=True)
class Dependency:
    """A declared dependency."""

    ecosystem: str
    name: str
    spec: str
    manifest: str
    pinned: bool

    def to_dict(self) -> dict[str, Any]:
        """Serialize."""
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "spec": self.spec,
            "manifest": self.manifest,
            "pinned": self.pinned,
        }


@dataclass(slots=True)
class ProjectReport:
    """Result of a project review."""

    root: str
    file_count: int = 0
    truncated: bool = False
    languages: dict[str, int] = field(default_factory=dict)
    manifests: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    architecture: list[dict[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize."""
        return {
            "root": self.root,
            "file_count": self.file_count,
            "truncated": self.truncated,
            "languages": self.languages,
            "manifests": self.manifests,
            "lockfiles": self.lockfiles,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "architecture": self.architecture,
            "limitations": self.limitations,
        }


def _walk(root: Path) -> tuple[list[Path], bool]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            files.append(p)
            if len(files) >= MAX_FILES:
                return files, True
    return files, False


_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?\s*(.*)$")


def _python_req(line: str, manifest: str) -> Dependency | None:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith(("-", "git+", "http")):
        return None
    m = _REQ_NAME.match(line.split(";", 1)[0])
    if not m:
        return None
    spec = m.group(3).strip()
    return Dependency("python", m.group(1).lower(), spec, manifest, spec.startswith("=="))


def _node_pinned(spec: str) -> bool:
    return bool(re.fullmatch(r"\d+\.\d+\.\d+([\-+][\w.\-]+)?", spec.strip()))


def parse_manifest(path: Path, rel: str) -> list[Dependency]:
    """Parse dependencies from a supported manifest. Returns [] for unparsed formats."""
    name = path.name
    deps: list[Dependency] = []
    try:
        if name == "requirements.txt" or (
            name.startswith("requirements") and name.endswith(".txt")
        ):
            for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                d = _python_req(line, rel)
                if d:
                    deps.append(d)
        elif name == "pyproject.toml":
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
            for line in data.get("project", {}).get("dependencies", []):
                d = _python_req(str(line), rel)
                if d:
                    deps.append(d)
            poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            for dep_name, spec in poetry.items():
                if dep_name.lower() == "python":
                    continue
                s = spec if isinstance(spec, str) else str(spec.get("version", "*"))
                deps.append(
                    Dependency(
                        "python", dep_name.lower(), s, rel, bool(re.fullmatch(r"=?\d[\w.]*", s))
                    )
                )
        elif name == "package.json":
            data = json.loads(path.read_text(encoding="utf-8-sig"))
            for section in ("dependencies", "devDependencies"):
                for dep_name, spec in (data.get(section) or {}).items():
                    deps.append(
                        Dependency("node", dep_name, str(spec), rel, _node_pinned(str(spec)))
                    )
        elif name == "go.mod":
            for m in re.finditer(
                r"^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+(v[\w.\-+]+)",
                path.read_text(encoding="utf-8-sig"),
                re.MULTILINE,
            ):
                deps.append(Dependency("go", m.group(1), m.group(2), rel, True))
        elif name == "Cargo.toml":
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
            for dep_name, spec in (data.get("dependencies") or {}).items():
                s = spec if isinstance(spec, str) else str(spec.get("version", "*"))
                deps.append(Dependency("rust", dep_name, s, rel, s.startswith("=")))
    except (OSError, ValueError, tomllib.TOMLDecodeError, AttributeError) as exc:
        log.warning("could not parse manifest %s: %s", rel, exc)
        raise SecAssessError(f"could not parse {rel}: {exc}") from exc
    return deps


def _scan_secrets(path: Path, rel: str) -> list[Finding]:
    if path.suffix.lower() not in _TEXT_EXT and not path.name.startswith(".env"):
        return []
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                out.append(
                    Finding(
                        id=f"SECRET:{rel}:{lineno}",
                        title=f"Possible {label} in source",
                        category="secrets",
                        severity=Severity.HIGH if "key" in label else Severity.MEDIUM,
                        confidence=Confidence.MEDIUM if "generic" in label else Confidence.HIGH,
                        kind=FindingKind.OBSERVED,
                        target=f"{rel}:{lineno}",
                        evidence=[
                            f"pattern '{label}' matched at line {lineno} (value not reported)"
                        ],
                        rationale="Secrets in source control are easily leaked and hard to revoke.",
                        remediation="Remove the secret, rotate it, and load it from a secret store "
                        "or environment at runtime.",
                    )
                )
                break
    return out


def _infer_architecture(
    rels: set[str], deps: list[Dependency], top_dirs: set[str] | None = None
) -> list[dict[str, str]]:
    arch: list[dict[str, str]] = []
    top = {r.split("/", 1)[0] for r in rels} | (top_dirs or set())

    def add(element: str, evidence: str, confidence: str) -> None:
        arch.append({"element": element, "evidence": evidence, "confidence": confidence})

    if "src" in top:
        add("src/ layout", "top-level src/ directory", "high")
    if top & {"tests", "test", "spec", "__tests__"}:
        add("dedicated test suite", "tests/ or spec/ directory", "high")
    if any(r.endswith("Dockerfile") or r.split("/")[-1].startswith("Dockerfile") for r in rels):
        add("containerized build", "Dockerfile present", "high")
    if any(
        r.split("/")[-1] in {"docker-compose.yml", "docker-compose.yaml", "compose.yaml"}
        for r in rels
    ):
        add("multi-service composition", "docker-compose file", "medium")
    if any(r.startswith(".github/workflows/") for r in rels) or ".gitlab-ci.yml" in rels:
        add("CI pipeline", "CI workflow definitions", "high")
    if any(r.endswith((".tf", ".tfvars")) for r in rels):
        add("infrastructure as code (Terraform)", ".tf files", "high")
    if any("/migrations/" in f"/{r}" for r in rels):
        add("database schema migrations", "migrations/ directory", "medium")
    names = {d.name.lower() for d in deps}
    for key, label in FRAMEWORK_HINTS.items():
        if key in names or any(n.endswith("/" + key) or n == key for n in names):
            add(label, f"declared dependency '{key}'", "medium")
    return arch


def review_project(
    root: Path,
    runner: CommandRunner | None = None,
    run_bandit: bool = False,
    semgrep_config: Path | None = None,
    tool_timeout: float = 600.0,
) -> ProjectReport:
    """Inspect ``root`` statically. Never executes the target project."""
    root = root.expanduser()
    if not root.is_dir():
        raise SecAssessError(f"project path is not a directory: {root}")
    root = root.resolve()
    report = ProjectReport(root=str(root))
    files, truncated = _walk(root)
    report.file_count, report.truncated = len(files), truncated
    if truncated:
        report.limitations.append(f"file walk stopped at {MAX_FILES} files")
    rels = {p.relative_to(root).as_posix() for p in files}

    langs: Counter[str] = Counter()
    ecosystems: set[str] = set()
    for p in files:
        rel = p.relative_to(root).as_posix()
        lang = LANGUAGES.get(p.suffix.lower())
        if lang:
            langs[lang] += 1
        manifest_kind = MANIFESTS.get(p.name) or (
            "python" if p.name.startswith("requirements") and p.suffix == ".txt" else None
        )
        if manifest_kind:
            report.manifests.append(rel)
            ecosystems.add(manifest_kind)
            try:
                report.dependencies.extend(parse_manifest(p, rel))
            except SecAssessError as exc:
                report.checks.append(
                    CheckRecord("project.manifest_parse", CheckStatus.FAILED, str(exc))
                )
        if any(p.name in names for names in LOCKFILES.values()):
            report.lockfiles.append(rel)
        if SENSITIVE_FILENAMES.search(p.name) and p.name not in {".env.example", ".env.sample"}:
            report.findings.append(
                Finding(
                    id=f"SENSFILE:{rel}",
                    title="Sensitive-looking file in project tree",
                    category="secrets",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    kind=FindingKind.OBSERVED,
                    target=rel,
                    evidence=[f"file name '{p.name}' (contents not read into report)"],
                    rationale="Environment files and private keys often contain credentials.",
                    remediation="Ensure it is git-ignored and not committed; rotate if it was.",
                )
            )
        report.findings.extend(_scan_secrets(p, rel))
    report.languages = dict(langs.most_common())
    report.checks.append(
        CheckRecord("project.inventory", CheckStatus.COMPLETED, f"{len(files)} files inspected")
    )
    report.checks.append(
        CheckRecord(
            "project.secret_patterns",
            CheckStatus.COMPLETED,
            "regex patterns for keys/credentials; values never reported",
        )
    )

    for eco in sorted(ecosystems):
        if eco in LOCKFILES and not any(Path(lf).name in LOCKFILES[eco] for lf in report.lockfiles):
            report.findings.append(
                Finding(
                    id=f"NOLOCK:{eco}",
                    title=f"No lockfile found for {eco} dependencies",
                    category="dependencies",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    kind=FindingKind.INFERRED,
                    target=report.root,
                    evidence=[f"manifests: {', '.join(m for m in report.manifests)}"],
                    rationale="Without a lockfile, builds may pull different "
                    "(possibly compromised) versions over time. Libraries often omit them.",
                    remediation="Commit a lockfile for applications, or pin versions explicitly.",
                )
            )
    unpinned = [d for d in report.dependencies if not d.pinned]
    if unpinned:
        sample = ", ".join(f"{d.name}{(' ' + d.spec) if d.spec else ''}" for d in unpinned[:10])
        report.findings.append(
            Finding(
                id="UNPINNED",
                title=f"{len(unpinned)} dependency declaration(s) not pinned exactly",
                category="dependencies",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                kind=FindingKind.OBSERVED,
                target=report.root,
                evidence=[f"examples: {sample}"],
                rationale="Ranges are normal in manifests if a lockfile pins resolved versions.",
                remediation="Ensure resolved versions are pinned in a lockfile and audited.",
            )
        )
    report.limitations.append(
        "Dependencies were not checked against vulnerability databases (no network access in "
        "this MVP); use pip-audit / npm audit / osv-scanner separately."
    )
    top_dirs = {p.name for p in root.iterdir() if p.is_dir() and not p.is_symlink()}
    report.architecture = _infer_architecture(rels, report.dependencies, top_dirs)
    if not report.architecture:
        report.limitations.append("No recognizable architectural structure could be inferred.")
    known = set(LANGUAGES.values())
    if langs and not set(langs) <= known:
        report.limitations.append("Some languages are not recognized by the inventory.")
    if not langs:
        report.limitations.append("No recognized source-code files were found.")

    _run_optional_tools(
        report, root, runner, run_bandit, semgrep_config, tool_timeout, has_python="Python" in langs
    )
    return report


def _run_optional_tools(
    report: ProjectReport,
    root: Path,
    runner: CommandRunner | None,
    run_bandit: bool,
    semgrep_config: Path | None,
    timeout: float,
    has_python: bool,
) -> None:
    if not run_bandit:
        report.checks.append(
            CheckRecord("project.bandit", CheckStatus.SKIPPED, "not requested (--bandit)")
        )
    elif runner is None or (path := runner.which("bandit")) is None:
        report.checks.append(
            CheckRecord(
                "project.bandit", CheckStatus.SKIPPED, "bandit not installed (pip install bandit)"
            )
        )
    elif not has_python:
        report.checks.append(
            CheckRecord("project.bandit", CheckStatus.SKIPPED, "no Python files found")
        )
    else:
        argv = [
            path,
            "-r",
            str(root),
            "-f",
            "json",
            "-q",
            "-x",
            ",".join(str(root / d) for d in sorted(SKIP_DIRS)),
        ]
        try:
            res = runner.run(argv, timeout=timeout)
            # bandit exits 1 when issues are found; that is not a failure.
            if res.returncode not in (0, 1):
                raise ToolError(f"bandit exited {res.returncode}: {res.stderr.strip()[:200]}")
            data = json.loads(res.stdout or "{}")
            for item in data.get("results", []):
                report.findings.append(_bandit_finding(item, root))
            report.checks.append(
                CheckRecord(
                    "project.bandit",
                    CheckStatus.COMPLETED,
                    f"{len(data.get('results', []))} issue(s)",
                    active=True,
                    impact="local static analysis only",
                )
            )
        except (ToolError, json.JSONDecodeError) as exc:
            report.checks.append(CheckRecord("project.bandit", CheckStatus.FAILED, str(exc)))

    if semgrep_config is None:
        report.checks.append(
            CheckRecord(
                "project.semgrep", CheckStatus.SKIPPED, "not configured (--semgrep-config PATH)"
            )
        )
    elif not semgrep_config.is_file():
        report.checks.append(
            CheckRecord(
                "project.semgrep",
                CheckStatus.FAILED,
                "semgrep config must be an existing local rules file",
            )
        )
    elif runner is None or (spath := runner.which("semgrep")) is None:
        report.checks.append(
            CheckRecord("project.semgrep", CheckStatus.SKIPPED, "semgrep not installed")
        )
    else:
        argv = [
            spath,
            "scan",
            "--config",
            str(semgrep_config.resolve()),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            str(root),
        ]
        try:
            res = runner.run(argv, timeout=timeout)
            if res.returncode not in (0, 1):
                raise ToolError(f"semgrep exited {res.returncode}: {res.stderr.strip()[:200]}")
            data = json.loads(res.stdout or "{}")
            for item in data.get("results", []):
                report.findings.append(_semgrep_finding(item, root))
            if tool_errors := data.get("errors") or []:
                report.limitations.append(
                    f"Semgrep reported {len(tool_errors)} error(s); some files may not have been "
                    "fully analyzed."
                )
            report.checks.append(
                CheckRecord(
                    "project.semgrep",
                    CheckStatus.COMPLETED,
                    f"{len(data.get('results', []))} match(es)",
                    active=True,
                    impact="local static analysis only",
                )
            )
        except (ToolError, json.JSONDecodeError) as exc:
            report.checks.append(CheckRecord("project.semgrep", CheckStatus.FAILED, str(exc)))


def _rel(root: Path, filename: str) -> str:
    try:
        return Path(filename).resolve().relative_to(root).as_posix()
    except ValueError:
        return Path(filename).name


_BANDIT_SEV = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}
_BANDIT_CONF = {"LOW": Confidence.LOW, "MEDIUM": Confidence.MEDIUM, "HIGH": Confidence.HIGH}


def _bandit_finding(item: dict[str, Any], root: Path) -> Finding:
    rel = _rel(root, str(item.get("filename", "?")))
    line = item.get("line_number", 0)
    return Finding(
        id=f"BANDIT:{item.get('test_id', '?')}:{rel}:{line}",
        title=f"Bandit {item.get('test_id', '')}: {item.get('issue_text', '')}"[:200],
        category="static-analysis",
        severity=_BANDIT_SEV.get(str(item.get("issue_severity", "")).upper(), Severity.LOW),
        confidence=_BANDIT_CONF.get(str(item.get("issue_confidence", "")).upper(), Confidence.LOW),
        kind=FindingKind.INFERRED,
        target=f"{rel}:{line}",
        evidence=[f"bandit test {item.get('test_name', '')} at line {line}"],
        rationale="Static pattern match; requires human review for exploitability.",
        remediation=str(item.get("more_info", "See Bandit documentation.")),
    )


_SEMGREP_SEV = {"INFO": Severity.INFO, "WARNING": Severity.MEDIUM, "ERROR": Severity.HIGH}


def _semgrep_finding(item: dict[str, Any], root: Path) -> Finding:
    rel = _rel(root, str(item.get("path", "?")))
    line = (item.get("start") or {}).get("line", 0)
    extra = item.get("extra") or {}
    return Finding(
        id=f"SEMGREP:{item.get('check_id', '?')}:{rel}:{line}",
        title=f"Semgrep: {str(extra.get('message', item.get('check_id', '')))[:180]}",
        category="static-analysis",
        severity=_SEMGREP_SEV.get(str(extra.get("severity", "")).upper(), Severity.LOW),
        confidence=Confidence.MEDIUM,
        kind=FindingKind.INFERRED,
        target=f"{rel}:{line}",
        evidence=[f"rule {item.get('check_id', '?')} matched at line {line}"],
        rationale="Static rule match from operator-supplied rules; review required.",
        remediation="Review the flagged code against the rule's guidance.",
    )
