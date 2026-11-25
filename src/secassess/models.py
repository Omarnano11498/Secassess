"""Shared data models: severities, confidence levels, findings and check records."""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with second precision."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class Severity(enum.IntEnum):
    """Ordered severity scale. Higher value means more severe."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        """Parse a severity name (case-insensitive). Raises ValueError on unknown input."""
        if isinstance(value, Severity):
            return value
        if not isinstance(value, str):
            raise ValueError(f"severity must be a string, got {type(value).__name__}")
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            allowed = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r}; expected one of: {allowed}") from exc

    @property
    def label(self) -> str:
        """Lower-case name for reports."""
        return self.name.lower()


class Confidence(enum.IntEnum):
    """How strongly the evidence supports a finding."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str | Confidence) -> Confidence:
        """Parse a confidence name (case-insensitive). Raises ValueError on unknown input."""
        if isinstance(value, Confidence):
            return value
        try:
            return cls[str(value).strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown confidence {value!r}; expected low, medium or high") from exc

    @property
    def label(self) -> str:
        """Lower-case name for reports."""
        return self.name.lower()


class FindingKind(enum.StrEnum):
    """Separates what was observed from what was inferred."""

    OBSERVED = "observed"  # a fact directly seen (e.g. port 23 open)
    INFERRED = "inferred"  # a risk deduced from observations (e.g. cleartext credentials)
    POTENTIAL_VULNERABILITY = "potential_vulnerability"  # advisory match, never confirmed


@dataclass(slots=True)
class Finding:
    """A single assessment result. ``evidence`` must never contain secrets."""

    id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    kind: FindingKind
    target: str
    evidence: list[str]
    rationale: str
    remediation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        data = asdict(self)
        data["severity"] = self.severity.label
        data["confidence"] = self.confidence.label
        data["kind"] = self.kind.value
        return data


class CheckStatus(enum.StrEnum):
    """Outcome of an individual check."""

    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"
    PLANNED = "planned"  # dry-run only


@dataclass(slots=True)
class CheckRecord:
    """Records each check that ran, was skipped or failed, with reason."""

    name: str
    status: CheckStatus
    detail: str = ""
    active: bool = False  # True if it sends network traffic or invokes an external tool
    impact: str = ""  # operational impact statement for active checks

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass(slots=True)
class Service:
    """An observed network service on a host."""

    port: int
    protocol: str
    state: str
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    tunnel: str = ""  # e.g. "ssl" when nmap detected TLS wrapping

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return asdict(self)


@dataclass(slots=True)
class OSGuess:
    """An OS fingerprint estimate. Always an estimate, never a fact."""

    name: str
    accuracy: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {"name": self.name, "accuracy_percent": self.accuracy, "is_estimate": True}


@dataclass(slots=True)
class Host:
    """An observed in-scope host."""

    address: str
    status: str
    services: list[Service] = field(default_factory=list)
    os_guesses: list[OSGuess] = field(default_factory=list)
    # False when the scanner gave up on the host (e.g. --host-timeout) and reported no port table.
    ports_reported: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-compatible primitives."""
        return {
            "address": self.address,
            "status": self.status,
            "services": [s.to_dict() for s in self.services],
            "os_guesses": [g.to_dict() for g in self.os_guesses],
        }
