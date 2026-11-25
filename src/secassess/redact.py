"""Redaction helpers that keep secrets out of logs, audit records and reports."""

from __future__ import annotations

import re
from typing import Any

_SENSITIVE_KEY = re.compile(
    r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|snmp_community|cookie)",
    re.IGNORECASE,
)
_INLINE_PATTERNS = (
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)['\"]?\s*[:=]\s*\S+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)bearer\s+[a-z0-9._\-]{10,}"),
)
REDACTED = "[REDACTED]"


def redact_text(text: str) -> str:
    """Replace inline secret-looking substrings."""
    out = text
    for pattern in _INLINE_PATTERNS:
        out = pattern.sub(REDACTED, out)
    return out


def redact(value: Any) -> Any:
    """Recursively redact dict values whose keys look sensitive and inline secrets in strings."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if isinstance(k, str) and _SENSITIVE_KEY.search(k) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
