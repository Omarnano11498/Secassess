"""Structured logging configuration (text or JSON lines on stderr)."""

from __future__ import annotations

import json
import logging
import sys

from secassess.models import utc_now_iso
from secassess.redact import redact_text


class JsonFormatter(logging.Formatter):
    """One JSON object per log record, with secrets redacted from the message."""

    def format(self, record: logging.LogRecord) -> str:
        """Render a record as JSON."""
        entry = {
            "ts": utc_now_iso(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": redact_text(record.getMessage()),
        }
        if record.exc_info and record.exc_info[0] is not None:
            entry["exc_type"] = record.exc_info[0].__name__
        return json.dumps(entry)


class RedactingFormatter(logging.Formatter):
    """Plain-text formatter that redacts secret-looking substrings."""

    def format(self, record: logging.LogRecord) -> str:
        """Render a record as text."""
        return redact_text(super().format(record))


def configure_logging(level: str = "WARNING", fmt: str = "text") -> None:
    """Configure the root logger once for CLI use."""
    handler = logging.StreamHandler(sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(RedactingFormatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.WARNING))
