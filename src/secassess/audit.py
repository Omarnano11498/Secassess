"""Concise, append-only local audit log (JSON Lines).

Records what the operator selected and how the run ended. It never records secrets, tool output
or report contents, and it is never deleted or rewritten by this program.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any

from secassess.models import utc_now_iso
from secassess.redact import redact

log = logging.getLogger(__name__)


class AuditLog:
    """Append-only audit trail for one run."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.run_id = uuid.uuid4().hex[:16]

    def record(self, event: str, **fields: Any) -> None:
        """Append one event. Failures are logged loudly but do not crash the run."""
        entry = {"ts": utc_now_iso(), "run_id": self.run_id, "event": event, **redact(fields)}
        line = json.dumps(entry, sort_keys=True, default=str)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            log.error("AUDIT LOG WRITE FAILED (%s): %s", self.path, exc.strerror)
