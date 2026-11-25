"""Local advisory database loading and conservative version matching.

The project ships **no vulnerability data**. Operators supply their own advisory JSON files
(for example, curated exports of vendor advisories). A version match only ever yields a
*potential* vulnerability with low or medium confidence, because banners can be wrong and Linux
distributions routinely backport fixes without changing upstream version numbers.

File format (``schema_version`` 1)::

    {
      "schema_version": 1,
      "source": "free-text description of where this data came from",
      "advisories": [
        {
          "id": "VENDOR-2024-0001",
          "product": "ExampleServer",          # compared case-insensitively to nmap 'product'
          "affected": [{"introduced": "1.0", "fixed": "1.4.2"}],   # fixed is exclusive
                                               # or {"last_affected": "1.4.1"} (inclusive)
          "versions": ["1.4.1"],               # optional exact list (alternative to ranges)
          "severity": "high",
          "summary": "short description",
          "remediation": "upgrade to 1.4.2 or later",
          "references": ["https://vendor.example/advisory"]
        }
      ]
    }
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secassess.errors import ConfigError
from secassess.models import Severity

_NUM = re.compile(r"\d+")
_BACKPORT_HINT = re.compile(r"(?i)(ubuntu|debian|deb\d|el\d|rhel|centos|suse|alpine|\+dfsg)")


def parse_version(text: str) -> tuple[int, ...] | None:
    """Parse the leading version token into an integer tuple, e.g. '8.9p1' -> (8, 9, 1)."""
    token = text.strip().split(" ", 1)[0] if text and text.strip() else ""
    if not token or not token[0].isdigit():
        return None
    parts = tuple(int(p) for p in _NUM.findall(token))
    return parts or None


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    width = max(len(a), len(b))
    pa, pb = a + (0,) * (width - len(a)), b + (0,) * (width - len(b))
    return (pa > pb) - (pa < pb)


@dataclass(frozen=True, slots=True)
class VersionRange:
    """Range [introduced, fixed) or [introduced, last_affected]. Missing bounds are unbounded.

    ``last_affected`` is inclusive. As in NVD, a suffix counts as a later version: ``9.8p1`` is
    after ``9.8`` (NVD lists OpenSSH ``p1`` releases as a separate CPE update).
    """

    introduced: tuple[int, ...] | None
    fixed: tuple[int, ...] | None
    last_affected: tuple[int, ...] | None = None
    introduced_after: tuple[int, ...] | None = None  # exclusive lower bound

    def contains(self, v: tuple[int, ...]) -> bool:
        """True if ``v`` falls inside the range."""
        if self.introduced is not None and _cmp(v, self.introduced) < 0:
            return False
        if self.introduced_after is not None and _cmp(v, self.introduced_after) <= 0:
            return False
        if self.fixed is not None and _cmp(v, self.fixed) >= 0:
            return False
        return not (self.last_affected is not None and _cmp(v, self.last_affected) > 0)


@dataclass(frozen=True, slots=True)
class Advisory:
    """One advisory record."""

    id: str
    product: str
    severity: Severity
    summary: str
    remediation: str
    ranges: tuple[VersionRange, ...] = ()
    exact_versions: frozenset[str] = frozenset()
    references: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True, slots=True)
class AdvisoryMatch:
    """A version-based correlation. Never proof of exploitability."""

    advisory: Advisory
    observed_version: str
    exact: bool
    backport_hint: bool


@dataclass(slots=True)
class AdvisoryDB:
    """In-memory advisory collection."""

    advisories: list[Advisory] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def match(self, product: str, version: str, extra_info: str = "") -> list[AdvisoryMatch]:
        """Return advisories whose product equals ``product`` and whose range covers ``version``."""
        if not product or not version:
            return []
        parsed = parse_version(version)
        hint = bool(_BACKPORT_HINT.search(f"{version} {extra_info}"))
        out: list[AdvisoryMatch] = []
        for adv in self.advisories:
            if adv.product.casefold() != product.strip().casefold():
                continue
            token = version.strip().split(" ", 1)[0]
            if token in adv.exact_versions:
                out.append(AdvisoryMatch(adv, version, True, hint))
            elif parsed is not None and any(r.contains(parsed) for r in adv.ranges):
                out.append(AdvisoryMatch(adv, version, False, hint))
        return out


def _bound(r: dict[str, Any], key: str, where: str) -> tuple[int, ...] | None:
    if not r.get(key):
        return None
    parsed = parse_version(str(r[key]))
    if parsed is None:  # dropping the bound would silently widen the affected range
        raise ConfigError(f"{where}: {key!r} is not a numeric version: {r[key]!r}")
    return parsed


def _parse_advisory(item: Any, source: str, where: str) -> Advisory:
    if not isinstance(item, dict):
        raise ConfigError(f"{where}: advisory entry must be an object")
    for key in ("id", "product", "severity", "summary"):
        if not isinstance(item.get(key), str) or not item[key].strip():
            raise ConfigError(f"{where}: advisory missing string field {key!r}")
    try:
        severity = Severity.parse(item["severity"])
    except ValueError as exc:
        raise ConfigError(f"{where} ({item['id']}): {exc}") from exc
    ranges: list[VersionRange] = []
    affected = item.get("affected", [])
    if not isinstance(affected, list):
        raise ConfigError(f"{where} ({item['id']}): 'affected' must be a list")
    for r in affected:
        if not isinstance(r, dict):
            raise ConfigError(f"{where} ({item['id']}): 'affected' entries must be objects")
        label = f"{where} ({item['id']})"
        intro = _bound(r, "introduced", label)
        after = _bound(r, "introduced_after", label)
        fixed = _bound(r, "fixed", label)
        last = _bound(r, "last_affected", label)
        if intro is None and after is None and fixed is None and last is None:
            raise ConfigError(
                f"{label}: range needs 'introduced', 'introduced_after', 'fixed' or 'last_affected'"
            )
        ranges.append(VersionRange(intro, fixed, last, after))
    exact = item.get("versions", [])
    if not isinstance(exact, list) or not all(isinstance(v, str) for v in exact):
        raise ConfigError(f"{where} ({item['id']}): 'versions' must be a list of strings")
    if not ranges and not exact:
        raise ConfigError(f"{where} ({item['id']}): needs 'affected' ranges or 'versions'")
    refs = item.get("references", [])
    return Advisory(
        id=item["id"].strip(),
        product=item["product"].strip(),
        severity=severity,
        summary=item["summary"].strip(),
        remediation=str(item.get("remediation", "Apply the vendor's fixed version.")),
        ranges=tuple(ranges),
        exact_versions=frozenset(exact),
        references=tuple(str(r) for r in refs) if isinstance(refs, list) else (),
        source=source,
    )


def load_advisories(paths: list[Path]) -> AdvisoryDB:
    """Load and validate advisory files. Missing files are a configuration error."""
    db = AdvisoryDB()
    for path in paths:
        try:
            doc = json.loads(path.read_text(encoding="utf-8-sig"))
        except OSError as exc:
            raise ConfigError(f"cannot read advisory file {path}: {exc.strerror}") from exc
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"invalid JSON in advisory file {path}: {exc}") from exc
        if not isinstance(doc, dict) or doc.get("schema_version") != 1:
            raise ConfigError(f"{path}: expected an object with schema_version = 1")
        items = doc.get("advisories", [])
        if not isinstance(items, list):
            raise ConfigError(f"{path}: 'advisories' must be a list")
        source = str(doc.get("source", path.name))
        db.sources.append(f"{path.name}: {source} ({len(items)} advisories)")
        for i, item in enumerate(items):
            db.advisories.append(_parse_advisory(item, source, f"{path.name}[{i}]"))
    return db
