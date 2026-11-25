"""Build a local advisory file from the NIST National Vulnerability Database (NVD API 2.0).

This is the only module that talks to the internet, and only when the operator explicitly runs
``secassess advisories fetch``. It sends nothing but public CPE product identifiers to
``services.nvd.nist.gov`` and writes a file in the local advisory format
(:mod:`secassess.risk.advisories`), which network assessments then use offline.

Mapping: each Nmap ``product`` string (what service detection reports, e.g. ``OpenSSH``) is
mapped to one or more NVD CPE ``vendor:product`` pairs. CVE configurations are converted to
version ranges: ``versionStartIncluding`` -> ``introduced``, ``versionStartExcluding`` ->
``introduced_after``, ``versionEndExcluding`` -> ``fixed``,
``versionEndIncluding`` -> ``last_affected``; exact CPE versions become ``versions``.
Entries that cover *all* versions are skipped because they cannot be correlated with a banner.
"""

from __future__ import annotations

import http.client
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from typing import Any

from secassess import __version__
from secassess.errors import ToolError
from secassess.models import Severity
from secassess.risk.advisories import parse_version

log = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000

# Nmap service-detection product name -> NVD CPE "vendor:product" identifiers.
PRODUCT_CPES: dict[str, tuple[str, ...]] = {
    "OpenSSH": ("openbsd:openssh",),
    "Dropbear sshd": ("dropbear_ssh_project:dropbear_ssh",),
    "Apache httpd": ("apache:http_server",),
    "Apache Tomcat": ("apache:tomcat",),
    "nginx": ("f5:nginx", "nginx:nginx"),
    "lighttpd": ("lighttpd:lighttpd",),
    "Microsoft IIS httpd": ("microsoft:internet_information_services",),
    "Squid http proxy": ("squid-cache:squid",),
    "vsftpd": ("vsftpd_project:vsftpd", "beasts:vsftpd"),
    "ProFTPD": ("proftpd:proftpd",),
    "Pure-FTPd": ("pureftpd:pure-ftpd",),
    "Exim smtpd": ("exim:exim",),
    "Postfix smtpd": ("postfix:postfix",),
    "Dovecot imapd": ("dovecot:dovecot",),
    "Dovecot pop3d": ("dovecot:dovecot",),
    "Samba smbd": ("samba:samba",),
    "ISC BIND": ("isc:bind",),
    "MySQL": ("oracle:mysql", "mysql:mysql"),
    "PostgreSQL DB": ("postgresql:postgresql",),
    "Redis key-value store": ("redis:redis",),
}

HttpGet = Callable[[str, dict[str, str]], bytes]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: they could leave the NVD host and would carry the API key with them."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        """Never follow; urllib then raises HTTPError with the 3xx status."""
        return None


def urllib_get(url: str, headers: dict[str, str]) -> bytes:
    """HTTPS GET restricted to the NVD API host."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.netloc != "services.nvd.nist.gov":
        raise ToolError(f"refusing to fetch from unexpected URL: {url}")
    req = urllib.request.Request(url, headers=headers)  # noqa: S310 - https + fixed host above
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(req, timeout=90) as resp:
        data: bytes = resp.read()
        return data


def _severity(cve: dict[str, Any]) -> str | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            sev = (m.get("cvssData") or {}).get("baseSeverity")
            if sev:
                return str(sev).lower()
    for m in metrics.get("cvssMetricV2") or []:
        if m.get("baseSeverity"):
            return str(m["baseSeverity"]).lower()
    return None


def _description(cve: dict[str, Any]) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en" and d.get("value"):
            text = " ".join(str(d["value"]).split())
            return text if len(text) <= 400 else text[:399] + "…"
    return "No description provided by NVD."


def _numeric(version: object) -> bool:
    return parse_version(str(version)) is not None


def sanitize_advisory(adv: dict[str, Any]) -> dict[str, Any] | None:
    """Drop non-numeric bounds/versions from an advisory dict; None if nothing usable is left."""
    ranges = []
    for r in adv.get("affected", []):
        clean = {k: v for k, v in r.items() if _numeric(v)}
        if ("fixed" in clean or "last_affected" in clean) and clean not in ranges:
            ranges.append(clean)
    exact = [v for v in adv.get("versions", []) if _numeric(v)]
    out = {k: v for k, v in adv.items() if k not in ("affected", "versions")}
    if ranges:
        out["affected"] = ranges
    if exact:
        out["versions"] = exact
    return out if ranges or exact else None


def _cpe_version(criteria: str) -> tuple[str, str, str, str] | None:
    """Return (vendor, product, version, update) from a CPE 2.3 string."""
    parts = criteria.split(":")
    if len(parts) < 7 or parts[0] != "cpe" or parts[2] not in ("a", "o", "h"):
        return None
    return parts[3], parts[4], parts[5], parts[6]


def convert_cve(
    cve: dict[str, Any], nmap_product: str, cpes: Iterable[str]
) -> dict[str, Any] | None:
    """Convert one NVD CVE object into a local advisory for ``nmap_product`` (or None)."""
    if str(cve.get("vulnStatus", "")).lower() == "rejected":
        return None
    wanted = {tuple(c.split(":", 1)) for c in cpes}
    ranges: list[dict[str, str]] = []
    exact: list[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parsed = _cpe_version(str(match.get("criteria", "")))
                if parsed is None or (parsed[0], parsed[1]) not in wanted:
                    continue
                version, update = parsed[2], parsed[3]
                # Bounds that are not numeric (e.g. NGINX Plus "r27") cannot be compared with
                # a banner version and are dropped.
                rng: dict[str, str] = {}
                start_in = match.get("versionStartIncluding")
                start = start_in or match.get("versionStartExcluding")
                if start and _numeric(start):
                    rng["introduced" if start_in else "introduced_after"] = str(start)
                end_ex, end_in = match.get("versionEndExcluding"), match.get("versionEndIncluding")
                if end_ex and _numeric(end_ex):
                    rng["fixed"] = str(end_ex)
                elif end_in and _numeric(end_in):
                    rng["last_affected"] = str(end_in)
                has_bounds = bool(start or end_ex or end_in)
                if "fixed" in rng or "last_affected" in rng:
                    if rng not in ranges:
                        ranges.append(rng)
                elif not has_bounds and version not in ("*", "-", ""):
                    v = version.replace("\\", "")
                    if update not in ("*", "-", ""):
                        v += update.replace("\\", "")
                    if _numeric(v) and v not in exact:
                        exact.append(v)
                # "all versions" (no bounds, wildcard version) cannot be matched to a banner
    if not ranges and not exact:
        return None
    sev = _severity(cve) or "medium"
    if sev == "none":
        sev = "info"
    cve_id = str(cve.get("id", "?"))
    refs = [f"https://nvd.nist.gov/vuln/detail/{cve_id}"]
    refs += [str(r["url"]) for r in (cve.get("references") or [])[:3] if r.get("url")]
    advisory: dict[str, Any] = {
        "id": cve_id,
        "product": nmap_product,
        "severity": sev,
        "summary": _description(cve),
        "remediation": f"Upgrade {nmap_product} to a version outside the affected range "
        "(see references). Distribution packages may already include a backported fix.",
        "references": refs,
    }
    if ranges:
        advisory["affected"] = ranges
    if exact:
        advisory["versions"] = sorted(exact)
    return advisory


def fetch_product(
    nmap_product: str,
    cpes: Iterable[str],
    http_get: HttpGet,
    api_key: str | None = None,
    delay: float | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """Download every CVE for the product's CPEs and convert them."""
    cpes = tuple(cpes)
    headers = {"User-Agent": f"secassess/{__version__} (local advisory build)"}
    if api_key:
        headers["apiKey"] = api_key
    pause = delay if delay is not None else (0.8 if api_key else 6.5)  # NVD public rate limits
    found: dict[str, dict[str, Any]] = {}
    for cpe in cpes:
        start = 0
        while True:
            query = urllib.parse.urlencode(
                {
                    "virtualMatchString": f"cpe:2.3:*:{cpe}",
                    "resultsPerPage": PAGE_SIZE,
                    "startIndex": start,
                }
            )
            page = _get_json(f"{NVD_API}?{query}", headers, http_get, sleep, pause)
            for item in page.get("vulnerabilities") or []:
                adv = convert_cve(item.get("cve") or {}, nmap_product, cpes)
                if adv is None:
                    continue
                prev = found.get(adv["id"])
                if prev is None:
                    found[adv["id"]] = adv
                else:  # same CVE via a second CPE alias: merge bounds
                    for r in adv.get("affected", []):
                        if r not in prev.setdefault("affected", []):
                            prev["affected"].append(r)
                    prev["versions"] = sorted(
                        set(prev.get("versions", [])) | set(adv.get("versions", []))
                    )
                    if not prev["versions"]:
                        del prev["versions"]
            total = int(page.get("totalResults", 0))
            start += int(page.get("resultsPerPage", PAGE_SIZE)) or PAGE_SIZE
            sleep(pause)
            if start >= total:
                break
    return sorted(found.values(), key=lambda a: a["id"])


def _get_json(
    url: str,
    headers: dict[str, str],
    http_get: HttpGet,
    sleep: Callable[[float], None],
    pause: float,
) -> dict[str, Any]:
    last: Exception | None = None
    for attempt in range(4):
        try:
            data = json.loads(http_get(url, headers).decode("utf-8"))
            if not isinstance(data, dict):
                raise ToolError("unexpected NVD response")
            return data
        except urllib.error.HTTPError as exc:
            last = exc
            if exc.code not in (403, 429, 500, 502, 503, 504):
                raise ToolError(f"NVD request failed: HTTP {exc.code}") from exc
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # URLError, timeouts and resets are OSError; the others are truncated/invalid bodies.
            last = exc
        wait = pause * (attempt + 2)
        log.warning("NVD request failed (%s); retrying in %.0fs", last, wait)
        sleep(wait)
    raise ToolError(f"NVD request failed after retries: {last}")


def build_advisory_file(
    products: Iterable[str],
    http_get: HttpGet,
    min_severity: Severity = Severity.LOW,
    api_key: str | None = None,
    progress: Callable[[str], None] = lambda _m: None,
    sleep: Callable[[float], None] = time.sleep,
    delay: float | None = None,
) -> dict[str, Any]:
    """Fetch advisories for ``products`` and return a schema_version 1 document."""
    advisories: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for product in products:
        cpes = PRODUCT_CPES.get(product)
        if cpes is None:
            raise ToolError(f"unknown product {product!r}; known: {', '.join(PRODUCT_CPES)}")
        progress(f"fetching {product} ({', '.join(cpes)}) ...")
        items = [
            a
            for a in fetch_product(product, cpes, http_get, api_key, delay=delay, sleep=sleep)
            if Severity.parse(a["severity"]) >= min_severity
        ]
        counts[product] = len(items)
        advisories += items
        progress(f"  {product}: {len(items)} advisories")
    stamp = time.strftime("%Y-%m-%d", time.gmtime())
    return {
        "schema_version": 1,
        "source": f"NIST NVD API 2.0, fetched {stamp}, min severity {min_severity.label}",
        "generated_by": f"secassess {__version__}",
        "products": counts,
        "advisories": advisories,
    }
