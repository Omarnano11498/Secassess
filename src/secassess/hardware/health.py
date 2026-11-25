"""Read-only hardware-health indicators.

Important interpretation limits:

* These are *indicators* reported by the OS, firmware or drives. They cannot predict remaining
  lifespan, and absence of a warning is not proof of health.
* ``unavailable``/``unsupported`` means *no data*, which is reported separately from ``ok``.
* No stress tests, benchmarks or write tests are ever run. SMART is queried read-only
  (``smartctl -H -A -i -j``), and only when the operator opts in.
"""

from __future__ import annotations

import enum
import importlib
import json
import logging
import platform
import re
import shutil
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from secassess.errors import ToolError
from secassess.models import utc_now_iso
from secassess.runner import CommandRunner

log = logging.getLogger(__name__)


class MeasurementStatus(enum.StrEnum):
    """Status of one indicator."""

    OK = "ok"  # indicator available and within the source's normal range
    WARNING = "warning"  # source reports degradation or a threshold was crossed
    CRITICAL = "critical"  # source reports failure
    INCONCLUSIVE = "inconclusive"  # data present but cannot be interpreted reliably
    UNAVAILABLE = "unavailable"  # source exists on this platform but returned no data
    UNSUPPORTED = "unsupported"  # not supported on this platform/MVP
    ERROR = "error"  # collection failed


NO_DATA = {MeasurementStatus.UNAVAILABLE, MeasurementStatus.UNSUPPORTED, MeasurementStatus.ERROR}


@dataclass(slots=True)
class Measurement:
    """A single indicator reading with provenance."""

    name: str
    status: MeasurementStatus
    source: str
    value: Any = None
    unit: str = ""
    note: str = ""
    timestamp: str = field(default_factory=utc_now_iso)
    # False for context readings (capacity, charge level) that say nothing about wear/health.
    health_indicator: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize."""
        data = asdict(self)
        data["status"] = self.status.value
        return data


def summarize(measurements: list[Measurement]) -> dict[str, Any]:
    """Overall verdict that never equates missing data with health."""
    counts: dict[str, int] = {}
    for m in measurements:
        counts[m.status.value] = counts.get(m.status.value, 0) + 1
    with_data = [m for m in measurements if m.status not in NO_DATA and m.health_indicator]
    if not with_data:
        overall = "no_data"
        text = (
            "No hardware-health indicators could be collected (capacity/charge readings do not "
            "count); health is UNKNOWN, not healthy."
        )
    elif any(m.status is MeasurementStatus.CRITICAL for m in with_data):
        overall, text = "critical_indicator_present", "At least one source reports a failure."
    elif any(m.status is MeasurementStatus.WARNING for m in with_data):
        overall, text = "warning_indicator_present", "At least one indicator needs attention."
    else:
        overall = "no_issues_in_available_indicators"
        text = (
            "No issues in the indicators that were available. This does not guarantee "
            "health or predict remaining lifespan."
        )
    return {"overall": overall, "explanation": text, "counts": counts}


# --- Collectors --------------------------------------------------------------------------------


def collect_disk_usage(paths: list[Path] | None = None) -> list[Measurement]:
    """Filesystem capacity (a capacity indicator, not a health indicator)."""
    out: list[Measurement] = []
    for p in paths or [Path(Path.cwd().anchor)]:
        try:
            u = shutil.disk_usage(p)
        except OSError as exc:
            out.append(
                Measurement(
                    f"disk_usage:{p}", MeasurementStatus.ERROR, "shutil.disk_usage", note=str(exc)
                )
            )
            continue
        pct = round(100 * u.used / u.total, 1) if u.total else None
        status = (
            MeasurementStatus.OK
            if pct is not None and pct < 90
            else (MeasurementStatus.WARNING if pct is not None else MeasurementStatus.INCONCLUSIVE)
        )
        out.append(
            Measurement(
                f"disk_usage:{p}",
                status,
                "shutil.disk_usage",
                pct,
                "% used",
                "capacity only; says nothing about drive wear",
                health_indicator=False,
            )
        )
    return out


def _load_psutil() -> Any | None:
    try:
        return importlib.import_module("psutil")
    except ImportError:
        return None


def collect_battery(
    psutil_mod: Any | None = None,
    sysfs: Path = Path("/sys/class/power_supply"),
    system: str | None = None,
) -> list[Measurement]:
    """Battery charge and (Linux sysfs) wear relative to design capacity."""
    out: list[Measurement] = []
    system = system or platform.system()
    if system == "Linux" and sysfs.is_dir():
        for bat in sorted(sysfs.glob("BAT*")):
            full = _read_int(bat / "energy_full") or _read_int(bat / "charge_full")
            design = _read_int(bat / "energy_full_design") or _read_int(bat / "charge_full_design")
            if full and design:
                health = round(100 * full / design, 1)
                status = MeasurementStatus.OK if health >= 80 else MeasurementStatus.WARNING
                out.append(
                    Measurement(
                        f"battery_capacity_vs_design:{bat.name}",
                        status,
                        f"sysfs {bat}",
                        health,
                        "% of design",
                        "below 80% is a common replacement guideline, not a rule",
                    )
                )
            else:
                out.append(
                    Measurement(
                        f"battery_capacity_vs_design:{bat.name}",
                        MeasurementStatus.UNAVAILABLE,
                        f"sysfs {bat}",
                        note="full/design capacity not exposed",
                    )
                )
    psutil_mod = psutil_mod if psutil_mod is not None else _load_psutil()
    if psutil_mod is not None and hasattr(psutil_mod, "sensors_battery"):
        try:
            b = psutil_mod.sensors_battery()
        except Exception as exc:  # noqa: BLE001 - third-party sensor backends raise varied errors
            out.append(
                Measurement("battery_charge", MeasurementStatus.ERROR, "psutil", note=str(exc))
            )
        else:
            if b is None:
                out.append(
                    Measurement(
                        "battery_charge",
                        MeasurementStatus.UNAVAILABLE,
                        "psutil",
                        note="no battery detected or not exposed",
                    )
                )
            else:
                out.append(
                    Measurement(
                        "battery_charge",
                        MeasurementStatus.OK,
                        "psutil",
                        round(float(b.percent), 1),
                        "%",
                        "charge level only; not a health measure",
                        health_indicator=False,
                    )
                )
    elif not out:
        out.append(
            Measurement(
                "battery",
                MeasurementStatus.UNSUPPORTED,
                "none",
                note="install psutil for cross-platform battery data",
            )
        )
    return out


def collect_temperatures(
    psutil_mod: Any | None = None, thermal: Path = Path("/sys/class/thermal")
) -> list[Measurement]:
    """Component temperatures from psutil or Linux thermal zones."""
    psutil_mod = psutil_mod if psutil_mod is not None else _load_psutil()
    out: list[Measurement] = []
    if psutil_mod is not None and hasattr(psutil_mod, "sensors_temperatures"):
        try:
            temps = psutil_mod.sensors_temperatures() or {}
        except Exception as exc:  # noqa: BLE001
            temps = {}
            out.append(
                Measurement("temperatures", MeasurementStatus.ERROR, "psutil", note=str(exc))
            )
        for chip, entries in temps.items():
            for i, e in enumerate(entries):
                label = e.label or f"{chip}#{i}"
                crit = e.critical or None
                high = e.high or None
                if crit and e.current >= crit:
                    st = MeasurementStatus.CRITICAL
                elif high and e.current >= high:
                    st = MeasurementStatus.WARNING
                elif high or crit:
                    st = MeasurementStatus.OK
                else:
                    st = MeasurementStatus.INCONCLUSIVE
                out.append(
                    Measurement(
                        f"temperature:{chip}:{label}",
                        st,
                        "psutil",
                        round(float(e.current), 1),
                        "°C",
                        "" if (high or crit) else "no vendor threshold to compare",
                    )
                )
        if out:
            return out
    if thermal.is_dir():
        for zone in sorted(thermal.glob("thermal_zone*")):
            milli = _read_int(zone / "temp")
            kind = _read_text(zone / "type") or zone.name
            if milli is None:
                continue
            out.append(
                Measurement(
                    f"temperature:{kind}",
                    MeasurementStatus.INCONCLUSIVE,
                    f"sysfs {zone}",
                    round(milli / 1000, 1),
                    "°C",
                    "thermal-zone reading without trip-point interpretation",
                )
            )
    if not out:
        out.append(
            Measurement(
                "temperatures",
                MeasurementStatus.UNAVAILABLE,
                "psutil/sysfs",
                note="no temperature sensors exposed "
                "(common in VMs, containers, macOS and Windows without vendor tools)",
            )
        )
    return out


_DEVICE_RE = re.compile(r"^(/dev/[\w\-/]+|[a-zA-Z]:|/dev/disk\d+)$")


def collect_smart(runner: CommandRunner, timeout: float = 60.0) -> list[Measurement]:
    """Read-only SMART health via smartctl (opt-in). Often requires administrator rights."""
    path = runner.which("smartctl")
    if path is None:
        return [
            Measurement(
                "smart",
                MeasurementStatus.UNAVAILABLE,
                "smartctl",
                note="smartctl not installed (smartmontools)",
            )
        ]
    try:
        scan = runner.run([path, "--scan", "-j"], timeout=timeout)
        devices = json.loads(scan.stdout or "{}").get("devices", [])
    except (ToolError, json.JSONDecodeError) as exc:
        return [Measurement("smart", MeasurementStatus.ERROR, "smartctl --scan", note=str(exc))]
    if not devices:
        return [
            Measurement(
                "smart",
                MeasurementStatus.UNAVAILABLE,
                "smartctl --scan",
                note="no devices listed (may need admin rights, or virtual disks)",
            )
        ]
    out: list[Measurement] = []
    for dev in devices:
        name = str(dev.get("name", ""))
        dtype = str(dev.get("type", ""))
        if not _DEVICE_RE.match(name) or not re.fullmatch(r"[\w,+\-]*", dtype):
            out.append(
                Measurement(
                    f"smart:{name[:40]}",
                    MeasurementStatus.ERROR,
                    "smartctl",
                    note="unexpected device identifier; skipped",
                )
            )
            continue
        argv = [path, "-H", "-A", "-i", "-j"] + (["-d", dtype] if dtype else []) + [name]
        try:
            res = runner.run(argv, timeout=timeout)
            data = json.loads(res.stdout or "{}")
        except (ToolError, json.JSONDecodeError) as exc:
            out.append(
                Measurement(f"smart:{name}", MeasurementStatus.ERROR, "smartctl", note=str(exc))
            )
            continue
        out.extend(interpret_smart(name, data, res.returncode))
    return out


def interpret_smart(name: str, data: dict[str, Any], returncode: int) -> list[Measurement]:
    """Interpret smartctl JSON. Exit-code bits per smartctl(8)."""
    src = "smartctl -H -A -i -j"
    if returncode & 0b11:  # bit0 cmdline error, bit1 device open failed
        return [
            Measurement(
                f"smart:{name}",
                MeasurementStatus.UNAVAILABLE,
                src,
                note="device could not be opened (permissions or unsupported)",
            )
        ]
    out: list[Measurement] = []
    passed = (data.get("smart_status") or {}).get("passed")
    model = data.get("model_name") or data.get("model_family") or "unknown model"
    if passed is True:
        out.append(
            Measurement(
                f"smart_overall:{name}",
                MeasurementStatus.OK,
                src,
                "PASSED",
                note=f"{model}; drive self-assessment only",
            )
        )
    elif passed is False:
        out.append(
            Measurement(
                f"smart_overall:{name}",
                MeasurementStatus.CRITICAL,
                src,
                "FAILED",
                note=f"{model}; back up data and replace the drive",
            )
        )
    else:
        out.append(
            Measurement(
                f"smart_overall:{name}",
                MeasurementStatus.UNAVAILABLE,
                src,
                note="drive did not report an overall SMART status",
            )
        )
    attrs = {a.get("id"): a for a in (data.get("ata_smart_attributes") or {}).get("table", [])}
    for attr_id, label in (
        (5, "reallocated_sectors"),
        (197, "pending_sectors"),
        (198, "offline_uncorrectable"),
    ):
        a = attrs.get(attr_id)
        if a is None:
            continue
        raw = (a.get("raw") or {}).get("value")
        if isinstance(raw, int):
            st = MeasurementStatus.OK if raw == 0 else MeasurementStatus.WARNING
            out.append(Measurement(f"smart_{label}:{name}", st, src, raw, "count"))
    nvme = data.get("nvme_smart_health_information_log")
    if isinstance(nvme, dict):
        used = nvme.get("percentage_used")
        if isinstance(used, int):
            st = MeasurementStatus.OK if used < 90 else MeasurementStatus.WARNING
            out.append(
                Measurement(
                    f"nvme_percentage_used:{name}",
                    st,
                    src,
                    used,
                    "%",
                    "vendor endurance estimate; not a lifespan guarantee",
                )
            )
        crit = nvme.get("critical_warning")
        if isinstance(crit, int):
            st = MeasurementStatus.OK if crit == 0 else MeasurementStatus.WARNING
            out.append(Measurement(f"nvme_critical_warning:{name}", st, src, crit, "bitmask"))
    if returncode & 0b11111000:
        out.append(
            Measurement(
                f"smart_exit_flags:{name}",
                MeasurementStatus.WARNING,
                src,
                returncode,
                "bitmask",
                "smartctl reported prior errors/thresholds (see smartctl(8))",
            )
        )
    return out


class RemoteHardwareSource(Protocol):
    """Interface for future read-only remote sources (e.g. authorized SNMP HOST-RESOURCES-MIB).

    Not implemented in this MVP. Implementations must be read-only, scope-checked and must
    never place SNMP community strings or credentials in reports or logs.
    """

    def collect(self, address: str) -> list[Measurement]:
        """Return measurements for one in-scope address."""
        ...


def collect_local(
    runner: CommandRunner,
    include_smart: bool,
    psutil_loader: Callable[[], Any | None] = _load_psutil,
) -> list[Measurement]:
    """Run all local collectors."""
    ps = psutil_loader()
    measurements = [*collect_disk_usage(), *collect_battery(ps), *collect_temperatures(ps)]
    if include_smart:
        measurements.extend(collect_smart(runner))
    else:
        measurements.append(
            Measurement(
                "smart", MeasurementStatus.UNAVAILABLE, "smartctl", note="not requested (--smart)"
            )
        )
    return measurements


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def _read_int(path: Path) -> int | None:
    text = _read_text(path)
    try:
        return int(text) if text else None
    except ValueError:
        return None
