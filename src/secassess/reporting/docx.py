"""Word (.docx) report export, Arabic right-to-left, standard library only.

The document is assembled directly as Office Open XML inside a ZIP container, so the core keeps
its "no mandatory third-party dependencies" property. Input is one or more report dicts in the
JSON schema produced by :meth:`secassess.reporting.report.Report.to_dict`; several reports
(e.g. network + project + hardware) are merged into a single document.

Arabic text runs are marked right-to-left; Latin/digit tokens inside them (IP ranges, paths,
flags, numbers) are emitted as separate left-to-right runs so Word keeps their order and digits.
"""

from __future__ import annotations

import os
import re
import zipfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from secassess.redact import redact

# --------------------------------------------------------------------------- vocabulary

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_AR = {
    "critical": "حرجة",
    "high": "عالية",
    "medium": "متوسطة",
    "low": "منخفضة",
    "info": "معلوماتية",
}
SEVERITY_COLOR = {
    "critical": "7B0000",
    "high": "C00000",
    "medium": "C55A11",
    "low": "2E75B6",
    "info": "595959",
}
STATUS_AR = {
    "completed": "مكتمل",
    "skipped": "متخطّى",
    "failed": "فشل",
    "planned": "مخطط",
    "ok": "سليم",
    "warning": "تحذير",
    "critical": "حرج",
    "inconclusive": "غير حاسم",
    "unavailable": "غير متاح",
    "unsupported": "غير مدعوم",
    "error": "خطأ",
    "no_data": "لا توجد بيانات",
    "healthy": "سليم",
    "degraded": "متدهور",
}
CONF_AR = {"high": "عالية", "medium": "متوسطة", "low": "منخفضة"}
KIND_AR = {"observed": "مُلاحَظ", "inferred": "مُستنتَج", "confirmed": "مؤكَّد"}
MODE_AR = {"dry-run": "تشغيل تجريبي (dry-run)", "active": "نشط", "local": "محلي، قراءة فقط"}
COMMAND_AR = {
    "network": "فحص الشبكة",
    "project": "مراجعة المشروع البرمجي",
    "hardware": "مؤشرات صحة العتاد",
}
COMMAND_ORDER = {"network": 0, "project": 1, "hardware": 2}

NAVY = "1F3864"
BLUE = "2F5496"
GREY = "F2F2F2"
HEAD_FILL = "D9E2F3"
BORDER = "BFBFBF"
FONT = "Arial"
MONO = "Consolas"

PAGE_W, PAGE_H, MARGIN = 11906, 16838, 1134  # A4, 2 cm margins (twentieths of a point)
TEXT_W = PAGE_W - 2 * MARGIN

MAX_DETAILED_FINDINGS = 40
MAX_TITLE = 160

_ARABIC = re.compile(r"[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]")
# A left-to-right span: starts at a Latin letter/digit (or a --flag), may contain any non-Arabic
# characters (spaces, punctuation), and ends at a letter/digit/%/slash so that surrounding
# brackets and punctuation stay in the RTL run and are mirrored correctly.
_LTR_TOKEN = re.compile(
    r"((?:--?)?[A-Za-z0-9](?:[^؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿«»—]*"
    r"[A-Za-z0-9%/\\])?)"
)
_INVALID_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")


# --------------------------------------------------------------------------- XML primitives


def _x(text: object) -> str:
    return escape(_INVALID_XML.sub("", str(text)), {'"': "&quot;"})


def _has_arabic(text: str) -> bool:
    return bool(_ARABIC.search(text))


@dataclass(frozen=True, slots=True)
class Style:
    """Character formatting for a run."""

    bold: bool = False
    italic: bool = False
    color: str | None = None
    size: int | None = None  # half-points
    mono: bool = False


PLAIN = Style()


def _run_xml(text: str, style: Style, rtl: bool) -> str:
    font = MONO if style.mono else FONT
    props = [f'<w:rFonts w:ascii="{font}" w:hAnsi="{font}" w:cs="{font}" w:eastAsia="{font}"/>']
    if style.bold:
        props.append("<w:b/><w:bCs/>")
    if style.italic:
        props.append("<w:i/><w:iCs/>")
    if style.color:
        props.append(f'<w:color w:val="{style.color}"/>')
    if style.size:
        props.append(f'<w:sz w:val="{style.size}"/><w:szCs w:val="{style.size}"/>')
    if rtl:
        props.append("<w:rtl/>")
    return f'<w:r><w:rPr>{"".join(props)}</w:rPr><w:t xml:space="preserve">{_x(text)}</w:t></w:r>'


def runs(text: object, style: Style = PLAIN) -> str:
    """Runs for mixed Arabic/Latin text; Latin and digit tokens stay left-to-right."""
    s = str(text)
    if not _has_arabic(s):
        return _run_xml(s, style, rtl=False)
    out = []
    pos = 0
    while (m := _LTR_TOKEN.search(s, pos)) is not None:
        start, end = m.span()
        # Absorb closing brackets that belong to an opening bracket inside the span.
        while (
            end < len(s) and s[end] == ")" and s.count("(", start, end) > s.count(")", start, end)
        ):
            end += 1
        if start > pos:
            out.append(_run_xml(s[pos:start], style, rtl=True))
        out.append(_run_xml(s[start:end], style, rtl=False))
        pos = end
    if pos < len(s):
        out.append(_run_xml(s[pos:], style, rtl=True))
    return "".join(out)


def para(
    content: str,
    *,
    rtl: bool = True,
    style_id: str | None = None,
    align: str | None = None,
    num_id: int | None = None,
    after: int = 100,
    before: int = 0,
    border_bottom: bool = False,
    keep_next: bool = False,
) -> str:
    """A paragraph; ``content`` is pre-built run XML."""
    ppr = []
    if style_id:
        ppr.append(f'<w:pStyle w:val="{style_id}"/>')
    if keep_next:
        ppr.append("<w:keepNext/>")
    if num_id is not None:
        ppr.append(f'<w:numPr><w:ilvl w:val="0"/><w:numId w:val="{num_id}"/></w:numPr>')
    if border_bottom:
        ppr.append(
            f'<w:pBdr><w:bottom w:val="single" w:sz="8" w:space="6" w:color="{NAVY}"/></w:pBdr>'
        )
    if rtl:
        ppr.append("<w:bidi/>")
    ppr.append(f'<w:spacing w:before="{before}" w:after="{after}"/>')
    if align:
        ppr.append(f'<w:jc w:val="{align}"/>')
    elif not rtl:
        ppr.append('<w:jc w:val="left"/>')
    return f"<w:p><w:pPr>{''.join(ppr)}</w:pPr>{content}</w:p>"


def p_text(text: object, style: Style = PLAIN, **kw: Any) -> str:
    """Paragraph from plain text; direction follows the text's script."""
    s = str(text)
    kw.setdefault("rtl", _has_arabic(s))
    return para(runs(s, style), **kw)


def heading(text: str, level: int) -> str:
    """Heading 1 or 2 (styled in styles.xml)."""
    return para(runs(text), style_id=f"Heading{level}", after=120 if level == 2 else 160)


@dataclass(frozen=True, slots=True)
class Cell:
    """A table cell value with optional formatting."""

    text: object
    style: Style = PLAIN
    fill: str | None = None


CellLike = object  # Cell, or any value rendered with str()


def table(
    headers: Sequence[str], rows: Iterable[Sequence[CellLike]], weights: Sequence[float]
) -> str:
    """A right-to-left table spanning the text width."""
    total = sum(weights)
    widths = [int(TEXT_W * w / total) for w in weights]
    widths[-1] += TEXT_W - sum(widths)
    border = f'w:val="single" w:sz="4" w:space="0" w:color="{BORDER}"'
    out = [
        "<w:tbl><w:tblPr><w:bidiVisual/>",
        f'<w:tblW w:w="{TEXT_W}" w:type="dxa"/>',
        "<w:tblBorders>"
        + "".join(f"<w:{s} {border}/>" for s in ("top", "left", "bottom", "right"))
        + f"<w:insideH {border}/><w:insideV {border}/></w:tblBorders>",
        '<w:tblLayout w:type="fixed"/>',
        '<w:tblCellMar><w:top w:w="60" w:type="dxa"/><w:left w:w="100" w:type="dxa"/>'
        '<w:bottom w:w="60" w:type="dxa"/><w:right w:w="100" w:type="dxa"/></w:tblCellMar>',
        "</w:tblPr><w:tblGrid>",
        "".join(f'<w:gridCol w:w="{w}"/>' for w in widths),
        "</w:tblGrid>",
    ]
    head_style = Style(bold=True, size=18)
    out.append("<w:tr><w:trPr><w:cantSplit/><w:tblHeader/></w:trPr>")
    out += [
        _cell_xml(Cell(h, head_style, HEAD_FILL), w) for h, w in zip(headers, widths, strict=True)
    ]
    out.append("</w:tr>")
    for i, row in enumerate(rows):
        out.append("<w:tr><w:trPr><w:cantSplit/></w:trPr>")
        for value, w in zip(row, widths, strict=True):
            c = value if isinstance(value, Cell) else Cell("—" if value in (None, "") else value)
            if c.fill is None and i % 2:
                c = Cell(c.text, c.style, GREY)
            out.append(_cell_xml(c, w))
        out.append("</w:tr>")
    out.append("</w:tbl>")
    return "".join(out) + para("", after=120)


def _cell_xml(c: Cell, width: int) -> str:
    style = (
        c.style
        if c.style.size
        else Style(c.style.bold, c.style.italic, c.style.color, 18, c.style.mono)
    )
    shd = f'<w:shd w:val="clear" w:color="auto" w:fill="{c.fill}"/>' if c.fill else ""
    paras = "".join(p_text(line, style, after=0) for line in str(c.text).split("\n"))
    return f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>{shd}</w:tcPr>{paras}</w:tc>'


def sev_cell(sev: str) -> Cell:
    return Cell(SEVERITY_AR.get(sev, sev), Style(bold=True, color=SEVERITY_COLOR.get(sev)))


def status_cell(status: str) -> Cell:
    color = {
        "ok": "2E7D32",
        "completed": "2E7D32",
        "warning": "C55A11",
        "failed": "C00000",
        "critical": "C00000",
        "error": "C00000",
    }.get(status)
    return Cell(STATUS_AR.get(status, status), Style(color=color))


def mono(text: object, size: int = 18) -> Cell:
    return Cell(text, Style(mono=True, size=size))


def bullet(text: str) -> str:
    return p_text(text, num_id=1, after=60, rtl=True)


def numbered(text: str) -> str:
    return p_text(text, num_id=2, after=60, rtl=True)


def _fmt_time(iso: str) -> str:
    return iso.replace("T", " ").replace("+00:00", " UTC") if iso else "—"


def _short(text: str, limit: int = MAX_TITLE) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


# --------------------------------------------------------------------------- content builder


def _sort_reports(reports: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(reports, key=lambda r: COMMAND_ORDER.get(str(r.get("command")), 9))


def _all_findings(reports: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    return [f for r in reports for f in r.get("findings", [])]


def _sev_counts(findings: Sequence[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.get("severity", "info")] = out.get(f.get("severity", "info"), 0) + 1
    return dict(sorted(out.items(), key=lambda kv: SEVERITY_ORDER.get(kv[0], 9)))


def _group_findings(findings: Sequence[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        groups.setdefault(str(f.get("title", "?")), []).append(f)
    return sorted(
        groups.values(),
        key=lambda g: (SEVERITY_ORDER.get(g[0].get("severity", "info"), 9), -len(g)),
    )


def _locations(items: Sequence[dict[str, Any]]) -> str:
    by_file: dict[str, list[str]] = {}
    for it in items:
        target = str(it.get("target", ""))
        m = re.match(r"^(.*?):(\d+)$", target)
        file, line = (m.group(1), m.group(2)) if m else (target, None)
        by_file.setdefault(file, [])
        if line:
            by_file[file].append(line)
    parts = []
    for file, lines in by_file.items():
        if len(lines) > 4:
            parts.append(f"{file} ({len(lines)}×)")
        elif lines:
            parts.append(f"{file}:{','.join(lines)}")
        else:
            parts.append(file)
    return "\n".join(parts[:12]) + (f"\n… +{len(parts) - 12}" if len(parts) > 12 else "")


def _checks_table(report: dict[str, Any]) -> str:
    checks = report.get("checks", [])
    if not checks:
        return p_text("لا توجد فحوص مسجّلة.")
    rows = [
        [
            mono(c["name"]),
            status_cell(c["status"]),
            c.get("detail", "") + (" [ACTIVE]" if c.get("active") else ""),
        ]
        for c in checks
    ]
    return table(["الفحص", "الحالة", "التفاصيل"], rows, [2.6, 1.3, 6])


def _findings_block(findings: Sequence[dict[str, Any]], prefix: str) -> list[str]:
    out = [heading(f"{prefix}.1 ملخص النتائج حسب الخطورة", 2)]
    if not findings:
        out.append(p_text("لا توجد نتائج. غياب النتائج ليس دليلًا على الأمان."))
        return out
    out.append(
        table(
            ["الخطورة", "العدد"],
            [[sev_cell(s), n] for s, n in _sev_counts(findings).items()],
            [5, 5],
        )
    )
    out.append(heading(f"{prefix}.2 النتائج المجمّعة", 2))
    out.append(p_text("جُمعت النتائج المتماثلة في صف واحد مع عددها ومواقعها."))
    rows = []
    for g in _group_findings(findings):
        f = g[0]
        rows.append(
            [
                sev_cell(f.get("severity", "info")),
                _short(f.get("title", "")),
                len(g),
                mono(_locations(g), 16),
                _short(f.get("remediation", ""), 220),
            ]
        )
    out.append(
        table(["الخطورة", "النتيجة", "العدد", "المواقع", "المعالجة"], rows, [1.1, 3, 0.8, 2.6, 3])
    )
    serious = [f for f in findings if SEVERITY_ORDER.get(f.get("severity", "info"), 9) <= 2]
    if serious:
        out.append(heading(f"{prefix}.3 تفاصيل النتائج (متوسطة فأعلى)", 2))
        for f in serious[:MAX_DETAILED_FINDINGS]:
            sev = f.get("severity", "info")
            out.append(
                table(
                    ["الحقل", "القيمة"],
                    [
                        ["العنوان", f.get("title", "")],
                        [
                            "الخطورة / الثقة / النوع",
                            f"{SEVERITY_AR.get(sev, sev)} / "
                            f"{CONF_AR.get(f.get('confidence', ''), f.get('confidence', ''))} / "
                            f"{KIND_AR.get(f.get('kind', ''), f.get('kind', ''))}",
                        ],
                        ["الموقع", mono(f.get("target", ""))],
                        ["الدليل", "\n".join(map(str, f.get("evidence", []))) or "—"],
                        ["السبب", f.get("rationale", "")],
                        ["المعالجة", f.get("remediation", "")],
                    ],
                    [2.4, 7.6],
                )
            )
        if len(serious) > MAX_DETAILED_FINDINGS:
            out.append(
                p_text(f"… و{len(serious) - MAX_DETAILED_FINDINGS} نتيجة أخرى في تقرير JSON.")
            )
    return out


def _kv_table(items: Sequence[tuple[str, CellLike]]) -> str:
    return table(["البند", "القيمة"], [[k, v] for k, v in items], [3, 7])


def _network_section(r: dict[str, Any], n: int) -> list[str]:
    out = [p_text(f"وضع التشغيل: {MODE_AR.get(r.get('mode', ''), r.get('mode', ''))}.")]
    scope = r.get("scope") or {}
    if scope:
        out.append(heading(f"{n}.1 النطاق المعتمد", 2))
        out.append(
            _kv_table(
                [
                    ("الشبكات المسموح بها", ", ".join(scope.get("allowed_cidrs", [])) or "—"),
                    (
                        "أسماء المضيفين المسموح بها",
                        ", ".join(scope.get("allowed_hostnames", [])) or "—",
                    ),
                    ("الأهداف", ", ".join(map(str, scope.get("targets", []))) or "—"),
                    ("السماح بعناوين عامة", "نعم" if scope.get("allow_public_targets") else "لا"),
                    ("الحد الأقصى للمضيفين", scope.get("max_hosts")),
                    ("معرّف النطاق (scope_id)", mono(scope.get("scope_id", "—"))),
                    ("ملاحظات", "\n".join(scope.get("notes", [])) or "—"),
                ]
            )
        )
    out.append(heading(f"{n}.2 الفحوص", 2))
    out.append(_checks_table(r))
    hosts = r.get("hosts", [])
    out.append(heading(f"{n}.3 المضيفون", 2))
    if hosts:
        rows = []
        for h in hosts:
            services = "\n".join(
                f"{s['port']}/{s['protocol']} {s['state']} "
                + " ".join(x for x in (s.get("name"), s.get("product"), s.get("version")) if x)
                for s in h.get("services", [])
            )
            os_guess = h.get("os_guesses") or []
            os_text = (
                f"{os_guess[0]['name']} ({os_guess[0]['accuracy_percent']}%, تقدير)"
                if os_guess
                else "—"
            )
            rows.append(
                [mono(h["address"]), h.get("status", ""), mono(services or "—", 16), os_text]
            )
        out.append(
            table(["العنوان", "الحالة", "الخدمات", "نظام التشغيل"], rows, [2, 1.2, 4.6, 2.2])
        )
    else:
        out.append(p_text("لم يُرصد أي مضيف (أو لم يُنفَّذ فحص فعلي)."))
    out += _findings_block(r.get("findings", []), f"{n}.4")
    paths = r.get("attack_paths", [])
    if paths:
        out.append(heading(f"{n}.5 مسارات الهجوم المحتملة (شرح فقط، لم يُجرَّب شيء)", 2))
        for path in paths:
            out.append(
                p_text(f"{path.get('target', '')}: " + " ← ".join(path.get("steps", [])), rtl=True)
            )
    nxt = (r.get("sections") or {}).get("next_step", {}).get("to_run_actively")
    if nxt:
        out.append(p_text("الخطوة التالية للتشغيل النشط:", Style(bold=True)))
        out.append(p_text(nxt, Style(mono=True, size=18)))
    return out


def _project_section(r: dict[str, Any], n: int) -> list[str]:
    out: list[str] = []
    sec = (r.get("sections") or {}).get("project")
    if sec:
        out.append(heading(f"{n}.1 نظرة عامة", 2))
        out.append(
            _kv_table(
                [
                    ("المسار", mono(sec.get("root", ""))),
                    ("عدد الملفات المفحوصة", sec.get("file_count")),
                    (
                        "اللغات",
                        ", ".join(f"{k}: {v}" for k, v in sec.get("languages", {}).items()) or "—",
                    ),
                    ("ملفات التبعيات", ", ".join(sec.get("manifests", [])) or "—"),
                    ("ملفات القفل (Lockfiles)", ", ".join(sec.get("lockfiles", [])) or "لا يوجد"),
                    ("عدد التبعيات", len(sec.get("dependencies", []))),
                    (
                        "البنية المستنتجة",
                        "\n".join(
                            f"{a['element']} ({CONF_AR.get(a['confidence'], a['confidence'])})"
                            for a in sec.get("architecture", [])
                        )
                        or "—",
                    ),
                ]
            )
        )
    elif r.get("scope", {}).get("project_path"):
        out.append(p_text(r["scope"]["project_path"], Style(mono=True, size=18)))
    out.append(heading(f"{n}.2 الفحوص المنفّذة", 2))
    out.append(_checks_table(r))
    out += _findings_block(r.get("findings", []), f"{n}.3")
    return out


def _hardware_section(r: dict[str, Any], n: int) -> list[str]:
    out: list[str] = []
    sec = (r.get("sections") or {}).get("hardware")
    if sec:
        summary = sec.get("summary", {})
        overall = summary.get("overall", "")
        out.append(
            para(
                runs("الحالة العامة: ")
                + runs(STATUS_AR.get(overall, overall), Style(bold=True))
                + runs(f" — {summary.get('explanation', '')}"),
            )
        )
        rows = []
        for m in sec.get("measurements", []):
            value = "—" if m.get("value") is None else f"{m['value']} {m.get('unit', '')}".strip()
            rows.append(
                [
                    mono(m["name"]),
                    status_cell(m["status"]),
                    value,
                    m.get("source", ""),
                    m.get("note", ""),
                ]
            )
        out.append(
            table(["المؤشر", "الحالة", "القيمة", "المصدر", "ملاحظة"], rows, [2, 1.2, 1.3, 1.8, 3.7])
        )
    out.append(heading(f"{n}.1 الفحوص", 2))
    out.append(_checks_table(r))
    if r.get("findings"):
        out += _findings_block(r["findings"], f"{n}.2")
    return out


def _generic_section(r: dict[str, Any], n: int) -> list[str]:
    return [
        heading(f"{n}.1 الفحوص", 2),
        _checks_table(r),
        *_findings_block(r.get("findings", []), f"{n}.2"),
    ]


SECTION_BUILDERS = {
    "network": _network_section,
    "project": _project_section,
    "hardware": _hardware_section,
}


def _tools(reports: Sequence[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    for r in reports:
        for name, info in (r.get("tool_versions") or {}).items():
            if isinstance(info, dict) and (name not in tools or info.get("available")):
                tools[name] = info
    return tools


def recommendations(reports: Sequence[dict[str, Any]]) -> list[str]:
    """Data-driven recommendations derived only from what the reports contain."""
    recs: list[str] = []
    findings = _all_findings(reports)
    counts = _sev_counts(findings)
    urgent = counts.get("critical", 0) + counts.get("high", 0)
    if urgent:
        recs.append(f"عالج أولًا النتائج الحرجة والعالية ({urgent}) الواردة في جداول النتائج.")
    for group in _group_findings(findings):
        f = group[0]
        if SEVERITY_ORDER.get(f.get("severity", "info"), 9) <= 2 and len(recs) < 8:
            recs.append(
                f"«{_short(f.get('title', ''), 90)}» ({len(group)}): "
                f"{_short(f.get('remediation', ''), 160)}"
            )
    for r in reports:
        hw = (r.get("sections") or {}).get("hardware") or {}
        for m in hw.get("measurements", []):
            if m.get("status") in ("warning", "critical") and str(m.get("name", "")).startswith(
                "disk_usage"
            ):
                drive = str(m["name"]).split(":", 1)[-1]
                recs.append(
                    f"حرّر مساحة على {drive} (مستخدم {m.get('value')}%)؛ امتلاء القرص قد يعطّل "
                    "التحديثات وكتابة السجلات."
                )
            elif m.get("status") in ("warning", "critical"):
                recs.append(f"راجع مؤشر العتاد {m.get('name')}: {m.get('note', '')}")
        if hw.get("summary", {}).get("overall") == "no_data":
            recs.append(
                "صحة العتاد غير معروفة: ثبّت smartmontools وشغّل «secassess hardware --smart» "
                "بصلاحيات المسؤول، أو استخدم أدوات الشركة المصنّعة لقراءة الحرارة."
            )
        nxt = (r.get("sections") or {}).get("next_step", {}).get("to_run_actively")
        if r.get("command") == "network" and r.get("mode") == "dry-run" and nxt:
            recs.append(f"فحص الشبكة كان تجريبيًا فقط: {nxt}")
    for name, info in _tools(reports).items():
        if name != "advisory_sources" and not info.get("available"):
            recs.append(f"ثبّت {name} لتفعيل: {info.get('purpose', name)}.")
    low = counts.get("low", 0)
    if low:
        recs.append(
            f"راجع النتائج المنخفضة ({low}) واستبعد المطابقات المتوقعة "
            "(مثل ملفات الاختبار) من الفحوص القادمة."
        )
    return list(dict.fromkeys(recs))


def build_document_xml(reports: Sequence[dict[str, Any]]) -> str:
    """The ``word/document.xml`` body for the given reports."""
    reports = _sort_reports(reports)
    first = reports[0]
    env = first.get("environment", {})
    tool = first.get("tool", {})
    started = min((r.get("started_at", "") for r in reports if r.get("started_at")), default="")
    body: list[str] = []

    body.append(
        para(
            runs("تقرير الفحص الأمني الشامل", Style(bold=True, color=NAVY, size=44)),
            align="center",
            before=480,
            after=120,
        )
    )
    body.append(
        para(
            runs(
                f"secassess {tool.get('version', '')}  •  {env.get('platform', '')} "
                f"{env.get('platform_release', '')}  •  Python {env.get('python', '')}",
                Style(color="595959", size=22),
            ),
            rtl=False,
            align="center",
            after=360,
            border_bottom=True,
        )
    )
    info: list[tuple[str, CellLike]] = [
        ("تاريخ الفحص", _fmt_time(started)),
        ("نظام التشغيل", f"{env.get('platform', '')} {env.get('platform_release', '')}"),
        ("الأوامر المشمولة", ", ".join(str(r.get("command")) for r in reports)),
        (
            "معرّفات التشغيل (Run IDs)",
            mono("\n".join(f"{r.get('command')}: {r.get('run_id')}" for r in reports)),
        ),
    ]
    for r in reports:
        if r.get("scope", {}).get("scope_id"):
            info.append(("معرّف النطاق (scope_id)", mono(r["scope"]["scope_id"])))
        if r.get("scope", {}).get("project_path"):
            info.append(("مسار المشروع المفحوص", mono(r["scope"]["project_path"])))
    body.append(_kv_table(info))

    # 1. executive summary
    findings = _all_findings(reports)
    counts = _sev_counts(findings)
    body.append(heading("1. الملخص التنفيذي", 1))
    body.append(
        p_text(
            f"شمل الفحص {len(reports)} محور/محاور. إجمالي النتائج: {len(findings)}"
            + (
                " (" + "، ".join(f"{SEVERITY_AR.get(s, s)}: {c}" for s, c in counts.items()) + ")"
                if counts
                else ""
            )
            + "."
        )
    )
    rows = []
    for r in reports:
        st = r.get("summary", {}).get("checks_by_status", {})
        rows.append(
            [
                COMMAND_AR.get(r.get("command", ""), r.get("command", "")),
                MODE_AR.get(r.get("mode", ""), r.get("mode", "")),
                st.get("completed", 0),
                st.get("skipped", 0),
                st.get("failed", 0),
                len(r.get("findings", [])),
            ]
        )
    body.append(
        table(
            ["المحور", "الوضع", "مكتملة", "متخطاة", "فاشلة", "النتائج"],
            rows,
            [2.4, 2.6, 1.1, 1.1, 1.1, 1.1],
        )
    )
    for r in reports:
        hw = (r.get("sections") or {}).get("hardware")
        if hw:
            overall = hw.get("summary", {}).get("overall", "")
            body.append(
                bullet(
                    f"صحة العتاد: {STATUS_AR.get(overall, overall)} — "
                    f"{hw.get('summary', {}).get('explanation', '')}"
                )
            )
        if r.get("command") == "network" and r.get("mode") == "dry-run":
            body.append(bullet("الشبكة: تشغيل تجريبي فقط؛ لم تُرسَل أي حزم."))
        for c in r.get("skipped_or_failed_checks", []):
            if c.get("status") == "failed":
                body.append(bullet(f"فحص فاشل: {c['name']} — {c.get('detail', '')}"))
        for e in r.get("errors", []):
            body.append(bullet(f"خطأ: {e}"))

    # 2. tools
    tools = _tools(reports)
    section_no = 2
    if tools:
        body.append(heading("2. الأدوات المستخدمة", 1))
        trows = []
        for name, tinfo in tools.items():
            ok = bool(tinfo.get("available"))
            detail = " ".join(
                str(x) for x in (tinfo.get("version"), tinfo.get("path"), tinfo.get("note")) if x
            )
            trows.append(
                [
                    mono(name),
                    Cell(
                        "متاحة" if ok else "غير متاحة",
                        Style(bold=True, color="2E7D32" if ok else "C00000"),
                    ),
                    detail or "—",
                ]
            )
        body.append(table(["الأداة", "الحالة", "التفاصيل"], trows, [1.8, 1.4, 6.6]))
        section_no = 3

    # per-command sections
    for r in reports:
        cmd = str(r.get("command", ""))
        body.append(heading(f"{section_no}. {COMMAND_AR.get(cmd, cmd)}", 1))
        body += SECTION_BUILDERS.get(cmd, _generic_section)(r, section_no)
        section_no += 1

    # recommendations
    recs = recommendations(reports)
    body.append(heading(f"{section_no}. التوصيات", 1))
    body += [numbered(x) for x in recs] if recs else [p_text("لا توجد توصيات آلية.")]
    section_no += 1

    # methodology & limitations
    body.append(heading(f"{section_no}. المنهجية والقيود", 1))
    methodology = list(dict.fromkeys(m for r in reports for m in r.get("methodology", [])))
    limitations = list(dict.fromkeys(m for r in reports for m in r.get("limitations", [])))
    if methodology:
        body.append(heading(f"{section_no}.1 المنهجية", 2))
        body += [p_text(m, after=40) for m in methodology]
    if limitations:
        body.append(heading(f"{section_no}.2 القيود", 2))
        body += [p_text(m, after=40) for m in limitations]
    body.append(
        p_text(
            "غياب النتائج ليس دليلًا على الأمان. "
            "نتائج التحليل الثابت ومطابقات الإصدارات تحتاج مراجعة بشرية.",
            Style(italic=True, color="595959"),
            before=160,
        )
    )

    sect = (
        '<w:sectPr><w:headerReference w:type="default" r:id="rIdHeader"/>'
        '<w:footerReference w:type="default" r:id="rIdFooter"/>'
        f'<w:pgSz w:w="{PAGE_W}" w:h="{PAGE_H}"/>'
        f'<w:pgMar w:top="{MARGIN}" w:right="{MARGIN}" w:bottom="{MARGIN}" w:left="{MARGIN}" '
        'w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f"<w:document {_NS}><w:body>{''.join(body)}{sect}</w:body></w:document>"
    )


# --------------------------------------------------------------------------- package parts

_NS = (
    'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
    'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
)
_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/'
    'vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.wordprocessingml.document.main+xml"/>'
    '<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.wordprocessingml.styles+xml"/>'
    '<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.wordprocessingml.numbering+xml"/>'
    '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.wordprocessingml.header+xml"/>'
    '<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.wordprocessingml.footer+xml"/>'
    '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-'
    'package.core-properties+xml"/>'
    '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-'
    'officedocument.extended-properties+xml"/>'
    "</Types>"
)

ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    f'<Relationship Id="rId1" Type="{_REL_NS}/officeDocument" Target="word/document.xml"/>'
    '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/'
    'metadata/core-properties" Target="docProps/core.xml"/>'
    f'<Relationship Id="rId3" Type="{_REL_NS}/extended-properties" Target="docProps/app.xml"/>'
    "</Relationships>"
)

DOC_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    f'<Relationship Id="rIdStyles" Type="{_REL_NS}/styles" Target="styles.xml"/>'
    f'<Relationship Id="rIdNumbering" Type="{_REL_NS}/numbering" Target="numbering.xml"/>'
    f'<Relationship Id="rIdHeader" Type="{_REL_NS}/header" Target="header1.xml"/>'
    f'<Relationship Id="rIdFooter" Type="{_REL_NS}/footer" Target="footer1.xml"/>'
    "</Relationships>"
)


def _heading_style(
    sid: str, name: str, size: int, color: str, before: int, after: int, lvl: int
) -> str:
    return (
        f'<w:style w:type="paragraph" w:styleId="{sid}"><w:name w:val="{name}"/>'
        '<w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>'
        "<w:pPr><w:keepNext/><w:keepLines/><w:bidi/>"
        f'<w:spacing w:before="{before}" w:after="{after}"/>'
        f'<w:outlineLvl w:val="{lvl}"/></w:pPr>'
        f'<w:rPr><w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}" w:cs="{FONT}"/><w:b/><w:bCs/>'
        f'<w:color w:val="{color}"/><w:sz w:val="{size}"/><w:szCs w:val="{size}"/>'
        "</w:rPr></w:style>"
    )


STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    "<w:docDefaults><w:rPrDefault><w:rPr>"
    f'<w:rFonts w:ascii="{FONT}" w:hAnsi="{FONT}" w:cs="{FONT}" w:eastAsia="{FONT}"/>'
    '<w:sz w:val="22"/><w:szCs w:val="22"/><w:lang w:val="en-US" w:bidi="ar-SA"/>'
    "</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr>"
    '<w:spacing w:after="100" w:line="264" w:lineRule="auto"/>'
    "</w:pPr></w:pPrDefault></w:docDefaults>"
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
    '<w:name w:val="Normal"/><w:qFormat/></w:style>'
    + _heading_style("Heading1", "heading 1", 32, NAVY, 360, 160, 0)
    + _heading_style("Heading2", "heading 2", 26, BLUE, 240, 120, 1)
    + '<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/>'
    '<w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/>'
    '<w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/>'
    '<w:right w:w="108" w:type="dxa"/>'
    "</w:tblCellMar></w:tblPr></w:style>"
    "</w:styles>"
)


def _abstract_num(aid: int, fmt: str, text: str) -> str:
    return (
        f'<w:abstractNum w:abstractNumId="{aid}"><w:multiLevelType w:val="singleLevel"/>'
        f'<w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="{fmt}"/>'
        f'<w:lvlText w:val="{text}"/><w:lvlJc w:val="left"/>'
        '<w:pPr><w:bidi/><w:ind w:left="540" w:hanging="300"/></w:pPr></w:lvl></w:abstractNum>'
    )


NUMBERING = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    + _abstract_num(0, "bullet", "•")
    + _abstract_num(1, "decimal", "%1.")
    + '<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>'
    '<w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>'
    "</w:numbering>"
)


def _header(text: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f"<w:hdr {_NS}>"
        + para(runs(text, Style(color="808080", size=16)), rtl=False, after=0)
        + "</w:hdr>"
    )


def _field(instr: str) -> str:
    style = Style(color="808080", size=16)
    return (
        '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
        f'<w:r><w:instrText xml:space="preserve"> {instr} </w:instrText></w:r>'
        '<w:r><w:fldChar w:fldCharType="separate"/></w:r>'
        + _run_xml("1", style, rtl=False)
        + '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
    )


FOOTER = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    f"<w:ftr {_NS}>"
    + para(
        _field("PAGE")
        + _run_xml(" / ", Style(color="808080", size=16), rtl=False)
        + _field("NUMPAGES"),
        rtl=False,
        align="center",
        after=0,
    )
    + "</w:ftr>"
)


def _core(created: str) -> str:
    stamp = created[:19] + "Z" if created else "2000-01-01T00:00:00Z"
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        "<cp:coreProperties "
        'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        "<dc:title>تقرير الفحص الأمني الشامل</dc:title><dc:creator>secassess</dc:creator>"
        f'<dcterms:created xsi:type="dcterms:W3CDTF">{_x(stamp)}</dcterms:created>'
        "</cp:coreProperties>"
    )


APP = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
    "<Application>secassess</Application></Properties>"
)


def write_docx(reports: Sequence[dict[str, Any]], path: Path) -> None:
    """Write one Word document covering ``reports`` (report dicts; redacted again here)."""
    if not reports:
        raise ValueError("at least one report is required")
    clean: list[dict[str, Any]] = [redact(dict(r)) for r in reports]
    started = min((str(r.get("started_at", "")) for r in clean if r.get("started_at")), default="")
    parts = {
        "[Content_Types].xml": CONTENT_TYPES,
        "_rels/.rels": ROOT_RELS,
        "docProps/core.xml": _core(started),
        "docProps/app.xml": APP,
        "word/_rels/document.xml.rels": DOC_RELS,
        "word/document.xml": build_document_xml(clean),
        "word/styles.xml": STYLES,
        "word/numbering.xml": NUMBERING,
        "word/header1.xml": _header(f"secassess  |  {_fmt_time(started)}"),
        "word/footer1.xml": FOOTER,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh, zipfile.ZipFile(fh, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in parts.items():
            zf.writestr(name, data.encode("utf-8"))
