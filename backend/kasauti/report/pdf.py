"""Per-device PDF report (PLAN §15.1; TODO M1.13, growing into M2.70). ReportLab, BSD licence.

Sections follow §15.1: cover and device profile, executive summary (Compliance % *and*
Coverage %), control matrix, detailed findings (FAIL first, with expected vs actual and the
evidence lines), remediation (a five-step, re-audit verified fix for every failed check), policy
analysis, assurance and transparency, appendix.

Security: every string that came from a configuration is escaped before it reaches ReportLab,
whose Paragraph markup would otherwise interpret ``<a href=…>``, ``<img>`` or ``<font>`` in a
crafted config line. Evidence is already masked by the pipeline.

The report is unsigned until M5 (PAdES via pyHanko, TODO M5.14) and says so on its cover.
Output is byte-reproducible (ReportLab's invariant mode), given the same audit and date.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from io import BytesIO
from typing import Any

# Output escaping for ReportLab markup; nothing is parsed with it.
from xml.sax.saxutils import escape  # nosec B406

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from kasauti.audit import AuditResult, effective_severity
from kasauti.remediation.model import Fix, Proof
from kasauti.rules.evaluate import display
from kasauti.rules.model import Finding, Severity, Status

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
_STATUS_ORDER = {Status.FAIL: 0, Status.REVIEW: 1, Status.PASS: 2, Status.NOT_APPLICABLE: 3}
# The web UI's palette (frontend/src/index.css): verdicts in jade, vermilion and indigo; basalt and
# brass for the brand only.
_STATUS_COLOUR = {
    Status.PASS: colors.HexColor("#177a59"),
    Status.FAIL: colors.HexColor("#c3303d"),
    Status.REVIEW: colors.HexColor("#5850c4"),
    Status.NOT_APPLICABLE: colors.HexColor("#7b8086"),
}
_INK = colors.HexColor("#16191c")
_MUTED = colors.HexColor("#5c6167")
_RULE = colors.HexColor("#e3e0d8")
_HEAD_BG = colors.HexColor("#f4f3ef")
_BASALT = colors.HexColor("#13171a")
_ON_BASALT = colors.HexColor("#b9bec3")
_BRASS = colors.HexColor("#c8972f")

# The Kasauti mark (frontend/src/components/Brand.tsx), on a 64-unit square: the touchstone and
# the streak rubbed across it.
_STONE = (
    "M13.6 7.4C23.4 2.9 43.1 2.6 53.2 8.1C60.1 11.9 61.6 22.6 61.2 34.8C60.8 48.9 54.9 58.6 39.6 "
    "60.3C26.9 61.7 11.8 60.4 6.1 51.9C2.2 46.1 2.1 29.6 3.6 21.4C4.6 15.3 8.2 9.9 13.6 7.4Z"
)
_STREAK = (
    "M17.3 32.4C18.3 31.6 19.5 31.8 20.4 32.6L27.2 38.4L45.9 18.9C46.9 17.9 48.5 18 49.3 19.1C49.9 "
    "19.9 49.8 21 49.2 21.8L30.4 46.4C29.1 48.1 26.6 48.3 25 46.8L16.8 36.1C16 35 16.2 33.3 17.3 "
    "32.4Z"
)
_PATH_TOKEN = re.compile(r"[MCLZ]|-?\d*\.?\d+")


def render_pdf(result: AuditResult, rules_by_id: dict[str, Any], *, generated: str) -> bytes:
    """Render the report. ``generated`` is the report date (YYYY-MM-DD), passed in so that
    the same audit on the same date renders to identical bytes."""
    buf = BytesIO()
    hostname = result.identity["hostname"].value or result.input.file
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=24 * mm,
        bottomMargin=18 * mm,
        title=f"Kasauti compliance report: {_safe(hostname)}",
        author="Kasauti",
        subject=f"Audit {result.audit_id}",
        creator=f"Kasauti {result.kb.kasauti_version}",
        invariant=1,
    )
    s = _Styles()
    story: list[Any] = []
    story += _cover(result, s, generated)
    story += _summary(result, s)
    story += _control_matrix(result, s)
    story += _findings(result, rules_by_id, s)
    story += _remediation(result, s)
    story += _policy(s)
    story += _assurance(result, s)
    story += _appendix(result, s)

    def footer(canvas: Any, _doc: Any) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(_MUTED)
        canvas.drawString(
            18 * mm, 10 * mm, f"Kasauti | {_safe(hostname)} | audit {result.audit_id} | unsigned"
        )
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"page {canvas.getPageNumber()}")
        canvas.restoreState()

    def first(canvas: Any, doc_: Any) -> None:
        _cover_band(canvas, generated)
        footer(canvas, doc_)

    def later(canvas: Any, doc_: Any) -> None:
        _running_head(canvas, _safe(hostname))
        footer(canvas, doc_)

    doc.build(story, onFirstPage=first, onLaterPages=later)
    return buf.getvalue()


# --- brand ---------------------------------------------------------------------------------------


def _mark(canvas: Any, x: float, y: float, size: float) -> None:
    """Draw the Kasauti mark with its lower-left corner at (x, y), ``size`` points square."""
    for d, colour in ((_STONE, colors.HexColor("#1f2428")), (_STREAK, colors.HexColor("#d9a93f"))):
        canvas.setFillColor(colour)
        canvas.drawPath(_svg_path(canvas, d, x, y, size / 64), stroke=0, fill=1)


def _svg_path(canvas: Any, d: str, x: float, y: float, scale: float) -> Any:
    """An absolute M/L/C/Z SVG path as a ReportLab path, flipped so SVG's y runs up the page."""
    path = canvas.beginPath()
    tokens = _PATH_TOKEN.findall(d)

    def point(i: int) -> tuple[float, float]:
        return x + float(tokens[i]) * scale, y + (64 - float(tokens[i + 1])) * scale

    i = 0
    while i < len(tokens):
        op = tokens[i]
        if op == "M":
            path.moveTo(*point(i + 1))
            i += 3
        elif op == "L":
            path.lineTo(*point(i + 1))
            i += 3
        elif op == "C":
            path.curveTo(*point(i + 1), *point(i + 3), *point(i + 5))
            i += 7
        elif op == "Z":
            path.close()
            i += 1
        else:
            raise ValueError(f"unsupported path token {op!r}")
    return path


def _cover_band(canvas: Any, generated: str) -> None:
    """The first page's basalt band: the mark, the name and what the document is."""
    width, height = A4
    band = 16 * mm
    canvas.saveState()
    canvas.setFillColor(_BASALT)
    canvas.rect(0, height - band, width, band, stroke=0, fill=1)
    canvas.setFillColor(_BRASS)
    canvas.rect(0, height - band - 0.8, width, 0.8, stroke=0, fill=1)
    _mark(canvas, 18 * mm, height - band + 3.5 * mm, 9 * mm)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 13)
    canvas.drawString(30 * mm, height - band + 6.2 * mm, "Kasauti")
    canvas.setFillColor(_ON_BASALT)
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(
        width - 18 * mm, height - band + 6.6 * mm, f"Compliance report | {generated}"
    )
    canvas.restoreState()


def _running_head(canvas: Any, host: str) -> None:
    """Later pages: the mark and the device, over a brass hairline."""
    width, height = A4
    canvas.saveState()
    _mark(canvas, 18 * mm, height - 14 * mm, 5 * mm)
    canvas.setFillColor(_MUTED)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(25 * mm, height - 12.4 * mm, "Kasauti")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(width - 18 * mm, height - 12.4 * mm, host)
    canvas.setStrokeColor(_BRASS)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, height - 16 * mm, width - 18 * mm, height - 16 * mm)
    canvas.restoreState()


# --- styles and helpers --------------------------------------------------------------------------


class _Styles:
    def __init__(self) -> None:
        base = getSampleStyleSheet()
        self.title = ParagraphStyle(
            "t",
            parent=base["Title"],
            alignment=TA_LEFT,
            fontSize=20,
            leading=24,
            textColor=_INK,
            spaceAfter=4,
        )
        self.h1 = ParagraphStyle(
            "h1",
            parent=base["Heading1"],
            fontSize=14,
            leading=18,
            textColor=_INK,
            spaceBefore=10,
            spaceAfter=6,
        )
        self.h2 = ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontSize=11,
            leading=14,
            textColor=_INK,
            spaceBefore=8,
            spaceAfter=3,
        )
        self.body = ParagraphStyle(
            "b", parent=base["BodyText"], fontSize=9, leading=12, textColor=_INK
        )
        self.small = ParagraphStyle("s", parent=self.body, fontSize=8, leading=10, textColor=_MUTED)
        self.cell = ParagraphStyle("c", parent=self.body, fontSize=8, leading=10)
        self.code = ParagraphStyle(
            "code", parent=self.cell, fontName="Courier", fontSize=7.5, leading=9.5
        )
        self.big = ParagraphStyle("big", parent=self.body, fontSize=22, leading=26)


# Typography the built-in (cp1252) fonts can't draw, spelled out rather than shown as "?".
_ASCII = str.maketrans({"→": "->", "←": "<-", "≥": ">=", "≤": "<=", "∋": "contains", "≠": "!="})


def _safe(text: object) -> str:
    """Escape for ReportLab markup and keep to characters the built-in fonts can draw."""
    raw = str(text).translate(_ASCII)
    printable = "".join(
        ch if ch in "\t\n" or (ch.isprintable() and _encodable(ch)) else "?" for ch in raw
    )
    return escape(printable)


def _encodable(ch: str) -> bool:
    try:
        ch.encode("cp1252")
    except UnicodeEncodeError:
        return False
    return True


def _p(text: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_safe(text), style)


def _status(status: Status, style: ParagraphStyle) -> Paragraph:
    colour = _STATUS_COLOUR[status].hexval()[2:]
    return Paragraph(f'<font color="#{colour}"><b>{escape(status.value)}</b></font>', style)


def _table(rows: list[list[Any]], widths: Sequence[float], *, header: bool = True) -> Table:
    table = Table(rows, colWidths=list(widths), repeatRows=1 if header else 0)
    commands: list[Any] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, _RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]
    if header:
        commands.append(("BACKGROUND", (0, 0), (-1, 0), _HEAD_BG))
    table.setStyle(TableStyle(commands))
    return table


def _family(r: AuditResult) -> str:
    """``brace``, or ``brace (from set_path)`` for a Junos ``display set`` export."""
    if r.input.rebuilt_from is None:
        return r.input.shape_family
    return f"{r.input.shape_family} (from {r.input.rebuilt_from})"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}%"


# --- 1. cover and device profile -----------------------------------------------------------------


def _cover(r: AuditResult, s: _Styles, generated: str) -> list[Any]:
    host = r.identity["hostname"].value or r.input.file
    out: list[Any] = [
        _p("Compliance report", s.title),
        _p(f"{host}: security configuration audit", s.h2),
        Spacer(1, 4 * mm),
        _p("Device profile", s.h1),
    ]
    rows = [[_p("Field", s.cell), _p("Value", s.cell), _p("Source", s.cell)]]
    labels = {
        "hostname": "Hostname",
        "vendor": "Vendor",
        "os_version": "OS version",
        "model": "Model",
        "serial": "Serial",
        "hardware": "Hardware",
    }
    for field, label in labels.items():
        item = r.identity[field]
        rows.append(
            [
                _p(label, s.cell),
                _p(item.value or "(not available)", s.cell),
                _rich(item.source, s.small),
            ]
        )
    out.append(_table(rows, (28 * mm, 45 * mm, 101 * mm)))
    if r.inventory:
        out += [Spacer(1, 3 * mm), _p("Hardware inventory", s.h2)]
        parts = [[_p(h, s.cell) for h in ("Component", "Part", "Serial", "Description", "Source")]]
        parts += [
            [
                _p(i.name, s.cell),
                _p(" ".join(filter(None, (i.part, i.version))) or "-", s.cell),
                _p(i.serial, s.cell),
                _p(i.description or "-", s.cell),
                _rich(i.source, s.small),
            ]
            for i in r.inventory
        ]
        out.append(_table(parts, (32 * mm, 30 * mm, 30 * mm, 42 * mm, 40 * mm)))
    out += [Spacer(1, 4 * mm), _p("Audit", s.h1)]
    meta = [
        ("Configuration file", r.input.file),
        ("SHA-256", r.input.sha256),
        ("Shape family / encoding", f"{_family(r)} / {r.input.encoding}"),
        *(
            [
                (
                    "Companion files",
                    "; ".join(
                        f"{c.file} ({c.command if c.used else 'not used'})" for c in r.companions
                    ),
                )
            ]
            if r.companions
            else []
        ),
        ("Vendor pack", f"{r.kb.vendor_pack} (chosen by {r.detection.chosen_by})"),
        ("Audit ID", r.audit_id),
        ("Report date", generated),
        ("Kasauti version", r.kb.kasauti_version),
        ("Knowledge base", r.kb.kb_version[:16]),
        ("Rule set", r.kb.ruleset_version[:16]),
        (
            "Frameworks",
            ", ".join(f"{sc.title} ({r.kb.frameworks.get(sc.framework, '?')})" for sc in r.scores),
        ),
        ("Signature", "none: this report is not digitally signed"),
    ]
    out.append(
        _table(
            [[_p(k, s.cell), _p(v, s.code if k == "SHA-256" else s.cell)] for k, v in meta],
            (40 * mm, 134 * mm),
            header=False,
        )
    )
    if r.warnings:
        out += [Spacer(1, 3 * mm), _p("Warnings", s.h2)]
        out += [_p(f"- {w}", s.body) for w in r.warnings]
    out.append(PageBreak())
    return out


# --- 2. executive summary ------------------------------------------------------------------------


def _summary(r: AuditResult, s: _Styles) -> list[Any]:
    out: list[Any] = [_p("Executive summary", s.h1)]
    for sc in r.scores:
        out.append(_p(sc.title, s.h2))
        cells = [
            [_p(_pct(sc.compliance_pct), s.big), _p(_pct(sc.coverage_pct), s.big)],
            [
                _p("Compliance: PASS / (PASS + FAIL)", s.small),
                _p("Coverage: rules we could judge / applicable rules", s.small),
            ],
        ]
        out.append(_table(cells, (87 * mm, 87 * mm), header=False))
        out.append(
            _p(
                f"{sc.passed} pass, {sc.failed} fail, {sc.review} need review, "
                f"{sc.not_applicable} not applicable. Read the two numbers together: a high "
                f"compliance score on low coverage means most rules could not be judged.",
                s.body,
            )
        )
        if sc.benchmarks:
            out.append(_p("Benchmarks applied: " + "; ".join(sc.benchmarks) + ".", s.small))
        if sc.framework == "disa_stig" and not sc.note:
            out.append(
                _p(
                    "A rule that checks only part of a STIG requirement can fail it but not "
                    "meet it, so its PASS counts as needing review here: the coverage shows how "
                    "much of the STIG this configuration settles.",
                    s.small,
                )
            )
        if sc.note:
            out.append(_p(sc.note[0].upper() + sc.note[1:] + ".", s.small))
    effective = effective_severity(r)
    checks = Counter(effective.values())
    findings = Counter(f.severity for f in r.findings if f.status is Status.FAIL)
    out += [Spacer(1, 3 * mm), _p("Failures by severity", s.h2)]
    out.append(
        _table(
            [
                [_p("", s.cell), *(_p(sev.value.capitalize(), s.cell) for sev in Severity)],
                [
                    _p("Failed checks", s.cell),
                    *(_p(str(checks.get(sev, 0)), s.cell) for sev in Severity),
                ],
                [
                    _p("Failed findings", s.cell),
                    *(_p(str(findings.get(sev, 0)), s.cell) for sev in Severity),
                ],
            ],
            (34 * mm, *(35 * mm,) * 4),
        )
    )
    out.append(
        _p(
            "A check counts once, at the severity of its worst finding; a finding is one object "
            "(an interface, a user, a line) that fails it. Exposure, such as a service reachable "
            "from an untrusted interface, can raise a finding above the rule's own severity.",
            s.small,
        )
    )
    out += [Spacer(1, 3 * mm), _p("Top risks", s.h2)]
    top = sorted(
        (x for x in r.rules if x.status is Status.FAIL),
        key=lambda x: (_SEVERITY_ORDER[effective[x.rule_id]], x.rule_id),
    )[:5]
    if not top:
        out.append(_p("No rule failed.", s.body))
    for i, rule in enumerate(top, 1):
        sev = effective[rule.rule_id]
        out.append(_p(f"{i}. [{sev.value}] {rule.title} ({rule.rule_id})", s.body))
    out.append(PageBreak())
    return out


# --- 3. control matrix ---------------------------------------------------------------------------


_MATRIX = {
    "nist_800_53r5": ("NIST SP 800-53 Rev. 5 controls", "Control"),
    "disa_stig": ("DISA STIG requirements", "STIG ID"),
    "iso_27001_2022": ("ISO/IEC 27001:2022 Annex A controls", "Control"),
}
_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def _control_matrix(r: AuditResult, s: _Styles) -> list[Any]:
    others = [f for f in r.frameworks if f != "nist_800_53r5"]
    out: list[Any] = [
        _p("Control matrix", s.h1),
        _p(
            "Each rule, the framework controls it gives evidence for on this device, and its "
            "status. Then, for each selected framework, every control those rules touch.",
            s.small,
        ),
        Spacer(1, 2 * mm),
    ]
    head = ("Rule", "Title", "NIST SP 800-53 r5", "Severity", "Status")
    if others:
        head = ("Rule", "Title", "NIST SP 800-53 r5", "Other frameworks", "Status")
    rows = [[_p(h, s.cell) for h in head]]
    for rule in sorted(r.rules, key=lambda x: (_STATUS_ORDER[x.status], x.rule_id)):
        extra = (
            _p(
                "; ".join(
                    f"{_SHORT.get(f, f)} {', '.join(rule.controls[f])}"
                    for f in others
                    if rule.controls.get(f)
                )
                or "-",
                s.small,
            )
            if others
            else _p(rule.severity.value, s.cell)
        )
        rows.append(
            [
                _p(rule.rule_id, s.code),
                _p(rule.title, s.cell),
                _p(", ".join(rule.nist_800_53r5) or "hardening best practice", s.cell),
                extra,
                _status(rule.status, s.cell),
            ]
        )
    widths = (40 * mm, 58 * mm, 30 * mm, 26 * mm, 20 * mm)
    if others:
        widths = (44 * mm, 46 * mm, 25 * mm, 41 * mm, 18 * mm)
    out.append(_table(rows, widths))
    for framework in r.frameworks:
        controls = [c for c in r.controls if c.framework == framework]
        heading, label = _MATRIX.get(framework, (framework, "Control"))
        out += [Spacer(1, 4 * mm), _p(heading, s.h2)]
        if not controls:
            note = next((sc.note for sc in r.scores if sc.framework == framework), "")
            out.append(_p((note[:1].upper() + note[1:] + ".") if note else "No control.", s.body))
            continue
        stig = framework == "disa_stig"
        rows = [[_p(h, s.cell) for h in (label, "Title", "Status", "Rules")]]
        if stig:
            rows = [[_p(h, s.cell) for h in (label, "CAT", "Title", "Status", "Rules")]]
        for c in controls:
            status = c.status.value + (" (checks cover part)" if c.partial else "")
            row = [
                _p(c.control, s.code),
                _p(c.title, s.cell if not stig else s.small),
                _p(status, s.cell),
                _p(", ".join(c.rules), s.small),
            ]
            if stig:
                row.insert(1, _p(_CAT.get(c.severity or "", ""), s.cell))
            rows.append(row)
        cols: tuple[float, ...] = (20 * mm, 62 * mm, 32 * mm, 60 * mm)
        if stig:
            cols = (28 * mm, 14 * mm, 62 * mm, 28 * mm, 42 * mm)
        out.append(_table(rows, cols))
    out.append(PageBreak())
    return out


_SHORT = {"disa_stig": "STIG", "iso_27001_2022": "ISO"}


# --- 4. detailed findings ------------------------------------------------------------------------


def _findings(r: AuditResult, rules_by_id: dict[str, Any], s: _Styles) -> list[Any]:
    out: list[Any] = [
        _p("Detailed findings", s.h1),
        _p(
            "Failures first, by severity; then items that need review. Evidence "
            "lines are quoted with their line numbers; secrets are masked.",
            s.small,
        ),
    ]
    shown = [f for f in r.findings if f.status in (Status.FAIL, Status.REVIEW)]
    fixes = {
        (x.rule_id, e): x
        for x in (r.remediation.fixes if r.remediation else ())
        for e in x.entity_ids
    }
    shown.sort(
        key=lambda f: (
            _STATUS_ORDER[f.status],
            _SEVERITY_ORDER.get(f.severity or Severity.LOW, 9),
            f.rule_id,
            f.entity_id,
        )
    )
    if not shown:
        out.append(_p("Nothing failed and nothing needs review.", s.body))
    for f in shown:
        out.append(CondPageBreak(45 * mm))
        fix = fixes.get((f.rule_id, f.entity_id))
        out.append(KeepTogether(_finding_block(f, rules_by_id.get(f.rule_id), s, fix)))
    passed = [f for f in r.findings if f.status in (Status.PASS, Status.NOT_APPLICABLE)]
    if passed:
        out += [Spacer(1, 4 * mm), _p("Passed and not applicable", s.h2)]
        rows = [[_p(h, s.cell) for h in ("Rule", "Entity", "Status", "Why")]]
        rows += [
            [
                _p(f.rule_id, s.code),
                _p(f.entity_id, s.cell),
                _status(f.status, s.cell),
                _p(f.reason, s.small),
            ]
            for f in passed
        ]
        out.append(_table(rows, (40 * mm, 38 * mm, 16 * mm, 80 * mm)))
    out.append(PageBreak())
    return out


def _finding_block(f: Finding, rule: Any, s: _Styles, fix: Fix | None) -> list[Any]:
    title = rule.title if rule is not None else f.rule_id
    block: list[Any] = [
        _p(f"{f.rule_id}: {title}", s.h2),
        _table(
            [
                [
                    _status(f.status, s.cell),
                    _p(f"Entity: {f.entity_id}", s.cell),
                    _p(f"Severity: {f.severity_reason or '-'}", s.cell),
                ]
            ],
            (22 * mm, 90 * mm, 62 * mm),
            header=False,
        ),
        _p(f.reason, s.body),
    ]
    if rule is not None:
        block.append(_p(f"Why it matters: {rule.intent}", s.small))
        block.append(_p(f"Expected: {rule.assert_}  (for each {rule.for_each})", s.code))
    if f.actual:
        block.append(_p("Actual:", s.small))
        block += [_p(line, s.code) for line in f.actual]
    if f.evidence:
        rows = [[_p("Lines", s.cell), _p("Configuration (masked)", s.cell), _p("Read by", s.cell)]]
        for ev in f.evidence:
            lines = (
                str(ev.line_start)
                if ev.line_start == ev.line_end
                else f"{ev.line_start}-{ev.line_end}"
            )
            rows.append(
                [_p(lines, s.code), _p(ev.raw, s.code), _p(ev.mapping_ref or "identity", s.small)]
            )
        block.append(_table(rows, (14 * mm, 104 * mm, 56 * mm)))
    if f.defaults_used:
        block.append(_p("Vendor defaults relied on: " + ", ".join(f.defaults_used), s.small))
    if f.status is Status.FAIL and fix is not None:
        block.append(
            _p(f"How to fix: see Remediation, {f.rule_id} ({_PROOF_WORD[fix.proof]}).", s.small)
        )
    elif rule is not None and rule.fix_intent is not None and f.status is Status.FAIL:
        block.append(
            _p(
                f"Fix intent: make {rule.fix_intent.make} = {display(rule.fix_intent.equal)}. "
                "This vendor pack has no command recipe for it; see Remediation.",
                s.small,
            )
        )
    block.append(Spacer(1, 3 * mm))
    return block


# --- 5. remediation (R-07c) -----------------------------------------------------------------------

_PROOF_WORD = {
    Proof.VERIFIED: "re-audit verified",
    Proof.NOT_VERIFIED: "didn't hold when re-audited",
    Proof.NOT_CHECKED: "not re-audited",
}
_PROOF_COLOUR = {
    Proof.VERIFIED: _STATUS_COLOUR[Status.PASS],
    Proof.NOT_VERIFIED: _STATUS_COLOUR[Status.FAIL],
    Proof.NOT_CHECKED: _STATUS_COLOUR[Status.REVIEW],
}
_STEPS = (
    ("1. Pre-check", "precheck"),
    ("2. Change", "change"),
    ("3. Verify", "verify"),
    ("4. Save", "save"),
    ("5. Rollback", "rollback"),
)


def _rich(text: str, style: ParagraphStyle) -> Paragraph:
    """Prose from a pack, with its `code` spans set in Courier."""
    parts = _safe(text).split("`")
    return Paragraph(
        "".join(
            f'<font name="Courier">{part}</font>' if i % 2 else part for i, part in enumerate(parts)
        ),
        style,
    )


def _commands(lines: Sequence[str], style: ParagraphStyle) -> Paragraph:
    """Commands one per line, their indentation kept (a sub-mode's depth matters)."""
    shown = []
    for line in lines:
        body = line.lstrip(" ")
        shown.append("&nbsp;" * (len(line) - len(body)) + _safe(body))
    return Paragraph("<br/>".join(shown) or "-", style)


def _remediation(r: AuditResult, s: _Styles) -> list[Any]:
    rem = r.remediation
    out: list[Any] = [_p("Remediation", s.h1)]
    if rem is None:
        out += [_p("Nothing failed, so there is nothing to fix.", s.body), PageBreak()]
        return out
    out.append(_p(rem.basis, s.small))
    if rem.combined is not None:
        c = rem.combined
        after = f"; compliance {_pct(c.compliance_after_pct)}" if c.compliance_after_pct else ""
        out += [
            Spacer(1, 2 * mm),
            _p(
                f"With every verified fix applied to one copy: failed checks "
                f"{c.failed_before} -> {c.failed_after}{after}.",
                s.h2,
            ),
            _p(c.detail, s.small),
        ]
    titles = {x.rule_id: x.title for x in r.rules}
    for fix in rem.fixes:
        out.append(CondPageBreak(60 * mm))
        out.append(KeepTogether(_fix_block(fix, titles.get(fix.rule_id, fix.rule_id), s)))
    if rem.unfixed:
        out += [_p("Failures without a command recipe", s.h2)]
        out += [_p(u, s.small) for u in rem.unfixed]
    out.append(PageBreak())
    return out


def _fix_block(fix: Fix, title: str, s: _Styles) -> list[Any]:
    colour = _PROOF_COLOUR[fix.proof].hexval()[2:]
    named = ["the device as a whole" if e == "Device[device]" else e for e in fix.entity_ids]
    entities = ", ".join(named[:6]) + (
        f" and {len(fix.entity_ids) - 6} more" if len(fix.entity_ids) > 6 else ""
    )
    block: list[Any] = [
        _p(f"{fix.rule_id}: {title}", s.h2),
        Paragraph(
            f'<font color="#{colour}"><b>{escape(_PROOF_WORD[fix.proof].upper())}</b></font>'
            f" &nbsp;{_safe(fix.proof_detail)}",
            s.small,
        ),
        _p(f"Fixes: {entities}. Recipe: {fix.recipe} ({fix.source}).", s.small),
    ]
    if fix.note:
        block.append(_rich(fix.note, s.body))
    if fix.placeholders:
        rows = [[_p("Fill in", s.cell), _p("Meaning", s.cell)]]
        rows += [[_p(f"<{p.name}>", s.code), _p(p.means, s.cell)] for p in fix.placeholders]
        block.append(_table(rows, (48 * mm, 126 * mm)))
    rows = [[_p("Step", s.cell), _p("Commands", s.cell), _p("Note", s.cell)]]
    for label, name in _STEPS:
        step = getattr(fix, name)
        if step is None:
            continue
        rows.append(
            [_p(label, s.cell), _commands(step.commands, s.code), _rich(step.note or "", s.small)]
        )
    block += [Spacer(1, 1 * mm), _table(rows, (22 * mm, 102 * mm, 50 * mm)), Spacer(1, 3 * mm)]
    return block


# --- 5-7 ---------------------------------------------------------------------------------------


def _policy(s: _Styles) -> list[Any]:
    return [
        _p("Firewall policy analysis", s.h1),
        _p(
            "Not performed in this version. Rule-set anomaly analysis (shadowing, redundancy, "
            "correlation) is planned for firewalls and cloud filters.",
            s.body,
        ),
        Spacer(1, 4 * mm),
    ]


def _assurance(r: AuditResult, s: _Styles) -> list[Any]:
    a = r.assurance
    out: list[Any] = [
        _p("Assurance and transparency", s.h1),
        _p(
            f"{a.understood} of {a.statements} configuration statements were understood "
            f"({_pct(a.understood_pct)}); {a.unmapped} were not, and {a.near_miss} looked "
            f"relevant but could not be read (those make the affected facts 'unknown', never "
            f"'absent'). {a.review_findings} finding(s) need human review.",
            s.body,
        ),
    ]
    if a.unmapped_patterns:
        out += [_p("Statements not understood (grouped by pattern)", s.h2)]
        rows = [[_p(h, s.cell) for h in ("Count", "First line", "Pattern")]]
        rows += [
            [_p(str(u.count), s.cell), _p(str(u.first_line), s.cell), _p(u.pattern_key, s.code)]
            for u in a.unmapped_patterns[:40]
        ]
        out.append(_table(rows, (14 * mm, 18 * mm, 142 * mm)))
        if len(a.unmapped_patterns) > 40:
            out.append(_p(f"... and {len(a.unmapped_patterns) - 40} more patterns.", s.small))
    if a.mappings_used:
        out += [_p("Mappings used and who approved them", s.h2)]
        rows = [[_p(h, s.cell) for h in ("Mapping", "Approved by", "Facts")]]
        rows += [
            [
                _p(m.mapping, s.code),
                _p(", ".join(m.approved_by) or "NOT APPROVED", s.cell),
                _p(str(m.facts), s.cell),
            ]
            for m in a.mappings_used
        ]
        out.append(_table(rows, (100 * mm, 56 * mm, 18 * mm)))
    if a.defaults_used:
        out += [_p("Vendor defaults relied on", s.h2)]
        out += [_p(d, s.code) for d in a.defaults_used]
    if a.mappings_skipped_for_version:
        out += [
            _p(
                "Mappings not applied (outside their OS version range, or version unknown): "
                + ", ".join(a.mappings_skipped_for_version),
                s.small,
            )
        ]
    out.append(PageBreak())
    return out


def _appendix(r: AuditResult, s: _Styles) -> list[Any]:
    glossary = [
        ("PASS", "The rule holds, from explicit configuration or a documented vendor default."),
        ("FAIL", "The rule is violated; the evidence lines show where."),
        (
            "REVIEW",
            "Could not be decided automatically: a fact is missing or was not "
            "understood, or relies on an unapproved mapping. Never counted as a pass.",
        ),
        ("N/A", "The rule does not apply to this device or nothing is in its scope."),
        ("Compliance %", "PASS / (PASS + FAIL) over applicable rules."),
        ("Coverage %", "(PASS + FAIL) / applicable rules: how much could be judged."),
    ]
    out: list[Any] = [
        _p("Appendix", s.h1),
        _p("Methodology", s.h2),
        _p(
            "The configuration is parsed into a vendor-neutral tree, translated into the Security "
            "Baseline Model by declarative, human-approved mappings, and checked by "
            "vendor-neutral rules. Every fact records the line it came from; a fact that is "
            "missing or was not understood is never treated as safe.",
            s.body,
        ),
        _p("Glossary", s.h2),
        _table(
            [[_p(k, s.cell), _p(v, s.cell)] for k, v in glossary], (28 * mm, 146 * mm), header=False
        ),
        _p("Framework attribution", s.h2),
        _p(
            "NIST SP 800-53 Rev. 5 control identifiers and titles are from NIST's official OSCAL "
            "catalog (public domain, US Government work).",
            s.body,
        ),
        *(
            [
                _p(
                    "DISA STIG identifiers, titles and categories are from DISA's published "
                    "XCCDF benchmarks (public domain, US Government work); each STIG "
                    "requirement's link to NIST SP 800-53 comes from DISA's CCI list.",
                    s.body,
                )
            ]
            if "disa_stig" in r.frameworks
            else []
        ),
        *(
            [
                _p(
                    "ISO/IEC 27001:2022 Annex A control numbers only; the descriptions are "
                    "Kasauti's own wording, not ISO text. Each rule's Annex A controls are "
                    "derived from its NIST anchors through NIST OLIR #155 and reviewed. A "
                    "configuration audit shows only the device's part of a control; the "
                    "organisational part is outside it.",
                    s.body,
                )
            ]
            if "iso_27001_2022" in r.frameworks
            else []
        ),
        _p("Provenance", s.h2),
        _table(
            [
                [_p(k, s.cell), _p(v, s.code)]
                for k, v in (
                    ("Knowledge base", r.kb.kb_version),
                    ("Rule set", r.kb.ruleset_version),
                    ("Vendor pack", r.kb.vendor_pack),
                    ("Input SHA-256", r.input.sha256),
                )
            ],
            (28 * mm, 146 * mm),
            header=False,
        ),
    ]
    return out
