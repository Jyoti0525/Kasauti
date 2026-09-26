"""Per-device PDF report (PLAN §15.1; TODO M1.13, growing into M2.70). ReportLab, BSD licence.

Sections follow §15.1: cover and device profile, executive summary (Compliance % *and*
Coverage %), control matrix, detailed findings (FAIL first, with expected vs actual and the
evidence lines), policy analysis, assurance and transparency, appendix.

Security: every string that came from a configuration is escaped before it reaches ReportLab,
whose Paragraph markup would otherwise interpret ``<a href=…>``, ``<img>`` or ``<font>`` in a
crafted config line. Evidence is already masked by the pipeline.

The report is unsigned until M5 (PAdES via pyHanko, TODO M5.14) and says so on its cover.
Output is byte-reproducible (ReportLab's invariant mode), given the same audit and date.
"""

from __future__ import annotations

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

from kasauti.audit import AuditResult
from kasauti.rules.evaluate import display
from kasauti.rules.model import Finding, Severity, Status

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
_STATUS_ORDER = {Status.FAIL: 0, Status.REVIEW: 1, Status.PASS: 2, Status.NOT_APPLICABLE: 3}
_STATUS_COLOUR = {
    Status.PASS: colors.HexColor("#1b7f3b"),
    Status.FAIL: colors.HexColor("#b3261e"),
    Status.REVIEW: colors.HexColor("#9a6700"),
    Status.NOT_APPLICABLE: colors.HexColor("#5f6368"),
}
_INK = colors.HexColor("#1f2328")
_MUTED = colors.HexColor("#57606a")
_RULE = colors.HexColor("#d0d7de")
_HEAD_BG = colors.HexColor("#f3f4f6")


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
        topMargin=18 * mm,
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

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()


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


def _safe(text: object) -> str:
    """Escape for ReportLab markup and keep to characters the built-in fonts can draw."""
    raw = str(text)
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


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}%"


# --- 1. cover and device profile -----------------------------------------------------------------


def _cover(r: AuditResult, s: _Styles, generated: str) -> list[Any]:
    host = r.identity["hostname"].value or r.input.file
    out: list[Any] = [
        _p("Kasauti compliance report", s.title),
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
                _p(item.source, s.small),
            ]
        )
    out.append(_table(rows, (28 * mm, 45 * mm, 101 * mm)))
    out += [Spacer(1, 4 * mm), _p("Audit", s.h1)]
    meta = [
        ("Configuration file", r.input.file),
        ("SHA-256", r.input.sha256),
        ("Shape family / encoding", f"{r.input.shape_family} / {r.input.encoding}"),
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
    fails = [f for f in r.findings if f.status is Status.FAIL]
    counts = Counter(f.severity for f in fails)
    out += [Spacer(1, 3 * mm), _p("Failed findings by severity", s.h2)]
    out.append(
        _table(
            [
                [_p(sev.value.capitalize(), s.cell) for sev in Severity],
                [_p(str(counts.get(sev, 0)), s.cell) for sev in Severity],
            ],
            (43.5 * mm,) * 4,
        )
    )
    out += [Spacer(1, 3 * mm), _p("Top risks", s.h2)]
    top = sorted(
        (x for x in r.rules if x.status is Status.FAIL),
        key=lambda x: (_SEVERITY_ORDER[x.severity], x.rule_id),
    )[:5]
    if not top:
        out.append(_p("No rule failed.", s.body))
    for i, rule in enumerate(top, 1):
        out.append(_p(f"{i}. [{rule.severity.value}] {rule.title} ({rule.rule_id})", s.body))
    out.append(PageBreak())
    return out


# --- 3. control matrix ---------------------------------------------------------------------------


def _control_matrix(r: AuditResult, s: _Styles) -> list[Any]:
    out: list[Any] = [
        _p("Control matrix", s.h1),
        _p(
            "Each rule, the NIST SP 800-53 Rev. 5 controls it supports, and its "
            "status on this device.",
            s.small,
        ),
        Spacer(1, 2 * mm),
    ]
    rows = [[_p(h, s.cell) for h in ("Rule", "Title", "NIST SP 800-53 r5", "Severity", "Status")]]
    for rule in sorted(r.rules, key=lambda x: (_STATUS_ORDER[x.status], x.rule_id)):
        rows.append(
            [
                _p(rule.rule_id, s.code),
                _p(rule.title, s.cell),
                _p(", ".join(rule.nist_800_53r5) or "hardening best practice", s.cell),
                _p(rule.severity.value, s.cell),
                _status(rule.status, s.cell),
            ]
        )
    out.append(_table(rows, (40 * mm, 62 * mm, 34 * mm, 18 * mm, 20 * mm)))
    if r.controls:
        out += [Spacer(1, 4 * mm), _p("NIST controls", s.h2)]
        rows = [[_p(h, s.cell) for h in ("Control", "Title", "Status", "Rules")]]
        rows += [
            [
                _p(c.control, s.code),
                _p(c.title, s.cell),
                _p(c.status.value, s.cell),
                _p(", ".join(c.rules), s.small),
            ]
            for c in r.controls
        ]
        out.append(_table(rows, (20 * mm, 62 * mm, 32 * mm, 60 * mm)))
    out.append(PageBreak())
    return out


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
        out.append(KeepTogether(_finding_block(f, rules_by_id.get(f.rule_id), s)))
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


def _finding_block(f: Finding, rule: Any, s: _Styles) -> list[Any]:
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
    if rule is not None and rule.fix_intent is not None and f.status is Status.FAIL:
        block.append(
            _p(
                f"Fix intent: make {rule.fix_intent.make} = {display(rule.fix_intent.equal)}. "
                "Vendor-specific remediation steps arrive in a later release.",
                s.small,
            )
        )
    block.append(Spacer(1, 3 * mm))
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
