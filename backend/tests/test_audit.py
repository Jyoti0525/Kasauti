"""End to end: audit, determinism, secrecy, the CLI and the PDF (TODO M1.13-M1.15, M1.G)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from kasauti.audit import AuditError, KnowledgeBase, audit, load_kb
from kasauti.cli.main import main
from kasauti.ingest.read import decode, read_file
from kasauti.report.pdf import render_pdf
from kasauti.rules.model import Status

REPO = Path(__file__).resolve().parents[2]
WEAK = REPO / "datasets" / "authored" / "cisco_ios_xe" / "weak.cfg"
HARDENED = REPO / "datasets" / "authored" / "cisco_ios_xe" / "hardened.cfg"
SECRETS = re.compile(r"PLACEHOLDER|\bpublic\b|\bprivate\b")


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


def test_weak_config_fails_every_rule_with_its_lines(kb: KnowledgeBase) -> None:
    result = audit(read_file(WEAK), kb)
    assert {r.rule_id: r.status for r in result.rules} == dict.fromkeys(
        (r.id for r in kb.ruleset.rules), Status.FAIL
    )
    telnet = next(f for f in result.findings if f.rule_id == "MGMT-TELNET-01")
    assert [e.line_start for e in telnet.evidence] == [49, 53, 54, 57]
    (score,) = result.scores
    assert (score.compliance_pct, score.coverage_pct) == (0.0, 100.0)


def test_hardened_config_passes_and_names_the_defaults_it_used(kb: KnowledgeBase) -> None:
    result = audit(read_file(HARDENED), kb)
    statuses = {r.rule_id: r.status for r in result.rules}
    assert statuses.pop("MGMT-WEB-ACL-01") is Status.NOT_APPLICABLE  # no web server runs
    assert set(statuses.values()) == {Status.PASS}
    snmp = next(f for f in result.findings if f.rule_id == "SNMP-COMMUNITY-01")
    assert snmp.defaults_used == ("cisco_ios_xe/defaults.yaml#no-snmp-communities",)


def test_two_runs_are_byte_identical_json_and_pdf(kb: KnowledgeBase) -> None:
    """PLAN §3.1 principle 5, TODO M1.15."""
    first = audit(read_file(WEAK), kb)
    second = audit(read_file(WEAK), load_kb(REPO / "packs"))
    assert first.canonical_json() == second.canonical_json()
    rules = {r.id: r for r in kb.ruleset.rules}
    assert render_pdf(first, rules, generated="2026-09-26") == render_pdf(
        second, rules, generated="2026-09-26"
    )


def test_no_secret_reaches_any_output(kb: KnowledgeBase) -> None:
    for path in (WEAK, HARDENED):
        result = audit(read_file(path), kb)
        assert not SECRETS.search(result.canonical_json()), path.name


def test_crafted_markup_in_a_config_cannot_break_or_inject_into_the_pdf(kb: KnowledgeBase) -> None:
    text = WEAK.read_text(encoding="utf-8").replace(
        "description LAN", 'description <a href="http://evil">x</a> <font size=90> <b'
    )
    result = audit(decode(text.encode(), "crafted.cfg"), kb, vendor="cisco_ios_xe")
    # Unescaped, "<b" would crash ReportLab's parser and "<a href>" would become a live link.
    pdf = render_pdf(result, {r.id: r for r in kb.ruleset.rules}, generated="2026-09-26")
    assert pdf.startswith(b"%PDF")
    assert b"/URI" not in pdf


def test_unknown_vendor_is_an_error_not_a_guess(kb: KnowledgeBase) -> None:
    junos = REPO / "datasets" / "authored" / "juniper_junos" / "hardened.conf"
    with pytest.raises(AuditError, match="can't tell which vendor"):
        audit(read_file(junos), kb)
    with pytest.raises(AuditError, match="no vendor pack"):
        audit(read_file(WEAK), kb, vendor="nokia_sros")


def test_forcing_a_vendor_that_does_not_fingerprint_warns(kb: KnowledgeBase) -> None:
    result = audit(
        decode(b"hostname R1\nline vty 0 4\n transport input telnet\n", "r.cfg"),
        kb,
        vendor="cisco_ios_xe",
    )
    assert result.detection.chosen_by == "operator"
    assert any("check this is really" in w for w in result.warnings)
    telnet = next(r for r in result.rules if r.rule_id == "MGMT-TELNET-01")
    assert telnet.status is Status.FAIL


def test_cli_audit_writes_json_and_pdf(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        [
            "audit",
            str(WEAK),
            "--framework",
            "nist",
            "--packs",
            str(REPO / "packs"),
            "--out",
            str(tmp_path),
            "--date",
            "2026-09-26",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "compliance 0.0%, coverage 100.0%" in out
    data = json.loads((tmp_path / "weak.kasauti.json").read_text(encoding="utf-8"))
    assert data["identity"]["hostname"]["value"] == "EDGE-R1"
    assert (tmp_path / "weak.kasauti.pdf").read_bytes().startswith(b"%PDF")


def test_cli_reports_bad_input_without_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    binary = tmp_path / "fw.bin"
    binary.write_bytes(b"\x00\x01\x02" * 100)
    assert main(["audit", str(binary), "--packs", str(REPO / "packs"), "--out", str(tmp_path)]) == 1
    assert "binary" in capsys.readouterr().err


def test_kb_version_does_not_depend_on_line_endings(tmp_path: Path) -> None:
    """A Windows checkout (CRLF) must report the same knowledge base as Linux CI (LF)."""
    import shutil  # noqa: PLC0415

    crlf = tmp_path / "packs"
    shutil.copytree(REPO / "packs", crlf)
    for path in crlf.rglob("*.yaml"):
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    assert load_kb(crlf).version == load_kb(REPO / "packs").version


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ntp server vrf Mgmt-intf 10.0.0.9 key 1", Status.PASS),
        ("ntp server vrf Mgmt-intf 10.0.0.9", Status.FAIL),
        ("ntp server 10.0.0.9 version 4", Status.REVIEW),  # read as a near miss, never a pass
    ],
)
def test_ntp_server_forms(kb: KnowledgeBase, line: str, expected: Status) -> None:
    text = f"version 17.9\nntp authenticate\n{line}\n"
    result = audit(decode(text.encode(), "ntp.cfg"), kb, vendor="cisco_ios_xe")
    assert {r.rule_id: r.status for r in result.rules}["TIME-NTP-AUTH-01"] is expected


def test_broken_password_types_fail_rather_than_review(kb: KnowledgeBase) -> None:
    text = "version 17.9\nenable secret 4 Xabc\nusername a privilege 15 secret 5 $1$x$y\n"
    result = audit(decode(text.encode(), "types.cfg"), kb, vendor="cisco_ios_xe")
    assert {r.rule_id: r.status for r in result.rules}["AAA-LOCAL-PASSWORD-HASH-01"] is Status.FAIL
