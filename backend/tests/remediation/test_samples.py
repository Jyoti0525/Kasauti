"""Remediation end to end on every seed vendor (PLAN §14, R-07c; TODO M4.09, M4.11).

Every failed check on a weak sample gets a five-step fix whose change, applied to a copy and
re-audited, clears it without making any other check worse; applied together they take the
device to no failed check. What is shown never carries a secret or a stand-in value.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from kasauti.audit import KnowledgeBase, audit, load_kb
from kasauti.ingest.mask import MASK, mask_secrets
from kasauti.ingest.read import read_file
from kasauti.remediation import engine
from kasauti.remediation.model import Fix, Proof
from kasauti.rules.model import Status

REPO = Path(__file__).resolve().parents[3]
AUTHORED = REPO / "datasets" / "authored"
# The seed vendors, which ship curated recipes. A vendor taught in the Training Studio (Huawei
# VRP) gets its fixes by inverse mapping (TODO M4.03), not from recipes.
SEEDED = {p.parent.name for p in (REPO / "packs" / "vendors").glob("*/recipes")}
WEAK = sorted(p for p in AUTHORED.glob("*/weak*") if p.parent.name in SEEDED)
HARDENED = sorted(p for p in AUTHORED.glob("*/hardened*") if p.parent.name in SEEDED)
PARAM = re.compile(r"<([A-Z][A-Z0-9_]*)>")
TOKEN = re.compile(r'"[^"]*"|\S+')
# With TACACS+ logins through an authentication profile, which lockout governs PAN-OS
# administrators isn't documented, so the pack reads it as unknown (paloalto_panos/aaa.yaml).
LEFT_FOR_REVIEW = {"weak.xml": ("AAA-LOCKOUT-01",)}


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


def _shown(fix: Fix) -> list[str]:
    steps = [fix.precheck, fix.change, fix.verify, fix.save, fix.rollback]
    lines = [c for s in steps if s is not None for c in s.commands]
    notes = [s.note for s in steps if s is not None and s.note]
    return [*lines, *notes, fix.proof_detail, fix.note or ""]


def _secrets(text: str) -> set[str]:
    """Every value the masker hides in the configuration, as it appears in the file."""
    found: set[str] = set()
    for line in text.splitlines():
        masked = mask_secrets(line)
        if masked == line:
            continue
        ours, theirs = TOKEN.findall(line), TOKEN.findall(masked)
        if len(ours) == len(theirs):
            found |= {a.strip('"') for a, b in zip(ours, theirs, strict=True) if MASK in b}
    return {s for s in found if len(s) > 3}


@pytest.mark.parametrize("path", WEAK, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_every_failed_check_gets_a_verified_fix(path: Path, kb: KnowledgeBase) -> None:
    result = audit(read_file(path), kb)
    rem = result.remediation
    assert rem is not None
    failed = {(f.rule_id, f.entity_id) for f in result.findings if f.status is Status.FAIL}
    fixed = {(fix.rule_id, e) for fix in rem.fixes for e in fix.entity_ids}
    assert rem.unfixed == ()
    assert fixed == failed
    assert len(rem.fixes) == sum(1 for r in result.rules if r.status is Status.FAIL)
    for fix in rem.fixes:
        assert fix.proof is Proof.VERIFIED, (fix.rule_id, fix.proof_detail)
        assert fix.precheck.commands, fix.rule_id
        assert fix.change.commands, fix.rule_id
        assert fix.verify.commands, fix.rule_id
        assert fix.rollback.commands, fix.rule_id
    assert rem.combined is not None
    assert rem.combined.proof is Proof.VERIFIED
    assert rem.combined.failed_after == 0
    assert rem.combined.left_for_review == LEFT_FOR_REVIEW.get(path.name, ())


@pytest.mark.parametrize("path", WEAK, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_no_secret_or_stand_in_value_is_shown(path: Path, kb: KnowledgeBase) -> None:
    artifact = read_file(path)
    rem = audit(artifact, kb).remediation
    assert rem is not None
    secrets = _secrets(artifact.text)
    params = kb.vendor_packs[audit(artifact, kb, fixes=False).kb.vendor_pack.split("@")[0]].verify
    examples = {p.example for p in params.params if len(p.example) > 4}
    for fix in rem.fixes:
        for text in _shown(fix):
            assert not any(s in text for s in secrets), (fix.rule_id, text)
            assert not any(e in text for e in examples), (fix.rule_id, text)
        described = {p.name for p in fix.placeholders}
        for line in fix.change.commands:
            assert set(PARAM.findall(line)) <= described, (fix.rule_id, line)


@pytest.mark.parametrize("path", HARDENED, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_nothing_to_fix_on_a_hardened_sample(path: Path, kb: KnowledgeBase) -> None:
    assert audit(read_file(path), kb).remediation is None


def test_fixes_are_deterministic(kb: KnowledgeBase) -> None:
    artifact = read_file(AUTHORED / "cisco_ios_xe" / "weak.cfg")
    assert audit(artifact, kb).canonical_json() == audit(artifact, kb).canonical_json()


def test_the_cisco_telnet_fix_is_the_one_an_engineer_would_type(kb: KnowledgeBase) -> None:
    rem = audit(read_file(AUTHORED / "cisco_ios_xe" / "weak.cfg"), kb).remediation
    assert rem is not None
    telnet = next(f for f in rem.fixes if f.rule_id == "MGMT-TELNET-01")
    assert telnet.change.commands == (
        "configure terminal",
        "line vty 0 4",
        " transport input ssh",
        "line vty 5 15",
        " transport input ssh",
        "end",
    )
    assert telnet.rollback.commands == (
        "configure terminal",
        "line vty 0 4",
        " transport input ssh telnet",
        " exit",
        "line vty 5 15",
        " transport input telnet",
        " exit",
        "end",
    )
    assert telnet.save is not None
    assert telnet.save.commands == ("copy running-config startup-config",)
    assert telnet.precheck.commands == (
        "show running-config | section line vty 0 4",
        "show running-config | section line vty 5 15",
    )


def test_a_fix_that_does_not_settle_together_is_proven_alone(
    kb: KnowledgeBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PAN-OS lockout reads as unknown once TACACS+ logins go through a profile: applied with
    the other fixes it doesn't settle, so it is re-audited on its own copy, and it holds."""
    rem = audit(read_file(AUTHORED / "paloalto_panos" / "weak.xml"), kb).remediation
    assert rem is not None
    lockout = next(f for f in rem.fixes if f.rule_id == "AAA-LOCKOUT-01")
    assert lockout.proof is Proof.VERIFIED
    assert lockout.proof_detail.startswith("Applied on its own")
    monkeypatch.setattr(engine, "WORK_LIMIT", 0)
    rem = audit(read_file(AUTHORED / "paloalto_panos" / "weak.xml"), kb).remediation
    assert rem is not None
    lockout = next(f for f in rem.fixes if f.rule_id == "AAA-LOCKOUT-01")
    assert lockout.proof is Proof.NOT_CHECKED
    assert "too large" in lockout.proof_detail


def test_one_fix_covers_every_entity_of_a_check(kb: KnowledgeBase) -> None:
    rem = audit(read_file(AUTHORED / "cisco_ios_xe" / "weak.cfg"), kb).remediation
    assert rem is not None
    proxy = next(f for f in rem.fixes if f.rule_id == "SVC-PROXY-ARP-01")
    assert proxy.entity_ids == (
        "Interface[GigabitEthernet1]",
        "Interface[GigabitEthernet2]",
        "Interface[GigabitEthernet3]",
    )
    vty = next(f for f in rem.fixes if f.rule_id == "MGMT-VTY-ACL-01")
    # Both vty ranges' fixes define the same access list: it is typed once.
    assert sum(1 for c in vty.change.commands if c.startswith("ip access-list")) == 1


def test_a_recipe_for_no_rule_or_with_an_undescribed_value_stops_the_load(
    tmp_path: Path,
) -> None:
    import shutil  # noqa: PLC0415 - only this test copies the packs

    from kasauti.packs.loader import PackError  # noqa: PLC0415

    packs = tmp_path / "packs"
    shutil.copytree(REPO / "packs", packs)
    (packs / "vendors" / "cisco_ios_xe" / "recipes" / "bad.yaml").write_text(
        "recipes:\n"
        "  - {id: ghost, rule: NO-SUCH-RULE-01, change: ['ip ssh version 2']}\n"
        "  - {id: vague, rule: MGMT-SSH-V2-01, change: ['logging host <SOMEWHERE>']}\n",
        encoding="utf-8",
    )
    with pytest.raises(PackError) as err:
        load_kb(packs)
    problems = "\n".join(err.value.problems)
    assert "no rule 'NO-SUCH-RULE-01'" in problems
    assert "<SOMEWHERE> isn't described" in problems


def _pdf_words(pdf: bytes) -> str:
    """The text a ReportLab PDF draws: its content streams inflated, string literals joined."""
    import base64  # noqa: PLC0415 - only the PDF test reads streams
    import zlib  # noqa: PLC0415

    drawn = b""
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        chunk = m.group(1).strip()
        try:
            if chunk.endswith(b"~>"):
                chunk = base64.a85decode(chunk, adobe=True)
            chunk = zlib.decompress(chunk)
        except (ValueError, zlib.error):
            pass  # a stream written uncompressed
        drawn += chunk
    return " ".join(s.decode("latin1") for s in re.findall(rb"\(((?:[^()\\]|\\.)*)\)", drawn))


def test_the_pdf_gives_each_fix_its_five_steps(kb: KnowledgeBase) -> None:
    from kasauti.report.pdf import render_pdf  # noqa: PLC0415

    result = audit(read_file(AUTHORED / "cisco_ios_xe" / "weak.cfg"), kb)
    words = _pdf_words(render_pdf(result, {r.id: r for r in kb.ruleset.rules}, generated="x"))
    assert "later release" not in words
    assert "Remediation" in words
    assert "failed checks 21 - > 0" in words  # ReportLab draws "->" as two runs
    for step in ("1. Pre-check", "2. Change", "3. Verify", "4. Save", "5. Rollback"):
        assert step in words
    assert "transport input ssh" in words
    assert "RE-AUDIT VERIFIED" in words
