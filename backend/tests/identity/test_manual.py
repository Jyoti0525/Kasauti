"""Device details typed by hand, identity source 4 (PLAN §7; TODO M2.19)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kasauti.audit import AuditError, AuditResult, KnowledgeBase, audit, load_kb
from kasauti.identity.detect import choose, detect_vendor
from kasauti.identity.manual import (
    ENTERABLE,
    SOURCE,
    VALUE_LIMIT,
    ManualEntryError,
    clean_entered,
)
from kasauti.identity.resolve import Identity, resolve_identity
from kasauti.ingest.read import decode
from kasauti.packs.loader import load_vendor_pack
from kasauti.rules.model import Status
from kasauti.sbm.facts import FactState
from kasauti.shape.parse import parse_text

REPO = Path(__file__).resolve().parents[3]
HARDENED = REPO / "datasets" / "authored" / "cisco_ios_xe" / "hardened.cfg"


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


def test_values_are_trimmed_ordered_and_an_empty_one_clears() -> None:
    assert clean_entered({"serial": "  FTX1234 ", "model": "C8000V", "hardware": " "}) == {
        "model": "C8000V",
        "serial": "FTX1234",
    }
    assert list(clean_entered(dict.fromkeys(reversed(ENTERABLE), "x"))) == list(ENTERABLE)
    assert clean_entered({"hostname": None}) == {}
    assert clean_entered({"serial": "x" * VALUE_LIMIT}) == {"serial": "x" * VALUE_LIMIT}


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({"vendor": "Cisco"}, "no such device detail: vendor"),
        ({"serial": 1234}, "serial: must be text"),
        ({"serial": "x" * (VALUE_LIMIT + 1)}, f"at most {VALUE_LIMIT} characters"),
        ({"serial": "FTX1\nhostname EVIL"}, "printable characters on one line only"),
        ({"model": "C8000V\x00"}, "printable characters on one line only"),
        # A right-to-left override would make a report show one serial and hold another.
        ({"serial": "FTX\u202e4321"}, "printable characters on one line only"),
        (["serial", "FTX1"], "field: value pairs"),
    ],
)
def test_what_can_t_be_taken_is_refused_by_name_never_echoed(values: object, message: str) -> None:
    with pytest.raises(ManualEntryError, match=message) as err:
        clean_entered(values)  # type: ignore[arg-type]
    assert "FTX" not in str(err.value)
    assert "C8000V" not in str(err.value)


def _identity(text: str, entered: dict[str, str]) -> Identity:
    cisco = load_vendor_pack(REPO / "packs" / "vendors" / "cisco_ios_xe")
    tree = parse_text(text, source_file="r.cfg", family=cisco.manifest.shape_family)
    return resolve_identity(
        tree, cisco, choose(detect_vendor(text, [cisco])), text, entered=entered
    )


def test_a_typed_value_fills_only_what_no_file_gives_and_is_no_fact() -> None:
    text = HARDENED.read_text(encoding="utf-8")
    ident = _identity(text, {"serial": "FTX1234", "hostname": "CORE-9", "os_version": "17.9"})
    assert ident.value("serial") == "FTX1234"
    assert ident.sources["serial"] == SOURCE
    assert "serial" not in ident.missing
    assert ident.device.serial.state is FactState.ABSENT, "facts are what the files show"
    assert ident.value("hostname") == "EDGE-R1", "the file names the host: it wins"
    assert ident.sources["hostname"].startswith("config line")
    assert ident.disagreements == (
        "Hostname entered by hand ('CORE-9') differs from config line 13 ('EDGE-R1'); the value "
        "in the files is used",
    )
    assert "os_version" not in ident.entered, "the same as the file's: nothing to say"


def test_a_typed_os_version_never_changes_a_verdict(kb: KnowledgeBase) -> None:
    """Version-scoped defaults need the release. Typed by hand it is only shown: a typo must not
    turn a REVIEW into a PASS."""
    text = HARDENED.read_text(encoding="utf-8")
    unversioned = "".join(ln for ln in text.splitlines(True) if not ln.startswith("version "))
    real = audit(decode(text.encode(), "r.cfg"), kb)
    without = audit(decode(unversioned.encode(), "r.cfg"), kb, vendor="cisco_ios_xe")
    typed = audit(
        decode(unversioned.encode(), "r.cfg"),
        kb,
        vendor="cisco_ios_xe",
        entered={"os_version": "17.9", "serial": "FTX1234"},
    )

    def statuses(result: AuditResult) -> dict[str, Status]:
        return {r.rule_id: r.status for r in result.rules}

    assert statuses(real)["MGMT-TELNET-01"] is Status.PASS, "17.9's default: telnet is off"
    assert statuses(without)["MGMT-TELNET-01"] is Status.REVIEW
    assert statuses(typed) == statuses(without)
    assert typed.sbm == without.sbm
    assert typed.identity["os_version"].model_dump() == {"value": "17.9", "source": SOURCE}
    assert typed.identity["serial"].model_dump() == {"value": "FTX1234", "source": SOURCE}
    assert typed.audit_id != without.audit_id, "a different report, so a different id"


def test_the_audit_checks_typed_values_itself(kb: KnowledgeBase) -> None:
    with pytest.raises(AuditError, match="no such device detail: vendor"):
        audit(decode(HARDENED.read_bytes(), "r.cfg"), kb, entered={"vendor": "Juniper"})
