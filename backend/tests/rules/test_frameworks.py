"""Multi-framework scoring and the crosswalk hub (PLAN §12.4, §12.6; R-06; TODO M2.56-M2.58)."""

from __future__ import annotations

from pathlib import Path

import pytest

from kasauti.audit import KnowledgeBase, audit, load_kb
from kasauti.ingest.read import read_file
from kasauti.packs.crosswalk import bridge_problems, bridged, citations
from kasauti.packs.loader import FrameworkPack
from kasauti.packs.model import Crosswalk
from kasauti.rules.model import Status
from kasauti.rules.scoring import (
    Cited,
    ControlStatus,
    Coverage,
    control_matrix,
    control_sort_key,
    framework_score,
)

REPO = Path(__file__).resolve().parents[3]
FULL, PART, STRICTER = Coverage.FULL, Coverage.PART, Coverage.STRICTER


@pytest.fixture(scope="module")
def kb() -> KnowledgeBase:
    return load_kb(REPO / "packs")


def _one(status: Status, covers: Coverage, *, atomic: bool = False) -> tuple[ControlStatus, bool]:
    rolled = control_matrix(
        {"R-01": (Cited("X-1", covers),)}, {"R-01": status}, order=str, atomic=atomic
    )
    return rolled["X-1"].status, rolled["X-1"].partial


def test_a_partial_rule_can_fail_a_control_but_never_satisfy_it() -> None:
    assert _one(Status.FAIL, PART) == (ControlStatus.NOT_SATISFIED, False)
    assert _one(Status.PASS, PART) == (ControlStatus.UNDETERMINED, True)
    assert _one(Status.PASS, FULL) == (ControlStatus.SATISFIED, False)


def test_a_stricter_rule_can_satisfy_a_control_but_never_fail_it() -> None:
    assert _one(Status.PASS, STRICTER) == (ControlStatus.SATISFIED, False)
    assert _one(Status.FAIL, STRICTER) == (ControlStatus.UNDETERMINED, False)


def test_a_stig_rule_is_open_or_not_never_partly_satisfied() -> None:
    cited = {"A-01": (Cited("S-1", PART),), "B-01": (Cited("S-1", FULL),)}
    statuses = {"A-01": Status.FAIL, "B-01": Status.PASS}
    broad = control_matrix(cited, statuses, order=str)
    atomic = control_matrix(cited, statuses, order=str, atomic=True)
    assert broad["S-1"].status is ControlStatus.PARTIALLY_SATISFIED
    assert atomic["S-1"].status is ControlStatus.NOT_SATISFIED


def test_framework_score_counts_verdicts_only_as_far_as_they_decide() -> None:
    cited = {
        "A-01": (Cited("S-1", PART),),
        "B-01": (Cited("S-2", FULL), Cited("S-3", PART)),
        "C-01": (Cited("S-4", STRICTER),),
        "D-01": (),
    }
    statuses = {"A-01": Status.PASS, "B-01": Status.PASS, "C-01": Status.FAIL, "D-01": Status.FAIL}
    s = framework_score(statuses, cited)
    # A's PASS settles nothing; B's does (S-2 in full); C's FAIL can't break S-4; D isn't mapped.
    assert (s.passed, s.failed, s.review) == (1, 0, 2)
    assert (s.compliance_pct, s.coverage_pct) == (100.0, 33.3)


def test_bridged_compares_base_controls() -> None:
    assert bridged(["AC-17(2)"], ["AC-17"])
    assert bridged(["SC-45(1)"], ["SC-45(2)"])
    assert not bridged(["AC-3", "AC-17"], ["AC-4"])


def test_stig_mappings_are_per_vendor_and_aws_has_none(kb: KnowledgeBase) -> None:
    stig = kb.frameworks["disa_stig"]
    cisco = citations("disa_stig", stig, kb.ruleset.rules, "cisco_ios_xe")
    junos = citations("disa_stig", stig, kb.ruleset.rules, "juniper_junos")
    aws = citations("disa_stig", stig, kb.ruleset.rules, "aws_vpc")
    assert {c.control for c in cisco["MGMT-TELNET-01"]} == {"CISC-ND-000470", "CISC-ND-001210"}
    assert {c.control for c in junos["MGMT-TELNET-01"]} == {"JUSX-DM-000109"}
    assert not any(aws.values())


def test_the_crosswalk_lint_rejects_an_unbridged_or_misplaced_mapping(
    kb: KnowledgeBase,
) -> None:
    stig = kb.frameworks["disa_stig"]
    assert bridge_problems(stig, kb.ruleset.rules) == []
    bad = Crosswalk.model_validate(
        {
            "format_version": 1,
            "framework": "disa_stig",
            "entries": [
                # DISA files CISC-ND-000140 under AC-4; the banner rule anchors AC-8.
                {
                    "rule": "MGMT-BANNER-01",
                    "vendor": "cisco_ios_xe",
                    "controls": ["CISC-ND-000140"],
                    "source": "authored",
                },
                # An Arista STIG rule mapped for a Cisco device.
                {
                    "rule": "MGMT-BANNER-01",
                    "vendor": "cisco_ios_xe",
                    "controls": ["ARST-ND-000130"],
                    "source": "authored",
                },
                {"rule": "MGMT-BANNER-01", "controls": ["CISC-ND-000160"], "source": "authored"},
                {
                    "rule": "NOPE-01",
                    "vendor": "cisco_ios_xe",
                    "controls": ["CISC-ND-000160"],
                    "source": "authored",
                },
            ],
        }
    )
    problems = bridge_problems(FrameworkPack(stig.root, stig.catalog, bad), kb.ruleset.rules)
    text = "\n".join(problems)
    assert "CISC-ND-000140 shares no NIST base control" in text
    assert "ARST-ND-000130 is in" in text
    assert "each mapping names its vendor" in text
    assert "unknown rule" in text


def test_a_partial_mapping_must_say_what_it_leaves_out() -> None:
    with pytest.raises(ValueError, match="needs a note"):
        Crosswalk.model_validate(
            {
                "format_version": 1,
                "framework": "disa_stig",
                "entries": [
                    {"rule": "R", "controls": ["X"], "source": "authored", "covers": "part"}
                ],
            }
        )


def test_catalogs_trace_to_official_sources(kb: KnowledgeBase) -> None:
    stig = kb.frameworks["disa_stig"].catalog
    iso = kb.frameworks["iso_27001_2022"].catalog
    assert stig.bridge is not None
    assert iso.bridge is not None
    assert all(
        len(b.source.sha256) == 64 and b.source.url.startswith("https://") for b in stig.benchmarks
    )
    assert all(c.severity and c.vuln_id and c.ccis for c in stig.controls)
    # Every STIG rule reaches an active Rev. 5 control through DISA's CCI list.
    nist = {c.id for c in kb.frameworks["nist_800_53r5"].catalog.controls}
    assert all(c.nist and set(c.nist) <= nist for c in stig.controls)
    assert len(iso.controls) == 93
    # ISO text is copyrighted: only our wording, and only where a rule is mapped.
    mapped = {c for e in kb.frameworks["iso_27001_2022"].crosswalk.entries for c in e.controls}  # type: ignore[union-attr]
    assert {c.id for c in iso.controls if c.title} == mapped


def test_selected_frameworks_change_the_control_matrix(kb: KnowledgeBase) -> None:
    config = read_file(REPO / "datasets/authored/cisco_ios_xe/weak.cfg")
    nist_only = audit(config, kb, frameworks=("nist_800_53r5",), fixes=False)
    three = audit(
        config, kb, frameworks=("nist_800_53r5", "disa_stig", "iso_27001_2022"), fixes=False
    )
    assert {c.framework for c in nist_only.controls} == {"nist_800_53r5"}
    assert {c.framework for c in three.controls} == {"nist_800_53r5", "disa_stig", "iso_27001_2022"}
    telnet = next(c for c in three.controls if c.control == "CISC-ND-000470")
    assert telnet.status is ControlStatus.NOT_SATISFIED
    assert telnet.severity == "high"
    assert "MGMT-TELNET-01" in telnet.rules
    rule = next(r for r in three.rules if r.rule_id == "MGMT-TELNET-01")
    assert rule.controls["iso_27001_2022"] == ("A.8.20",)
    stig = [c.control for c in three.controls if c.framework == "disa_stig"]
    assert stig == sorted(stig, key=lambda c: (not c.startswith("CISC-ND"), c))


def test_a_platform_without_a_stig_says_so(kb: KnowledgeBase) -> None:
    result = audit(
        read_file(REPO / "datasets/authored/aws_vpc/weak.json"),
        kb,
        frameworks=("disa_stig",),
        fixes=False,
    )
    (s,) = result.scores
    assert (s.passed, s.failed, s.review, s.coverage_pct) == (0, 0, 0, None)
    assert "no benchmark for this platform" in s.note
    assert result.controls == ()


def test_nist_order_is_unchanged() -> None:
    assert sorted(["AC-17", "AC-2(1)", "AC-2"], key=control_sort_key) == [
        "AC-2",
        "AC-2(1)",
        "AC-17",
    ]
