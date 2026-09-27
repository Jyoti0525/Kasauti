"""Grouping uploaded files into devices (PLAN §5.1; TODO M2.06): the rules, without I/O."""

from __future__ import annotations

import pytest

from kasauti.ingest.devices import (
    MAX_COMPANIONS,
    How,
    Kind,
    Member,
    Placement,
    Recognised,
    group,
    host_key,
    name_key,
)


def _config(file_id: str, name: str, host: str | None, vendor: str = "cisco_ios_xe") -> Member:
    return Member(file_id, name, Recognised(Kind.CONFIG, vendor, None, host))


def _output(
    file_id: str,
    name: str,
    host: str | None = None,
    vendor: str = "cisco_ios_xe",
    command: str = "show_version",
    **manual: object,
) -> Member:
    return Member(file_id, name, Recognised(Kind.COMPANION, vendor, command, host), **manual)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("edge-r1.cfg", "edge-r1"),
        ("EDGE_R1_show_inventory.txt", "edge-r1"),
        ("show-version-edge-r1.txt", "edge-r1"),
        ("edge-r1.running-config.txt", "edge-r1"),
        ("edge-r1_2026-09-27.cfg", "edge-r1"),
        ("edge-r1_20260927_1030.cfg", "edge-r1"),
        ("edge-r1 2026_09_27 10_30_15 show version.txt", "edge-r1"),
        ("site-a/edge-r1/show_version.txt", "edge-r1"),  # a generic name: its folder speaks
        ("fleet.zip/running-config.txt", "fleet"),
        ("router 1.cfg", "router-1"),  # a number that isn't a date stays
        ("router-2026.cfg", "router-2026"),  # a year alone isn't a date
        ("show_version.txt", None),
    ],
)
def test_what_a_file_name_says_about_its_device(name: str, key: str | None) -> None:
    assert name_key(name) == key


def test_hostnames_compare_the_way_names_do() -> None:
    assert host_key("EDGE_R1") == host_key("edge-r1") == "edge-r1"


def test_every_configuration_is_its_own_device_and_outputs_join_theirs() -> None:
    placed = group(
        [
            _config("c1", "a.cfg", "EDGE-R1"),
            _config("c2", "leaf1.cfg", "LEAF-1", vendor="arista_eos"),
            _output("o1", "show_version.txt", "edge-r1"),  # by the host it names
            _output("o2", "a_show_inventory.txt", command="show_inventory"),  # by file name
            _output("o3", "LEAF-1-version.txt", vendor="arista_eos"),  # named after the host
        ]
    )
    assert placed == {
        "c1": Placement("c1", How.OWN),
        "c2": Placement("c2", How.OWN),
        "o1": Placement("c1", How.HOSTNAME),
        "o2": Placement("c1", How.NAME),
        "o3": Placement("c2", How.NAME),
    }


def test_an_output_never_joins_another_vendor_or_another_host() -> None:
    placed = group(
        [
            _config("c1", "edge-r1.cfg", "EDGE-R1"),
            _output("o1", "edge-r1_show_version.txt", "EDGE-R2"),  # its name matches; its host not
            _output("o2", "edge-r1_status.txt", vendor="fortinet_fortios"),
        ]
    )
    assert placed["o1"] == Placement(
        None, How.HOSTNAME, "names host EDGE-R2, and no configuration here is that host"
    )
    assert placed["o2"].device is None


def test_a_configuration_with_no_hostname_takes_its_host_s_output_by_name() -> None:
    placed = group([_config("c1", "edge-r1.cfg", None), _output("o1", "edge-r1-ver.txt", "X")])
    assert placed["o1"] == Placement("c1", How.NAME)


def test_a_tie_is_left_for_a_person_not_guessed() -> None:
    members = [
        _config("c1", "running.cfg", "EDGE-R1"),
        _config("c2", "startup.cfg", "EDGE-R1"),
        _output("o1", "show_version.txt", "EDGE-R1"),
        _output("o2", "inventory.txt", command="show_inventory"),
    ]
    placed = group(members)
    assert placed["o1"] == Placement(
        None, How.HOSTNAME, "matches 2 configurations (running.cfg, startup.cfg): pair it by hand"
    )
    assert placed["o2"].device is None
    assert placed["o2"].note is not None
    assert "pair it by hand" in placed["o2"].note


def test_the_file_name_settles_two_configurations_of_one_host() -> None:
    placed = group(
        [
            _config("c1", "edge-r1-2026-09-01.cfg", "EDGE-R1"),
            _config("c2", "edge-r2.cfg", "EDGE-R1"),  # copied from R1, never renamed
            _output("o1", "edge-r1_show_version.txt", "EDGE-R1"),
        ]
    )
    assert placed["o1"] == Placement("c1", How.HOSTNAME)


def test_by_hand_wins_and_can_leave_an_output_out() -> None:
    placed = group(
        [
            _config("c1", "a.cfg", "EDGE-R1"),
            _config("c2", "b.cfg", "EDGE-R9"),
            _output("o1", "show_version.txt", "EDGE-R1", manual=True, paired_with="c2"),
            _output("o2", "a_show_inventory.txt", command="show_inventory", manual=True),
        ]
    )
    assert placed["o1"] == Placement("c2", How.HAND)
    assert placed["o2"] == Placement(None, How.HAND, "left out by hand: used in no audit")


def test_a_configuration_takes_a_bounded_number_of_outputs() -> None:
    outputs = [_output(f"o{i}", f"day{i}/r1_version.txt") for i in range(MAX_COMPANIONS + 1)]
    placed = group([_config("c1", "r1.cfg", None), *outputs])
    paired = [o.id for o in outputs if placed[o.id].device == "c1"]
    assert len(paired) == MAX_COMPANIONS
    assert placed[outputs[-1].id].note == f"r1.cfg already has {MAX_COMPANIONS} command outputs"


def test_files_still_being_recognised_and_unrecognised_ones() -> None:
    placed = group(
        [Member("p", "r1.cfg", None), Member("u", "notes.txt", Recognised(Kind.UNKNOWN))]
    )
    assert placed["p"] == Placement(None, None)
    assert placed["u"].device == "u"
    assert placed["u"].how is How.ALONE
