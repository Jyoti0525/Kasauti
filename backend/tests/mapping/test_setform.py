"""Junos ``display set`` exports, read as the brace configuration they stand for (TODO M2.28)."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import pytest

from kasauti.audit import audit, load_kb
from kasauti.ingest.read import read_file
from kasauti.ingest.sort import recognise
from kasauti.mapping.engine import MappingResult, _Engine, apply_mappings
from kasauti.mapping.match import Compiled, tokenize_path
from kasauti.mapping.setform import SetFormReader, is_set_form, parse_config
from kasauti.packs.loader import VendorPack, load_vendor_pack
from kasauti.packs.model import VendorManifest
from kasauti.shape import brace
from kasauti.shape.model import ConfigTree, ShapeFamily
from kasauti.shape.parse import parse_text
from kasauti.shape.tokens import tokenize

REPO = Path(__file__).resolve().parents[3]
JUNOS = REPO / "datasets" / "authored" / "juniper_junos"
ALL_MAPPINGS = Path(__file__).with_name("junos_all_mappings.conf")
"""A brace configuration most of the pack's mappings read, with two ``inactive:`` blocks."""
ALTERNATIVES = (
    # What a second configuration would say instead: single values for lists, a TACACS+ server
    # and filter actions on one line, a zone-wide service, a policy that rejects.
    """system {
    authentication-order password;
    tacplus-server {
        10.0.0.7 secret "$9$PLACEHOLDER";
    }
    services {
        ssh {
            protocol-version v2;
        }
    }
}
firewall {
    filter F {
        term T {
            from {
                port 22;
            }
            then {
                syslog;
                discard;
            }
        }
        term U {
            then reject;
        }
    }
}
security {
    zones {
        security-zone z {
            host-inbound-traffic {
                system-services {
                    any-service;
                }
            }
        }
    }
    policies {
        from-zone a to-zone b {
            policy R {
                then {
                    reject;
                }
            }
        }
    }
}
""",
    "system { services { ssh { protocol-version v1; } } }\n",
    "system { services { ssh { protocol-version [ v2 ]; } } }\n",
)


@pytest.fixture(scope="module")
def junos() -> VendorPack:
    return load_vendor_pack(REPO / "packs" / "vendors" / "juniper_junos")


def display_set(text: str) -> str:
    """``text``, a brace configuration, as ``show configuration | display set`` prints it: one
    ``set`` line per statement, from the top of the hierarchy (Juniper, "Displaying set
    Commands from the Junos OS Configuration"). A list goes one value per line; Kasauti
    reads it in brackets too. ``inactive:`` isn't handled: callers add ``deactivate`` lines."""
    raws = list(brace.parse(text.replace("inactive: ", "")))
    blocks = {r.path[: i + 1] for r in raws for i in range(len(r.path))}
    out = []
    for r in raws:
        if (*r.path, r.text) in blocks:
            continue
        words = tokenize(r.text)
        if words[-1] == "]" and "[" in words:
            at = words.index("[")
            out += [" ".join(("set", *r.path, *words[:at], v)) for v in words[at + 1 : -1]]
        else:
            out.append(" ".join(("set", *r.path, r.text)))
    return "\n".join(out) + "\n"


def _mapped(tree: ConfigTree, pack: VendorPack) -> MappingResult:
    return apply_mappings(
        tree,
        pack.mappings,
        negation_words=pack.manifest.negation_words,
        defaults=pack.defaults.defaults,
        os_version="23.4R1.9",
        pack_id=pack.manifest.id,
    )


def _facts(result: MappingResult) -> str:
    """The SBM without evidence, and without the line numbers some entity keys are made of
    (``community-{@}``): what the configuration says, not where."""

    def strip(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: strip(v) for k, v in o.items() if k != "evidence"}
        if isinstance(o, list):
            return [strip(v) for v in o]
        return o

    dump = strip(result.sbm.model_dump(mode="json"))
    dump["unread"] = sorted(dump["unread"])
    return re.sub(r'"community-\d+"', '"community-N"', json.dumps(dump, indent=1, sort_keys=True))


def _read_by(tree: ConfigTree, pack: VendorPack) -> set[str]:
    """The ids of the mappings that match some statement of ``tree``."""
    engine = _Engine(tree, [Compiled(m, i) for i, m in enumerate(pack.mappings)], frozenset())
    return {
        hit.compiled.mapping.id
        for s in tree.statements
        for hit in engine._hits(s, tokenize_path(s.path))
    }


def _rows(tree: ConfigTree) -> list[tuple[tuple[str, ...], str]]:
    return [(s.path, s.text) for s in tree.statements]


# --- the same configuration, both ways ------------------------------------------------------------


@pytest.mark.parametrize("name", ["hardened", "weak"])
def test_the_display_set_twins_are_their_brace_configs(name: str, junos: VendorPack) -> None:
    """The corpus exports are what :func:`display_set` prints for the brace files, and read
    into the same facts, rule by rule the same verdicts, and the same identity."""
    brace_text = (JUNOS / f"{name}.conf").read_text(encoding="utf-8")
    set_text = (JUNOS / f"{name}_set.conf").read_text(encoding="utf-8")
    assert set_text.split("\n", 2)[2] == display_set(brace_text)

    tree = parse_config(set_text, junos, source_file=f"{name}_set.conf")
    assert tree.family is ShapeFamily.BRACE
    assert tree.rebuilt_from is ShapeFamily.SET_PATH
    assert tree.warnings == ()
    as_brace = parse_config(brace_text, junos, source_file=f"{name}.conf")
    assert as_brace.rebuilt_from is None
    assert _facts(_mapped(tree, junos)) == _facts(_mapped(as_brace, junos))

    kb = load_kb(REPO / "packs")
    by_set = audit(read_file(JUNOS / f"{name}_set.conf"), kb)
    by_brace = audit(read_file(JUNOS / f"{name}.conf"), kb)
    assert by_set.detection.pack_id == "juniper_junos"
    assert by_set.detection.chosen_by == "fingerprint"
    assert by_set.detection.score == by_brace.detection.score
    assert by_set.input.shape_family == "brace"
    assert by_set.input.rebuilt_from == "set_path"
    assert [(r.rule_id, r.status) for r in by_set.rules] == [
        (r.rule_id, r.status) for r in by_brace.rules
    ]
    assert {k: v.value for k, v in by_set.identity.items()} == {
        k: v.value for k, v in by_brace.identity.items()
    }


def test_every_mapping_reads_the_set_form_as_it_reads_braces(junos: VendorPack) -> None:
    """Every mapping in the pack reads one of these configurations, and each gives the same
    facts from its ``display set`` export as from its braces."""
    text = ALL_MAPPINGS.read_text(encoding="utf-8")
    exports = [
        (text, display_set(text) + (
            "deactivate interfaces ge-0/0/2\n"
            "deactivate security policies from-zone trust to-zone untrust policy OLD\n"
        )),
        *((alt, display_set(alt)) for alt in ALTERNATIVES),
    ]  # fmt: skip
    read: set[str] = set()
    for braces, as_set in exports:
        brace_tree = parse_config(braces, junos, source_file="b.conf")
        by_brace = _mapped(brace_tree, junos)
        by_set = _mapped(parse_config(as_set, junos, source_file="s.conf"), junos)
        assert by_set.stats.mapped == by_brace.stats.mapped
        assert _facts(by_set) == _facts(by_brace)
        read |= _read_by(brace_tree, junos)
    assert read == {m.id for m in junos.mappings}


# --- where a line's blocks end --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "blocks", "statement"),
    [
        # A block with settings of its own (Junos prints `host 10.0.0.2 { any notice; }`).
        ("set system syslog host 10.0.0.2 any notice", "system|syslog|host 10.0.0.2", "any notice"),
        # One statement, as Junos prints it (`server 10.0.0.1 key 1;`).
        ("set system ntp server 10.0.0.1 key 1", "system|ntp", "server 10.0.0.1 key 1"),
        ("set routing-options static route 0.0.0.0/0 next-hop 192.0.2.1", "routing-options|static",
         "route 0.0.0.0/0 next-hop 192.0.2.1"),
        # `http` is a statement the pack reads, and a block when it has settings: read as one
        # statement, HTTP would look off (a false PASS the M2.28 review caught).
        ("set system services web-management http interface ge-0/0/0.0",
         "system|services|web-management|http", "interface ge-0/0/0.0"),
        # `filter` continues the interface's context before it could start a firewall filter.
        ("set interfaces lo0 unit 0 family inet filter input PROTECT-RE",
         "interfaces|lo0|unit 0|family inet|filter", "input PROTECT-RE"),
        ("set security policies from-zone trust to-zone untrust policy P then permit",
         "security|policies|from-zone trust to-zone untrust|policy P|then", "permit"),
        # Nothing the pack reads: one statement, as a line no mapping knows.
        ("set protocols ospf area 0.0.0.0 interface ge-0/0/0.0", "",
         "protocols ospf area 0.0.0.0 interface ge-0/0/0.0"),
    ],
)  # fmt: skip
def test_a_line_is_split_where_the_mappings_expect_blocks(
    line: str, blocks: str, statement: str, junos: VendorPack
) -> None:
    got, rest = SetFormReader(junos.mappings).split(tokenize(line)[1:], 1)
    assert "|".join(" ".join(b) for b in got) == blocks
    assert " ".join(rest) == statement


def test_juniper_s_own_example_reads_as_its_brace_form(junos: VendorPack) -> None:
    """Juniper's example of ``display set`` (Junos OS 12.1X46, "Displaying set Commands from
    the Junos OS Configuration"): the brace configuration and the lines it prints, a
    ``deactivate`` line for its inactive unit."""
    braces = """interfaces {
    fe-0/0/0 {
        unit 0 {
            family inet {
                address 192.107.1.230/24;
            }
            family iso;
            family mpls;
        }
        inactive: unit 1 {
            family inet {
                address 10.0.0.1/8;
            }
        }
    }
}
"""
    printed = """set interfaces fe-0/0/0 unit 0 family inet address 192.107.1.230/24
set interfaces fe-0/0/0 unit 0 family iso
set interfaces fe-0/0/0 unit 0 family mpls
set interfaces fe-0/0/0 unit 1 family inet address 10.0.0.1/8
deactivate interfaces fe-0/0/0 unit 1
"""
    tree = parse_config(printed, junos, source_file="s.conf")
    assert _rows(tree) == _rows(parse_text(braces, source_file="b.conf", family=ShapeFamily.BRACE))
    assert [(s.line_start, s.line_end) for s in tree.statements][-1] == (3, 3)


# --- commands other than set ----------------------------------------------------------------------


def test_deleted_and_deactivated_paths_leave_no_statement(junos: VendorPack) -> None:
    text = (
        "set system services telnet\n"
        "set system services ftp\n"
        "set system services finger\n"
        "delete system services telnet\n"
        "deactivate system services ftp\n"
        "set system services telnet\n"  # set again after the delete: there
        "deactivate system services finger\n"
        "activate system services finger\n"
        "protect system services\n"
        'annotate system "edge router"\n'
        "set system login user a class super-user\n"
        "deactivate system login\n"
        "delete system login\n"
        "set system login user b class super-user\n"  # a new login block, active
    )
    tree = parse_config(text, junos, source_file="s.conf")
    assert [s.text for s in tree.statements if s.path == ("system", "services")] == [
        "finger",
        "telnet",
    ]
    assert [(s.path, s.text) for s in tree.statements if "login" in s.path] == [
        (("system", "login"), "user b"),
        (("system", "login", "user b"), "class super-user"),
    ]


def test_a_command_that_reorders_or_renames_is_read_line_by_line(junos: VendorPack) -> None:
    """``insert`` moves a policy before another: which policy matches first depends on it, and
    the lines alone don't show the result. The file is read line by line with the reason, and
    the audit leaves every verdict for review, as for any file its parser can't read."""
    text = (
        "set system host-name R1\n"
        "set system services telnet\n"
        "insert security policies from-zone a to-zone b policy P1 before policy P0\n"
    )
    tree = parse_config(text, junos, source_file="s.conf")
    assert tree.family is ShapeFamily.FLAT
    assert tree.warnings == (
        "not valid set_path syntax (line 3: 'insert' changes the configuration in a way its "
        "lines don't show); parsed line by line instead",
    )


def test_a_list_given_one_value_per_line_is_one_ordered_list(junos: VendorPack) -> None:
    text = (
        "set system authentication-order radius\n"
        "set system authentication-order password\n"
        "set system services ssh protocol-version v2\n"
        "set system ntp trusted-key 1\n"
        "set system ntp trusted-key 2\n"
    )
    rows = _rows(parse_config(text, junos, source_file="s.conf"))
    assert (("system",), "authentication-order [ radius password ]") in rows
    assert (("system", "services", "ssh"), "protocol-version v2") in rows
    # Not an ordered list in the pack: each value is read on its own.
    assert (("system", "ntp"), "trusted-key 1") in rows
    assert (("system", "ntp"), "trusted-key 2") in rows
    bracketed = parse_config(
        "set system authentication-order [ tacplus password ]\n", junos, source_file="s.conf"
    )
    assert _rows(bracketed)[-1] == (("system",), "authentication-order [ tacplus password ]")


def test_a_statement_given_as_a_block_and_as_a_line_is_one_block(junos: VendorPack) -> None:
    text = "set system services ssh\nset system services ssh root-login deny\n"
    assert _rows(parse_config(text, junos, source_file="s.conf")) == [
        ((), "system"),
        (("system",), "services"),
        (("system", "services"), "ssh"),
        (("system", "services", "ssh"), "root-login deny"),
    ]


# --- which files, and which packs ----------------------------------------------------------------


def test_only_a_file_of_set_commands_is_rebuilt(junos: VendorPack) -> None:
    assert is_set_form("# exported\n\nset system host-name R1\n")
    assert not is_set_form("/* c */\nversion 23.4R1.9;\nsystem { host-name R1; }\n")
    assert not is_set_form("")
    brace_text = (JUNOS / "hardened.conf").read_text(encoding="utf-8")
    assert parse_config(brace_text, junos, source_file="h.conf").rebuilt_from is None


def test_only_a_brace_pack_takes_set_commands(junos: VendorPack) -> None:
    data = junos.manifest.model_dump()
    data["shape_family"] = "indent"
    with pytest.raises(ValueError, match="set_form rebuilds a brace tree"):
        VendorManifest.model_validate(data)


def test_an_uploaded_export_is_sorted_as_a_junos_configuration(junos: VendorPack) -> None:
    data = (JUNOS / "weak_set.conf").read_bytes()
    assert recognise(data, {"juniper_junos": junos}, None) == {
        "kind": "config",
        "vendor": "juniper_junos",
        "hostname": "BR-SRX1",
    }


NL = chr(10)
HOSTILE = {
    "a path deeper than the limit": lambda: "set " + "system " * 200_000 + "x" + NL,
    "a line of a million words": lambda: "set system " + "a " * 500_000 + NL,
    "many lines": lambda: ("set system services ssh root-login deny" + NL) * 30_000,
    "a delete and a deactivate after every line": lambda: "".join(
        f"set system login user u{i} class c{NL}delete system login user u{i}{NL}"
        f"deactivate system login user u{i} class{NL}"
        for i in range(20_000)
    ),
}


@pytest.mark.parametrize("why", HOSTILE)
def test_hostile_exports_are_read_in_linear_time(why: str, junos: VendorPack) -> None:
    text = HOSTILE[why]()
    started = time.monotonic()
    tree = parse_config(text, junos, source_file="s.conf")
    assert time.monotonic() - started < 10.0, why
    assert tree.family in (ShapeFamily.BRACE, ShapeFamily.FLAT)
