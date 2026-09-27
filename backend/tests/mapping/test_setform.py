"""Junos ``display set`` exports, read as the brace configuration they stand for (TODO M2.28)."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import pytest

from kasauti.audit import audit, load_kb
from kasauti.ingest.read import decode, read_file
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


_BLOCK_ONLY = frozenset(
    f"juniper_junos/{m}"
    for m in (
        # Braces print these as a block and its line; the export's line is the one-line form,
        # which its own mapping reads: `route X { next-hop Y; }` / `route X next-hop Y`.
        "radius-server-secret",
        "tacplus-server-secret",
        "tacplus-server-inline-secret",
        "static-route-block-next-hop",
        "static-route-block-next-hop-interface",
        "static-route-block-qualified-next-hop",
        "static-route-block-qualified-next-hop-interface",
        "term-then-block-accept",
        "term-then-block-reject",
        "term-then-block-discard",
        "term-then-reject",
        "term-then-discard",
        # `protocol-version [ v2 ]` in braces, one value per line in the export.
        "ssh-v2-list",
        "ssh-v2",
    )
)
"""Mappings one form of the same statement uses and the other doesn't."""


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
        set_tree = parse_config(as_set, junos, source_file="s.conf")
        by_brace, by_set = _mapped(brace_tree, junos), _mapped(set_tree, junos)
        # Statement counts may differ (`route X { next-hop Y; }` is two statements, its line
        # one); the facts, and the mappings that give them, may not.
        assert _facts(by_set) == _facts(by_brace)
        assert _read_by(set_tree, junos) - _BLOCK_ONLY == _read_by(brace_tree, junos) - _BLOCK_ONLY
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


def test_insert_rename_and_copy_are_replayed(junos: VendorPack) -> None:
    """Juniper's own examples: the authentication order built with ``insert`` ("show system
    authentication-order" then prints ``authentication-order [ radius tacplus password ];``),
    and an interface copied and renamed."""
    text = (
        "set system authentication-order password\n"
        "delete system authentication-order\n"
        "set system authentication-order radius\n"
        "insert system authentication-order tacplus after radius\n"
        "insert system authentication-order password after tacplus\n"
        "set interfaces lo0 unit 100 family inet address 10.0.0.100/32\n"
        "copy interfaces lo0 unit 100 to unit 101\n"
        "rename interfaces lo0 unit 100 to unit 102\n"
    )
    tree = parse_config(text, junos, source_file="s.conf")
    rows = _rows(tree)
    assert (("system",), "authentication-order [ radius tacplus password ]") in rows
    units = [s.path[2] for s in tree.statements if s.text.startswith("address")]
    assert units == ["unit 102", "unit 101"]
    assert tree.family is ShapeFamily.BRACE
    # No export prints `delete`: this is a change to a configuration the file doesn't hold...
    assert tree.partial == (
        "line 2: 'delete' changes a configuration the file doesn't hold, so the file is a "
        "change to one, not a whole configuration",
    )
    # ...unless it first deletes everything ("Delete everything under this level?").
    whole = parse_config("delete\n" + text, junos, source_file="w.conf")
    assert whole.partial == ()
    assert _rows(whole) == rows


def test_insert_moves_a_term_ahead_and_first_match_follows(junos: VendorPack) -> None:
    """A term inserted before the others decides first: an accept-all moved ahead of the
    management terms opens the device, where the same term at the end is never reached."""
    hardened = (JUNOS / "hardened_set.conf").read_text(encoding="utf-8")
    at_end = hardened + "set firewall family inet filter PROTECT-RE term ANY then accept\n"
    ahead = at_end + (
        "insert firewall family inet filter PROTECT-RE term ANY before term ALLOW-SSH-MGMT\n"
    )

    def lets_anyone_in(text: str) -> object:
        sbm = _mapped(parse_config(text, junos, source_file="f.conf"), junos).sbm
        ref = next(e for e in sbm.entities if e.type == "Reference")
        return ref.permits_any.value  # type: ignore[attr-defined]

    assert lets_anyone_in(hardened) is False
    assert lets_anyone_in(at_end) is False  # after DENY-REST: never reached
    assert lets_anyone_in(ahead) is True
    tree = parse_config(ahead, junos, source_file="a.conf")
    assert tree.order is not None
    terms = [s.text for s in tree.statements if s.text.startswith("term ")]
    assert terms[:2] == ["term ANY", "term ALLOW-SSH-MGMT"]


def test_a_command_naming_what_the_file_lacks_makes_it_partial(junos: VendorPack) -> None:
    text = (
        "set system host-name R1\n"
        "insert security policies from-zone a to-zone b policy P1 before policy P0\n"
        "rename interfaces ge-0/0/9 to ge-0/0/8\n"
    )
    tree = parse_config(text, junos, source_file="s.conf")
    assert tree.family is ShapeFamily.BRACE
    assert tree.partial == (
        "line 2: 'insert' changes a configuration the file doesn't hold, so the file is a "
        "change to one, not a whole configuration",
        "line 2: insert names security policies from-zone a to-zone b policy P1, which isn't "
        "in the file",
        "line 3: rename names interfaces ge-0/0/9, which isn't in the file",
    )


def test_a_command_with_an_unseen_result_is_read_line_by_line(junos: VendorPack) -> None:
    """``load`` and ``rollback`` bring in configuration the file doesn't hold."""
    tree = parse_config("set system host-name R1\nrollback 1\n", junos, source_file="s.conf")
    assert tree.family is ShapeFamily.FLAT
    assert "'rollback' changes the configuration from something the file" in tree.warnings[0]


# --- files that start below the top ---------------------------------------------------------------


def test_juniper_relative_example_is_read_at_its_banner(junos: VendorPack) -> None:
    """Juniper's ``show | display set relative`` sample, as a terminal capture: the banner
    names the level, and ``deactivate unit 1`` is relative too."""
    text = (
        "[edit interfaces xe-0/0/0]\n"
        "user@host# show | display set relative\n"
        "set unit 0 family inet address 192.107.1.230/24\n"
        "set unit 0 family iso\n"
        "set unit 0 family mpls\n"
        "set unit 1 family inet address 10.0.0.1/8\n"
        "deactivate unit 1\n"
        "\n"
        "[edit interfaces xe-0/0/0]\n"
        "user@host#\n"
    )
    tree = parse_config(text, junos, source_file="c.conf")
    rows = _rows(tree)
    assert (("interfaces", "xe-0/0/0", "unit 0", "family inet"), "address 192.107.1.230/24") in rows
    assert not any("unit 1" in s.path for s in tree.statements)
    assert tree.partial == ("line 2: it shows only [edit interfaces xe-0/0/0]",)
    facts = json.loads(_facts(_mapped(tree, junos)))
    assert any(e.get("key") == "xe-0/0/0.0" for e in facts["entities"])


def test_explicit_sets_and_brace_output_from_a_level(junos: VendorPack) -> None:
    """``| display set explicit`` also prints the lines that create each block, and ``show``
    at an edit level prints braces from there; a statement shown by name is itself."""
    explicit = parse_config(
        "[edit interfaces ge-0/0/0]\n"
        "user@host# show | display set explicit\n"
        "set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.254/24\n"
        "set interfaces ge-0/0/0 unit 0 family inet\n"
        "set interfaces ge-0/0/0 unit 0\n",
        junos,
        source_file="e.conf",
    )
    assert _rows(explicit)[-1] == (
        ("interfaces", "ge-0/0/0", "unit 0", "family inet"),
        "address 10.0.1.254/24",
    )
    order = parse_config(
        "[edit]\nuser@host# show system authentication-order\n"
        "authentication-order [ radius tacplus password ];\n",
        junos,
        source_file="o.conf",
    )
    assert _rows(order)[-1] == (("system",), "authentication-order [ radius tacplus password ]")
    assert order.partial == ("line 2: it shows only [edit system authentication-order]",)


def test_a_whole_configuration_in_a_capture_is_not_partial(junos: VendorPack) -> None:
    hardened = (JUNOS / "hardened.conf").read_text(encoding="utf-8")
    as_set = (JUNOS / "hardened_set.conf").read_text(encoding="utf-8")
    plain = _facts(_mapped(parse_config(hardened, junos, source_file="h.conf"), junos))
    for capture in (
        "user@BR-SRX1> show configuration\n" + hardened + "\nuser@BR-SRX1> exit\n",
        "[edit]\nuser@BR-SRX1# show | display set | no-more\n" + as_set,
        # Changes typed, then the whole configuration shown: the output is what counts.
        "[edit]\nuser@BR-SRX1# set system services telnet\n[edit]\n"
        "user@BR-SRX1# rollback 0\nload complete\n[edit]\nuser@BR-SRX1# show\n" + hardened,
    ):
        tree = parse_config(capture, junos, source_file="c.conf")
        assert tree.partial == (), capture[:40]
        assert _facts(_mapped(tree, junos)) == plain


def test_filtered_denied_or_answered_output_is_partial(junos: VendorPack) -> None:
    cases = {
        "user@h> show configuration | display set | match address\n"
        "set interfaces lo0 unit 0 family inet address 127.0.0.1/32\n": "filtered",
        "set system host-name R1\nset system login user ACCESS-DENIED\n": "ACCESS-DENIED",
        "[edit]\nuser@h# set system services telnet\nerror: syntax error\n": "answered",
        "[edit]\nuser@h# set system services telnet\n": "never shows the whole",
    }
    for text, why in cases.items():
        tree = parse_config(text, junos, source_file="c.conf")
        assert tree.family is ShapeFamily.BRACE, text
        assert any(why in p for p in tree.partial), (text, tree.partial)


def test_commands_without_a_banner_are_read_at_the_level_they_fit(junos: VendorPack) -> None:
    """Juniper's examples paste commands at an edit level ("at the [edit policy-options]
    hierarchy level"). With no banner, the level is the one the pack's mappings allow for every
    first word, if only one does."""
    text = "set host-name R1\nset services telnet\nset services ssh root-login allow\n"
    tree = parse_config(text, junos, source_file="r.conf")
    assert (("system", "services"), "telnet") in _rows(tree)
    assert tree.partial == ("its commands are relative to [edit system]",)
    braces = parse_config(
        "host-name R1;\nservices {\n    telnet;\n}\n", junos, source_file="b.conf"
    )
    assert (("system", "services"), "telnet") in _rows(braces)
    assert braces.partial == ("its statements are from [edit system], not the top",)
    # From the top, nothing is inferred.
    top = parse_config("set system services telnet\n", junos, source_file="t.conf")
    assert top.partial == ()


def test_edit_up_and_top_move_the_level(junos: VendorPack) -> None:
    text = (
        "edit system services\n"
        "set telnet\n"
        "up\n"
        "set host-name R1\n"
        "top\n"
        "edit snmp\n"
        "top set system login message hi\n"
        "set community public authorization read-only\n"
        "exit\n"
        "set system ntp server 10.0.0.1\n"
    )
    rows = _rows(parse_config(text, junos, source_file="e.conf"))
    for row in (
        (("system", "services"), "telnet"),
        (("system",), "host-name R1"),
        (("system", "login"), "message hi"),
        (("snmp", "community public"), "authorization read-only"),
        (("system", "ntp"), "server 10.0.0.1"),
    ):
        assert row in rows, row


def test_a_partial_file_passes_nothing_it_doesnt_show() -> None:
    """Shown from [edit system]: telnet in it still fails; nothing passes, since the rest of
    the configuration could change it. The fingerprint reads it from the top."""
    kb = load_kb(REPO / "packs")
    text = (
        "[edit system]\n"
        "user@host# show | display set relative\n"
        "set host-name R9\n"
        "set authentication-order password\n"
        "set services telnet\n"
        "set services ssh protocol-version v2\n"
        "set services ssh root-login deny\n"
    )
    result = audit(decode(text.encode(), "frag.conf"), kb)
    assert result.detection.pack_id == "juniper_junos"
    assert result.detection.chosen_by == "fingerprint"
    statuses = _statuses(result)
    assert "PASS" not in statuses.values()
    assert statuses["MGMT-TELNET-01"] == "FAIL"
    assert any("only part of a configuration" in w for w in result.warnings)


def test_bracket_lists_read_the_same_in_both_forms(junos: VendorPack) -> None:
    """``application [ junos-ssh junos-telnet ]`` is two applications; in braces it was left
    unread, so the policy's service was unknown."""
    braces = (
        "security { policies { from-zone trust to-zone untrust { policy P {\n"
        "    match { source-address any; destination-address any;\n"
        "        application [ junos-ssh junos-telnet ]; }\n"
        "    then { permit; } } } } }\n"
    )
    head = "set security policies from-zone trust to-zone untrust policy P "
    as_set = "".join(
        head + tail + "\n"
        for tail in (
            "match source-address any",
            "match destination-address any",
            "match application junos-ssh",
            "match application junos-telnet",
            "then permit",
        )
    )
    bracketed = "".join(
        head + tail + "\n"
        for tail in (
            "match source-address any",
            "match destination-address any",
            "match application [junos-ssh junos-telnet]",
            "then permit",
        )
    )
    got = [
        _facts(_mapped(parse_config(t, junos, source_file="p.conf"), junos))
        for t in (braces, as_set, bracketed)
    ]
    assert got[0] == got[1] == got[2]
    rule = next(e for e in json.loads(got[0])["entities"] if e["type"] == "FilterRule")
    assert rule["service"]["value"] == ["junos-ssh", "junos-telnet"]


def test_routes_by_interface_and_qualified_next_hops(junos: VendorPack) -> None:
    text = (
        "routing-options { static {\n"
        "    route 0.0.0.0/0 { next-hop [ 198.51.100.1 st0.0 ]; qualified-next-hop 203.0.113.1 {\n"
        "        preference 7; } }\n"
        "} }\n"
    )
    facts = json.loads(_facts(_mapped(parse_config(text, junos, source_file="r.conf"), junos)))
    route = next(e for e in facts["entities"] if e["type"] == "Route")
    assert route["next_hops"]["value"] == ["198.51.100.1", "203.0.113.1"]
    assert route["interface"]["value"] == "st0.0"


def _statuses(result: Any) -> dict[str, str]:
    return {r.rule_id: r.status.value for r in result.rules}


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
    "an insert after every line": lambda: "".join(
        f"set firewall filter F term T{i} then accept{NL}"
        f"insert firewall filter F term T{i} before term T0{NL}"
        for i in range(3_000)
    ),
    "a rename after every line": lambda: "".join(
        f"set interfaces ge-0/0/0 unit {i} family inet{NL}"
        f"rename interfaces ge-0/0/0 unit {i} to unit {i + 100_000}{NL}"
        for i in range(20_000)
    ),
    "a copy on every line": lambda: (
        "set system services ssh"
        + NL
        + "".join(f"copy system services to services{i}{NL}" for i in range(20_000))
    ),
    "a prompt on every line": lambda: f"[edit]{NL}user@h# set system services telnet{NL}" * 20_000,
    "paths of many lengths": lambda: "".join(
        "set " + "a " * i + NL + "delete " + "a " * i + NL for i in range(1, 200)
    ),
}


@pytest.mark.parametrize("why", HOSTILE)
def test_hostile_exports_are_read_in_linear_time(why: str, junos: VendorPack) -> None:
    text = HOSTILE[why]()
    started = time.monotonic()
    tree = parse_config(text, junos, source_file="s.conf")
    assert time.monotonic() - started < 10.0, why
    assert tree.family in (ShapeFamily.BRACE, ShapeFamily.FLAT)
