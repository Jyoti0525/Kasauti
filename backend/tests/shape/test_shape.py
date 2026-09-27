"""Shape families, detection and pattern keys (PLAN §6; TODO M1.02, M1.03, M2.10-M2.17)."""

from pathlib import Path

import pytest

from kasauti.packs.loader import load_vendor_packs
from kasauti.shape.base import ParseError
from kasauti.shape.detect import detect_family, score_families
from kasauti.shape.model import ShapeFamily as F
from kasauti.shape.parse import parse_text
from kasauti.shape.patterns import pattern_key

REPO = Path(__file__).resolve().parents[3]
DATASETS = REPO / "datasets"
AUTHORED = DATASETS / "authored"
FAMILIES = {v: p.manifest.shape_family for v, p in load_vendor_packs(REPO / "packs").items()}
MARGIN = 0.05
"""How far a corpus file's family must score above the next: a near tie means one more line of
another shape could flip it."""
NOT_CONFIGS = {"SOURCES.md", ".gitkeep", "case.yaml", "expected.json"}
"""Files under ``datasets/`` that aren't configurations: the index, placeholders, and golden
cases (which point at authored files)."""


def _corpus() -> tuple[list[tuple[Path, F]], list[Path]]:
    """Every configuration under ``datasets/``, with the family of the vendor pack whose folder
    it is in; and those in no vendor's folder, which a new corpus must sort before its files
    are tested. Command outputs (``companions/``) aren't configurations."""
    placed, unplaced = [], []
    for path in sorted(DATASETS.rglob("*")):
        if not path.is_file() or path.name in NOT_CONFIGS or "companions" in path.parts:
            continue
        vendors = [part for part in path.relative_to(DATASETS).parts if part in FAMILIES]
        if vendors:
            placed.append((path, FAMILIES[vendors[0]]))
        else:
            unplaced.append(path)
    return placed, unplaced


CORPUS, UNPLACED = _corpus()


def _rows(text: str, family: F) -> list[tuple[tuple[str, ...], str, int, int]]:
    tree = parse_text(text, source_file="t", family=family, fallback=False)
    return [(s.path, s.text, s.line_start, s.line_end) for s in tree.statements]


# --- indent ------------------------------------------------------------------------------------


def test_indent_nesting_separators_and_end() -> None:
    text = (
        "!\nhostname R1\narchive\n log config\n  logging enable\n!\n"
        "line vty 0 4\n transport input ssh\nend\n"
    )
    assert _rows(text, F.INDENT) == [
        ((), "hostname R1", 2, 2),
        ((), "archive", 3, 3),
        (("archive",), "log config", 4, 4),
        (("archive", "log config"), "logging enable", 5, 5),
        ((), "line vty 0 4", 7, 7),
        (("line vty 0 4",), "transport input ssh", 8, 8),
    ]


def test_banner_body_is_one_statement_not_configuration() -> None:
    text = "banner login ^C\nno ip http server\nAuthorised only\n^C\nhostname R1\n"
    assert _rows(text, F.INDENT) == [((), "banner login ^C", 1, 4), ((), "hostname R1", 5, 5)]
    assert _rows("banner motd #Hi there#\nhostname R1\n", F.INDENT)[0] == (
        (),
        "banner motd #Hi there#",
        1,
        1,
    )


def test_eos_banner_runs_to_its_eof_line() -> None:
    text = "banner login\nmanagement telnet\n   no shutdown\nEOF\nhostname L1\n"
    assert _rows(text, F.INDENT) == [((), "banner login", 1, 4), ((), "hostname L1", 5, 5)]
    # Without an EOF line nothing is swallowed: the rest is still read as configuration.
    assert [r[1] for r in _rows("banner login\nhostname L1\n", F.INDENT)] == [
        "banner login",
        "hostname L1",
    ]


def test_crlf_and_tabs_keep_line_numbers() -> None:
    rows = _rows("interface Gi1\r\n\tshutdown\r\n", F.INDENT)
    assert rows == [((), "interface Gi1", 1, 1), (("interface Gi1",), "shutdown", 2, 2)]


# --- brace -------------------------------------------------------------------------------------


def test_brace_blocks_comments_and_inactive() -> None:
    text = (
        "## Last commit\nsystem {\n    host-name R1; # inline\n    /* note */\n"
        "    services {\n        ssh;\n        inactive: telnet;\n    }\n"
        "    inactive: syslog { host 10.0.0.1 { any any; } }\n"
        '    login { message "Authorised; only {staff}"; }\n}\n'
    )
    assert _rows(text, F.BRACE) == [
        ((), "system", 2, 2),
        (("system",), "host-name R1", 3, 3),
        (("system",), "services", 5, 5),
        (("system", "services"), "ssh", 6, 6),
        (("system",), "login", 10, 10),
        (("system", "login"), 'message "Authorised; only {staff}"', 10, 10),
    ]


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("system {\n host-name R1;\n", "never closed"),
        ("host-name R1;\n}\n", "without a matching"),
        ("system { host-name R1 }\n", "missing ';'"),
        ('system { message "open; }\n', "unterminated"),
    ],
)
def test_brace_errors_name_the_line(text: str, message: str) -> None:
    with pytest.raises(ParseError, match=message):
        _rows(text, F.BRACE)


def test_bad_syntax_falls_back_to_flat_with_a_warning() -> None:
    tree = parse_text("system {\n host-name R1;\n", source_file="t", family=F.BRACE)
    assert tree.family is F.FLAT
    assert tree.warnings
    assert "never closed" in tree.warnings[0]
    assert [s.text for s in tree.statements] == ["system {", "host-name R1;"]


def test_authored_junos_config_parses() -> None:
    tree = parse_text(
        (AUTHORED / "juniper_junos/hardened.conf").read_text(encoding="utf-8"),
        source_file="j",
        family=F.BRACE,
        fallback=False,
    )
    assert any(s.path == ("system",) and s.text.startswith("host-name") for s in tree.statements)


# --- set-path, block-edit, path-command, flat ------------------------------------------------


def test_set_path_drops_only_the_set_verb() -> None:
    assert _rows("set system services ssh\ndelete system services telnet\n# c\n", F.SET_PATH) == [
        ((), "system services ssh", 1, 1),
        ((), "delete system services telnet", 2, 2),
    ]


def test_block_edit_nesting_and_multiline_values() -> None:
    text = (
        '#config-version=FGT60F-7.2.8\nconfig system interface\n    edit "wan1"\n'
        '        set allowaccess ping https\n        set description "line one\nline two"\n'
        "    next\nend\nconfig system global\n    set admintimeout 5\nend\n"
    )
    assert _rows(text, F.BLOCK_EDIT) == [
        ((), "config system interface", 2, 2),
        (("config system interface",), 'edit "wan1"', 3, 3),
        (("config system interface", 'edit "wan1"'), "set allowaccess ping https", 4, 4),
        (("config system interface", 'edit "wan1"'), 'set description "line one\nline two"', 5, 6),
        ((), "config system global", 9, 9),
        (("config system global",), "set admintimeout 5", 10, 10),
    ]
    with pytest.raises(ParseError, match="outside"):
        _rows("edit 1\n", F.BLOCK_EDIT)


def test_path_command_both_export_styles_and_continuations() -> None:
    text = (
        "# by RouterOS 7.12\n/ip service\nset telnet disabled=yes\n"
        "/ip service set ssh \\\n    port=2222\n"
    )
    tree = parse_text(text, source_file="t", family=F.PATH_COMMAND, fallback=False)
    rows = [(s.path, s.tokens, s.line_start, s.line_end) for s in tree.statements]
    assert rows == [
        (("/ip service",), ("set", "telnet", "disabled=", "yes"), 3, 3),
        (("/ip service",), ("set", "ssh", "port=", "2222"), 4, 5),
    ]
    quoted = parse_text(
        '/system identity\nset name="core 1"\n', source_file="t", family=F.PATH_COMMAND
    )
    assert quoted.statements[0].tokens == ("set", "name=", '"core 1"')


def test_flat_fallback_is_one_statement_per_line() -> None:
    assert [r[1] for r in _rows("a b\n\n# c\nd\n", F.FLAT)] == ["a b", "d"]


# --- XML and JSON/YAML -------------------------------------------------------------------------


def test_xml_named_entries_leaves_and_lines() -> None:
    text = (
        '<?xml version="1.0"?>\n<config>\n  <entry name="fw 1">\n'
        "    <description>Edge firewall</description>\n    <disable-telnet>yes</disable-telnet>\n"
        "    <ssh/>\n  </entry>\n</config>\n"
    )
    assert _rows(text, F.XML) == [
        ((), "config", 2, 8),
        (("config",), 'entry "fw 1"', 3, 7),
        (("config", 'entry "fw 1"'), 'description "Edge firewall"', 4, 4),
        (("config", 'entry "fw 1"'), "disable-telnet yes", 5, 5),
        (("config", 'entry "fw 1"'), "ssh", 6, 6),
    ]


@pytest.mark.parametrize(
    "text",
    [
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]><x>&b;</x>',
    ],
)
def test_xml_entities_and_dtds_are_refused(text: str) -> None:
    with pytest.raises(ParseError, match="unsafe XML"):
        _rows(text, F.XML)


def test_json_paths_named_items_and_lines() -> None:
    text = (
        '{\n  "DEVICE_METADATA": {"localhost": {"hostname": "leaf1"}},\n'
        '  "rules": [\n    {"name": "allow ssh", "port": 22},\n    {"port": 23}\n  ],\n'
        '  "ntp": ["10.0.0.1"]\n}\n'
    )
    assert _rows(text, F.JSON_YAML) == [
        ((), "DEVICE_METADATA", 2, 2),
        (("DEVICE_METADATA",), "localhost", 2, 2),
        (("DEVICE_METADATA", "localhost"), "hostname leaf1", 2, 2),
        ((), 'rules "allow ssh"', 4, 4),
        (('rules "allow ssh"',), 'name "allow ssh"', 4, 4),
        (('rules "allow ssh"',), "port 22", 4, 4),
        ((), "rules 1", 5, 5),
        (("rules 1",), "port 23", 5, 5),
        ((), "ntp 10.0.0.1", 7, 7),
    ]


def test_yaml_aliases_are_refused() -> None:
    bomb = "a: &a [x, x]\nb: &b [*a, *a]\nc: [*b, *b]\n"
    with pytest.raises(ParseError, match="aliases"):
        _rows(bomb, F.JSON_YAML)


# --- detection and pattern keys ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "family"),
    [
        ((AUTHORED / "cisco_ios_xe/weak.cfg").read_text(encoding="utf-8"), F.INDENT),
        ((AUTHORED / "cisco_ios_xe/hardened.cfg").read_text(encoding="utf-8"), F.INDENT),
        ((AUTHORED / "juniper_junos/hardened.conf").read_text(encoding="utf-8"), F.BRACE),
        ("set system services ssh\nset system host-name R1\n", F.SET_PATH),
        ("config system global\n    set hostname FW\nend\n", F.BLOCK_EDIT),
        ("/ip service\nset telnet disabled=yes\n", F.PATH_COMMAND),
        ("<config><a>1</a></config>\n", F.XML),
        ('{"a": 1}\n', F.JSON_YAML),
        ("hostname: leaf1\nntp:\n  - 10.0.0.1\n", F.JSON_YAML),
        ("just some words\nmore words\n", F.FLAT),
    ],
)
def test_family_detection(text: str, family: F) -> None:
    assert detect_family(text) is family


def test_every_corpus_file_is_in_a_vendor_s_folder() -> None:
    assert len(CORPUS) >= 19, "fewer configurations than the corpus held in v5.1.25: moved?"
    assert UNPLACED == [], "put each under datasets/<corpus>/<vendor pack>/, or say its family"


@pytest.mark.parametrize(
    ("path", "family"), CORPUS, ids=[str(p.relative_to(DATASETS).as_posix()) for p, _ in CORPUS]
)
def test_every_corpus_file_is_detected_as_its_vendor_s_family_by_a_clear_margin(
    path: Path, family: F
) -> None:
    """TODO M2.17: every corpus, as it grows; a file added under a vendor's folder is tested
    here without anyone having to remember to."""
    text = path.read_text(encoding="utf-8")
    assert detect_family(text) is family
    scores = score_families(text)
    runner_up = max(v for f, v in scores.items() if f is not family)
    assert scores[family] - runner_up >= MARGIN, scores


def test_48_interface_blocks_collapse_into_one_pattern() -> None:
    text = "".join(
        f"interface GigabitEthernet1/0/{i}\n description port {i}\n"
        f" switchport access vlan {i + 100}\n"
        for i in range(1, 49)
    )
    tree = parse_text(text, source_file="t", family=F.INDENT)
    headers = {s.pattern_key for s in tree.statements if not s.path}
    vlans = {s.pattern_key for s in tree.statements if s.text.startswith("switchport")}
    assert headers == {"interface <IFNAME>"}
    assert vlans == {"switchport access vlan <INT>"}


def test_different_commands_keep_different_patterns() -> None:
    # Drain-style similarity merging would collapse these two; keyword-literal keys don't.
    assert pattern_key(("ip", "ssh", "version", "2")) == "ip ssh version <INT>"
    assert pattern_key(("ip", "ssh", "time-out", "60")) == "ip ssh time-out <INT>"
    assert pattern_key(("address", "ipv4", "10.0.0.1")) == "address ipv4 <IP>"


def test_pattern_keys_never_carry_secrets() -> None:
    tree = parse_text("username bob password 7 abc123\n", source_file="t", family=F.INDENT)
    assert "abc123" not in (tree.statements[0].pattern_key or "")
