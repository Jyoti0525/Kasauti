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
    statuses = {r.rule_id: r.status for r in result.rules}
    # The weak config references no ACL or object, so the reference rules have nothing to judge.
    assert statuses.pop("REF-DANGLING-01") is Status.NOT_APPLICABLE
    assert statuses.pop("MGMT-VTY-ACL-02") is Status.NOT_APPLICABLE
    assert set(statuses.values()) == {Status.FAIL}
    telnet = next(f for f in result.findings if f.rule_id == "MGMT-TELNET-01")
    # The vty lines that allow Telnet, plus the WAN interface that makes it Critical (§12.7).
    assert {49, 53, 54, 57} <= {e.line_start for e in telnet.evidence}
    assert telnet.severity == "critical"
    assert telnet.severity_reason is not None
    assert telnet.severity_reason.startswith("High (base) → Critical")
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
    # MikroTik is deliberately never a seed vendor: it is the unseen-vendor demo (§20.4).
    mikrotik = b"# by RouterOS 7.12\n/ip service\nset telnet disabled=yes\n"
    with pytest.raises(AuditError, match="can't tell which vendor"):
        audit(decode(mikrotik, "routeros.rsc"), kb)
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


def test_zone_wide_telnet_on_junos_is_seen(kb: KnowledgeBase) -> None:
    """Host-inbound services granted to a whole zone must count, not read as "not reachable"."""
    text = (
        "version 23.4R1.9;\nsystem { host-name X; services { ssh; } }\nsecurity { zones { "
        "security-zone untrust { host-inbound-traffic { system-services { telnet; } } "
        "interfaces { ge-0/0/0.0; } } } }\n"
    )
    result = audit(decode(text.encode(), "zone.conf"), kb, vendor="juniper_junos")
    assert {r.rule_id: r.status for r in result.rules}["MGMT-TELNET-01"] is Status.FAIL


def test_eos_identity_comes_from_the_running_config_header(kb: KnowledgeBase) -> None:
    result = audit(read_file(REPO / "datasets" / "authored" / "arista_eos" / "hardened.cfg"), kb)
    assert result.detection.pack_id == "arista_eos"
    version, model = result.identity["os_version"], result.identity["model"]
    assert (version.value, model.value) == ("4.30.1F", "DCS-7050SX3-48YC8")
    assert version.source == "config line 2"  # the `! device:` comment, not a command


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("aaa accounting commands all default start-stop logging", Status.PASS),
        ("aaa accounting commands all default start-stop group TAC", Status.PASS),
        # Console-only accounting misses every SSH session: not a record of all changes.
        ("aaa accounting commands all console start-stop logging", Status.REVIEW),
    ],
)
def test_eos_command_accounting_records_config_changes(
    kb: KnowledgeBase, line: str, expected: Status
) -> None:
    text = f"! device: L1 (DCS-7050SX3-48YC8, EOS-4.30.1F)\nhostname L1\n{line}\n"
    result = audit(decode(text.encode(), "acct.cfg"), kb, vendor="arista_eos")
    assert {r.rule_id: r.status for r in result.rules}["LOG-CONFIG-CHANGE-01"] is expected


def test_eos_banner_text_is_never_read_as_configuration(kb: KnowledgeBase) -> None:
    text = (
        "! device: L1 (DCS-7050SX3-48YC8, EOS-4.30.1F)\nhostname L1\n"
        "interface Ethernet1\n   description LAN\nmanagement ssh\n   idle-timeout 10\n"
        "banner login\nmanagement telnet\n   no shutdown\nEOF\n"
    )
    result = audit(decode(text.encode(), "banner.cfg"), kb, vendor="arista_eos")
    statuses = {r.rule_id: r.status for r in result.rules}
    assert statuses["MGMT-TELNET-01"] is Status.PASS  # Telnet off by default; the banner is text
    assert statuses["MGMT-BANNER-01"] is Status.PASS


def test_junos_predefined_classes_never_time_out(kb: KnowledgeBase) -> None:
    text = (
        "version 23.4R1.9;\nsystem { login { user a { class super-user; authentication "
        '{ encrypted-password "$6$x$y"; } } } }\n'
    )
    result = audit(decode(text.encode(), "cls.conf"), kb, vendor="juniper_junos")
    timeout = next(f for f in result.findings if f.rule_id == "MGMT-SESSION-TIMEOUT-01")
    assert timeout.status is Status.FAIL
    assert timeout.defaults_used == ("juniper_junos/defaults.yaml#class-never-times-out",)


FGT_HEADER = "#config-version=FGT60F-7.4.8-FW-build2795-250523:opmode=0:vdom=0:user=admin\n"


def _fortios(kb: KnowledgeBase, body: str) -> dict[str, Status]:
    result = audit(decode((FGT_HEADER + body).encode(), "fgt.conf"), kb, vendor="fortinet_fortios")
    return {r.rule_id: r.status for r in result.rules}


def test_fortios_identity_comes_from_the_config_version_header(kb: KnowledgeBase) -> None:
    path = REPO / "datasets" / "authored" / "fortinet_fortios" / "hardened.conf"
    result = audit(read_file(path), kb)
    assert result.detection.pack_id == "fortinet_fortios"
    ident = result.identity
    assert (ident["hostname"].value, ident["os_version"].value, ident["model"].value) == (
        "FGT-EDGE",
        "7.4.8",
        "FGT60F",
    )


POLICY = (
    'config firewall policy\n    edit 1\n        set srcintf "wan1"\n'
    '        set dstintf "internal"\n        set action accept\n'
    '        set srcaddr "all"\n        set dstaddr "{dst}"\n        set service "ALL"\n'
    "    next\nend\n"
)


@pytest.mark.parametrize(
    ("objects", "expected"),
    [
        # A host object: not a permit-any.
        ('    edit "SRV"\n        set subnet 10.0.0.1 255.255.255.255\n    next\n', Status.PASS),
        # A catch-all hidden behind a name is still a permit-any.
        ('    edit "SRV"\n        set subnet 0.0.0.0 0.0.0.0\n    next\n', Status.FAIL),
        # An object whose extent wasn't read (a dynamic address): REVIEW, never an assumed PASS.
        ('    edit "SRV"\n        set type dynamic\n    next\n', Status.REVIEW),
    ],
)
def test_fortios_policies_see_through_address_objects(
    kb: KnowledgeBase, objects: str, expected: Status
) -> None:
    body = "config firewall address\n" + objects + "end\n" + POLICY.format(dst="SRV")
    assert _fortios(kb, body)["FILTER-PERMIT-ANY-01"] is expected


def test_fortios_catch_all_inside_an_address_group_is_found(kb: KnowledgeBase) -> None:
    body = (
        'config firewall address\n    edit "WIDE"\n        set subnet 0.0.0.0 0.0.0.0\n'
        '    next\n    edit "SRV"\n        set subnet 10.0.0.1 255.255.255.255\n    next\nend\n'
        'config firewall addrgrp\n    edit "GRP"\n        set member "SRV" "WIDE"\n    next\nend\n'
        + POLICY.format(dst="GRP")
    )
    assert _fortios(kb, body)["FILTER-PERMIT-ANY-01"] is Status.FAIL


SERVICE_POLICY = (
    "config firewall service custom\n"
    '    edit "SVC"\n{svc}    next\nend\n'
    "config firewall service group\n"
    '    edit "GRP"\n        set member "SVC"\n    next\nend\n'
    'config firewall policy\n    edit 1\n        set srcintf "wan1"\n'
    '        set dstintf "internal"\n        set action accept\n'
    '        set srcaddr "all"\n        set dstaddr "all"\n        set service "{name}"\n'
    "    next\nend\n"
)


@pytest.mark.parametrize(
    ("svc", "name", "expected"),
    [
        # Every IP protocol behind a custom name is still a permit-all, alone or in a group.
        ("        set protocol IP\n", "SVC", Status.FAIL),
        ("        set protocol IP\n", "GRP", Status.FAIL),
        ("        set protocol IP\n        set protocol-number 0\n", "SVC", Status.FAIL),
        # A protocol number narrows it (GRE), as do port ranges.
        ("        set protocol IP\n        set protocol-number 47\n", "SVC", Status.PASS),
        ("        set tcp-portrange 443\n", "GRP", Status.PASS),
        # A service whose extent wasn't read: REVIEW, never an assumed PASS.
        ('        set category "General"\n', "SVC", Status.REVIEW),
    ],
)
def test_fortios_policies_see_through_service_objects(
    kb: KnowledgeBase, svc: str, name: str, expected: Status
) -> None:
    body = SERVICE_POLICY.format(svc=svc, name=name)
    assert _fortios(kb, body)["FILTER-PERMIT-ANY-01"] is expected


ADMINS = 'config system admin\n    edit "a"\n{a}    next\n    edit "b"\n{b}    next\nend\n'
V4 = "        set trusthost1 10.30.10.0 255.255.255.0\n"
V6 = "        set ip6-trusthost1 fd00:30:10::/64\n"


@pytest.mark.parametrize(
    ("b", "expected"),
    [
        (V4 + V6, Status.PASS),
        # Restricting only IPv4 leaves IPv6 open from anywhere (ip6-trusthost defaults to ::/0).
        (V4, Status.FAIL),
        # An account without trusted hosts (a password-less wildcard admin, say) opens it all.
        ("        set remote-auth enable\n        set wildcard enable\n", Status.FAIL),
        ("        set trusthost1 0.0.0.0 0.0.0.0\n" + V6, Status.FAIL),
    ],
)
def test_fortios_web_management_is_restricted_only_if_every_admin_is(
    kb: KnowledgeBase, b: str, expected: Status
) -> None:
    assert _fortios(kb, ADMINS.format(a=V4 + V6, b=b))["MGMT-WEB-ACL-01"] is expected


def test_trusted_host_inference_never_fires_on_platforms_without_them(kb: KnowledgeBase) -> None:
    config = b"version 17.9\nhostname R1\nusername a privilege 15 secret 9 $9$x\nip http server\n"
    cisco = audit(decode(config, "r.cfg"), kb, vendor="cisco_ios_xe")
    assert {r.rule_id: r.status for r in cisco.rules}["MGMT-WEB-ACL-01"] is Status.FAIL


@pytest.mark.parametrize(
    ("ntp", "expected"),
    [
        # No `ntpsync enable` (the default is disable): the clock isn't set from NTP at all.
        ("config system ntp\n    set type custom\nend\n", Status.NOT_APPLICABLE),
        # FortiGuard's servers with NTP authentication left at its default (disable).
        ("config system ntp\n    set ntpsync enable\nend\n", Status.FAIL),
        # Authentication on, but Fortinet doesn't say whether it covers FortiGuard's servers.
        (
            "config system ntp\n    set ntpsync enable\n    set authentication enable\nend\n",
            Status.REVIEW,
        ),
    ],
)
def test_fortios_fortiguard_time_source_is_judged(
    kb: KnowledgeBase, ntp: str, expected: Status
) -> None:
    assert _fortios(kb, ntp)["TIME-NTP-AUTH-01"] is expected


@pytest.mark.parametrize(
    ("block", "rule", "expected"),
    [
        # A value set while its feature is switched off doesn't count.
        (
            'config log syslogd setting\n    set server "10.0.0.5"\nend\n',
            "LOG-REMOTE-01",
            Status.FAIL,
        ),
        (
            'config log syslogd setting\n    set status enable\n    set server "10.0.0.5"\nend\n',
            "LOG-REMOTE-01",
            Status.PASS,
        ),
        (
            "config system password-policy\n    set minimum-length 15\nend\n",
            "AAA-PASSWORD-MIN-LENGTH-01",
            Status.FAIL,
        ),
        (
            "config system password-policy\n    set status enable\n"
            "    set minimum-length 15\nend\n",
            "AAA-PASSWORD-MIN-LENGTH-01",
            Status.PASS,
        ),
    ],
)
def test_fortios_on_switches_are_respected(
    kb: KnowledgeBase, block: str, rule: str, expected: Status
) -> None:
    assert _fortios(kb, block)[rule] is expected


def test_a_documented_protective_default_passes_where_absence_would_fail(
    kb: KnowledgeBase,
) -> None:
    """FortiOS locks administrators out after 3 failures by default (on_no_default: fail)."""
    result = audit(
        decode((FGT_HEADER + "config system global\nend\n").encode(), "fgt.conf"),
        kb,
        vendor="fortinet_fortios",
    )
    lockout = next(f for f in result.findings if f.rule_id == "AAA-LOCKOUT-01")
    assert lockout.status is Status.PASS
    assert lockout.defaults_used == (
        "fortinet_fortios/defaults.yaml#lockout-60-seconds",
        "fortinet_fortios/defaults.yaml#lockout-after-3",
    )
    # Cisco documents no lockout default, so there absence is still the violation.
    cisco = audit(decode(b"version 17.9\nhostname R1\n", "r.cfg"), kb, vendor="cisco_ios_xe")
    assert {r.rule_id: r.status for r in cisco.rules}["AAA-LOCKOUT-01"] is Status.FAIL


# --- PAN-OS (XML) ------------------------------------------------------------------------------

PANOS = """<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks" detail-version="11.1.2">
  <mgt-config>{mgt}</mgt-config>
  <devices>
    <entry name="localhost.localdomain">
      <network>{network}</network>
      <deviceconfig>
        <system>{system}</system>
        <setting><management>{management}</management></setting>
      </deviceconfig>
      <vsys><entry name="vsys1">{vsys}</entry></vsys>
    </entry>
  </devices>
</config>
"""


def _panos(kb: KnowledgeBase, **parts: str) -> dict[str, Status]:
    fields = {k: parts.get(k, "") for k in ("mgt", "network", "system", "management", "vsys")}
    text = PANOS.format(**fields)
    result = audit(decode(text.encode(), "running-config.xml"), kb)
    assert result.detection.pack_id == "paloalto_panos"
    return {r.rule_id: r.status for r in result.rules}


def test_panos_identity_comes_from_the_config_root_and_system(kb: KnowledgeBase) -> None:
    path = REPO / "datasets" / "authored" / "paloalto_panos" / "hardened.xml"
    result = audit(read_file(path), kb)
    assert result.detection.pack_id == "paloalto_panos"
    ident = result.identity
    assert (ident["hostname"].value, ident["os_version"].value) == ("PA-EDGE", "11.1.2")


def _rule(**members: str) -> str:
    base = {
        "source": "any",
        "destination": "any",
        "application": "any",
        "service": "any",
    }
    base.update(members)
    body = "".join(f"<{k}><member>{v}</member></{k}>" for k, v in base.items())
    extra = members.get("extra", "")
    return (
        "<rulebase><security><rules><entry name='r1'><from><member>untrust</member></from>"
        f"<to><member>trust</member></to>{body}<action>allow</action>{extra}"
        "</entry></rules></security></rulebase>"
    ).replace("<extra><member></member></extra>", "")


@pytest.mark.parametrize(
    ("members", "expected"),
    [
        ({}, Status.FAIL),
        # Application-default ports for every application is still everything.
        ({"service": "application-default"}, Status.FAIL),
        # Naming the applications narrows the rule even with service any.
        ({"application": "ssl"}, Status.PASS),
        ({"destination": "10.20.0.10"}, Status.PASS),
        # "Everything except X" is taken as any.
        (
            {"destination": "10.20.0.10", "extra": "<negate-destination>yes</negate-destination>"},
            Status.FAIL,
        ),
        # A disabled rule filters nothing either way.
        ({"extra": "<disabled>yes</disabled>"}, Status.PASS),
    ],
)
def test_panos_permit_all_needs_every_application_and_an_enabled_rule(
    kb: KnowledgeBase, members: dict[str, str], expected: Status
) -> None:
    assert _panos(kb, vsys=_rule(**members))["FILTER-PERMIT-ANY-01"] is expected


PROFILE_WEB = (
    "<profiles><interface-management-profile><entry name='WEB'><https>yes</https>"
    "</entry></interface-management-profile></profiles>"
)


@pytest.mark.parametrize(
    ("system", "network", "expected"),
    [
        # The MGT port accepts any address unless permitted IPs are listed.
        ("<service><disable-https>no</disable-https></service>", "", Status.FAIL),
        (
            "<service><disable-https>no</disable-https><disable-http>yes</disable-http></service>"
            "<permitted-ip><entry name='10.30.10.0/24'/></permitted-ip>",
            "",
            Status.PASS,
        ),
        (
            "<service><disable-https>no</disable-https></service>"
            "<permitted-ip><entry name='0.0.0.0/0'/></permitted-ip>",
            "",
            Status.FAIL,
        ),
        # A profile offering HTTPS on a data interface isn't covered by the MGT port's list,
        # whichever comes first in the file.
        (
            "<service><disable-https>yes</disable-https></service>"
            "<permitted-ip><entry name='10.30.10.0/24'/></permitted-ip>",
            PROFILE_WEB,
            Status.FAIL,
        ),
    ],
)
def test_panos_web_management_sources(
    kb: KnowledgeBase, system: str, network: str, expected: Status
) -> None:
    got = _panos(kb, system=system, network=network)["MGMT-WEB-ACL-01"]
    assert got is expected


@pytest.mark.parametrize(
    ("lockout", "expected"),
    [
        ("", Status.FAIL),  # Failed Attempts defaults to 0: unlimited
        ("<admin-lockout><failed-attempts>5</failed-attempts></admin-lockout>", Status.FAIL),
        (
            "<admin-lockout><failed-attempts>5</failed-attempts>"
            "<lockout-time>30</lockout-time></admin-lockout>",
            Status.PASS,
        ),
    ],
)
def test_panos_lockout_needs_attempts_and_a_duration(
    kb: KnowledgeBase, lockout: str, expected: Status
) -> None:
    """Palo Alto documents Lockout Time 0 both as "until unlocked" and "never locked out"."""
    assert _panos(kb, management=lockout)["AAA-LOCKOUT-01"] is expected


def test_panos_telnet_in_a_profile_counts_even_if_the_mgt_port_disables_it(
    kb: KnowledgeBase,
) -> None:
    profile = (
        "<profiles><interface-management-profile><entry name='OLD'><telnet>yes</telnet>"
        "</entry></interface-management-profile></profiles>"
    )
    system = "<service><disable-telnet>yes</disable-telnet></service>"
    assert _panos(kb, system=system, network=profile)["MGMT-TELNET-01"] is Status.FAIL
    # With an interface read (and no profile on it), Telnet is known to be unreachable.
    interface = (
        "<interface><ethernet><entry name='ethernet1/1'><layer3/></entry></ethernet></interface>"
    )
    assert _panos(kb, system=system, network=interface)["MGMT-TELNET-01"] is Status.PASS


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        ("<none/>", Status.FAIL),
        ("<symmetric-key><key-id>1</key-id></symmetric-key>", Status.PASS),
        ("<autokey/>", Status.REVIEW),  # not mapped: Autokey isn't judged either way
    ],
)
def test_panos_ntp_authentication(kb: KnowledgeBase, auth: str, expected: Status) -> None:
    system = (
        "<ntp-servers><primary-ntp-server><ntp-server-address>10.0.0.1</ntp-server-address>"
        f"<authentication-type>{auth}</authentication-type></primary-ntp-server></ntp-servers>"
    )
    assert _panos(kb, system=system)["TIME-NTP-AUTH-01"] is expected
