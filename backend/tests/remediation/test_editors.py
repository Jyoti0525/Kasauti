"""The editors that apply a fix to a copy of a configuration, family by family (PLAN §14.3)."""

from __future__ import annotations

import json

import pytest

from kasauti.packs.model import JsonEdit, Session
from kasauti.remediation.editors import Change, EditError
from kasauti.remediation.editors.blockedit import BlockEditEditor
from kasauti.remediation.editors.indent import IndentEditor
from kasauti.remediation.editors.json_edit import JsonEditor
from kasauti.remediation.editors.setpath import SetPathEditor
from kasauti.remediation.editors.xml_set import XmlSetEditor

IOS = Session(
    enter=("configure terminal",),
    exit=("end",),
    precheck=("show running-config | section {path}",),
    verify=("show running-config | section {path}",),
    kept_negations=("no ip http server", "no ip proxy-arp"),
)
PLAIN = Session(precheck=("show {path}",), verify=("show {path}",))


def change(*lines: str, replaces: tuple[str, ...] = ()) -> Change:
    return Change(lines=lines, stored=lines, replaces=replaces)


# --- indent (IOS, EOS) -----------------------------------------------------------------------

CISCO = """hostname R1
ip http server
interface Gi1
 ip proxy-arp
 description WAN
line vty 0 4
 exec-timeout 0 0
 transport input ssh telnet
end
"""


def test_indent_overwrites_what_it_replaces_and_keeps_order() -> None:
    applied = IndentEditor().apply(
        CISCO, change("line vty 0 4", " exec-timeout 10 0", replaces=("exec-timeout",)), IOS
    )
    assert "exec-timeout 10 0" in applied.text
    assert "exec-timeout 0 0" not in applied.text
    assert applied.replaced == [("line vty 0 4", "exec-timeout 0 0", "exec-timeout 10 0")]
    assert applied.text.rstrip().endswith("end")
    rollback = IndentEditor().rollback(applied, IOS)
    assert rollback == ("configure terminal", "line vty 0 4", " exec-timeout 0 0", " exit", "end")


def test_indent_negation_is_kept_only_where_the_device_keeps_it() -> None:
    kept = IndentEditor().apply(CISCO, change("no ip http server"), IOS)
    assert "no ip http server" in kept.text.splitlines()
    assert "ip http server" not in kept.text.splitlines()
    gone = IndentEditor().apply(CISCO, change("no hostname R1"), IOS)
    assert "hostname" not in gone.text


def test_indent_creates_a_block_and_rolls_it_back_whole() -> None:
    applied = IndentEditor().apply(
        CISCO, change("ip access-list standard MGMT", " 10 permit 10.0.0.0 0.0.0.255"), IOS
    )
    lines = applied.text.splitlines()
    assert lines.index("ip access-list standard MGMT") < lines.index("end")
    assert " 10 permit 10.0.0.0 0.0.0.255" in lines
    assert IndentEditor().rollback(applied, IOS)[-2] == "no ip access-list standard MGMT"


def test_indent_keeps_a_sub_mode_s_depth() -> None:
    applied = IndentEditor().apply(CISCO, change("archive", " log config", "  logging enable"), IOS)
    assert "archive\n log config\n  logging enable" in applied.text


def test_indent_replaces_a_banner_whole() -> None:
    text = "hostname R1\nbanner login ^C\nold notice\n^C\nend\n"
    applied = IndentEditor().apply(text, change("banner login ^C", "New notice.", "^C"), IOS)
    assert "old notice" not in applied.text
    assert "New notice." in applied.text
    assert applied.text.count("banner login") == 1


def test_indent_refuses_an_indented_line_outside_a_block() -> None:
    with pytest.raises(EditError):
        IndentEditor().apply(CISCO, change(" transport input ssh"), IOS)


# --- set path (Junos) ------------------------------------------------------------------------


def test_set_path_deletes_a_whole_branch_and_replaces_a_leaf() -> None:
    text = (
        "set system services telnet\n"
        "set system services ssh\n"
        "set system login password minimum-length 6\n"
    )
    applied = SetPathEditor().apply(
        text,
        change(
            "delete system services telnet",
            "set system login password minimum-length 15",
            replaces=("set system login password minimum-length",),
        ),
        PLAIN,
    )
    assert applied.text.splitlines() == [
        "set system services ssh",
        "set system login password minimum-length 15",
    ]
    assert SetPathEditor().rollback(
        applied, Session(precheck=("x",), verify=("x",), rollback=("rollback 1",))
    ) == ("rollback 1",)


# --- block edit (FortiOS) --------------------------------------------------------------------

FORTI = """config system global
    set admintimeout 480
end
config system proxy-arp
    edit 1
        set interface "wan1"
    next
end
"""


def test_block_edit_sets_unsets_deletes_and_rolls_back() -> None:
    applied = BlockEditEditor().apply(
        FORTI,
        change(
            "config system global",
            "    set admintimeout 10",
            "end",
            "config system proxy-arp",
            "    delete 1",
            "end",
        ),
        PLAIN,
    )
    assert "set admintimeout 10" in applied.text
    assert "480" not in applied.text
    assert "wan1" not in applied.text
    rollback = BlockEditEditor().rollback(applied, PLAIN)
    assert "    set admintimeout 480" in rollback
    assert '        set interface "wan1"' in rollback


def test_block_edit_unsets_settings_of_a_config_block_it_created() -> None:
    applied = BlockEditEditor().apply(
        FORTI, change("config system password-policy", "    set minimum-length 15", "end"), PLAIN
    )
    assert BlockEditEditor().rollback(applied, PLAIN) == (
        "config system password-policy",
        "    unset minimum-length",
        "end",
    )


def test_block_edit_refuses_an_unclosed_block() -> None:
    with pytest.raises(EditError):
        BlockEditEditor().apply(FORTI, change("config system global"), PLAIN)


# --- XML via set commands (PAN-OS) -----------------------------------------------------------

PANOS = """<?xml version="1.0"?>
<config><mgt-config><users><entry name="admin"><phash>$1$x</phash></entry></users></mgt-config>
<shared/><devices><entry name="localhost.localdomain"><deviceconfig><system>
<service><disable-telnet>no</disable-telnet></service>
<ntp-servers><primary-ntp-server><authentication-type><none/></authentication-type>
</primary-ntp-server></ntp-servers></system></deviceconfig>
<vsys><entry name="vsys1"><rulebase><security><rules><entry name="allow-all">
<service><member>any</member></service></entry></rules></security></rulebase></entry></vsys>
</entry></devices></config>
"""


def test_xml_set_follows_lists_members_and_choices() -> None:
    applied = XmlSetEditor().apply(
        PANOS,
        change(
            "set deviceconfig system service disable-telnet yes",
            "set deviceconfig system permitted-ip 192.0.2.0/24",
            "set rulebase security rules allow-all service application-default",
            "set shared server-profile tacplus TACACS server tacacs-1 address 192.0.2.40",
            "set deviceconfig system ntp-servers primary-ntp-server authentication-type "
            "symmetric-key key-id 1",
        ),
        PLAIN,
    )
    text = applied.text
    assert "<disable-telnet>yes</disable-telnet>" in text
    assert "<permitted-ip>\n" in text
    assert '<entry name="192.0.2.0/24"' in text
    assert "<member>application-default</member>" in text
    assert "<member>any</member>" not in text
    assert '<entry name="TACACS">' in text
    assert "<address>192.0.2.40</address>" in text
    assert "<none" not in text
    assert "<key-id>1</key-id>" in text
    assert "set deviceconfig system service disable-telnet no" in XmlSetEditor().rollback(
        applied, PLAIN
    )


def test_xml_delete_is_rolled_back_leaf_by_leaf() -> None:
    applied = XmlSetEditor().apply(PANOS, change("delete rulebase security rules allow-all"), PLAIN)
    assert "allow-all" not in applied.text
    assert "set rulebase security rules allow-all service [ any ]" in XmlSetEditor().rollback(
        applied, PLAIN
    )


# --- JSON (AWS) ------------------------------------------------------------------------------

AWS = {
    "SecurityGroups": [
        {
            "GroupId": "sg-1",
            "IpPermissions": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
            ],
        }
    ],
    "NetworkAcls": [
        {
            "NetworkAclId": "acl-1",
            "Entries": [
                {"RuleNumber": 100, "Egress": True, "Protocol": "-1"},
                {"RuleNumber": 100, "Egress": False, "Protocol": "-1"},
            ],
        }
    ],
}


def test_json_edits_select_by_fields_index_and_nested_values() -> None:
    edits = (
        JsonEdit(
            op="remove",
            at="SecurityGroups{GroupId=sg-1}.IpPermissions",
            where={"IpProtocol": "-1", "IpRanges.CidrIp": "0.0.0.0/0"},
        ),
        JsonEdit(
            op="set",
            at="NetworkAcls{NetworkAclId=acl-1}.Entries{RuleNumber=100,Egress=false}.Protocol",
            value="6",
        ),
        JsonEdit(
            op="append",
            at="SecurityGroups{GroupId=sg-1}.IpPermissions[0].IpRanges",
            value={"CidrIp": "192.0.2.0/24"},
        ),
    )
    applied = JsonEditor().apply(
        json.dumps(AWS), Change(lines=("x",), stored=("x",), edits=edits), PLAIN
    )
    doc = json.loads(applied.text)
    perms = doc["SecurityGroups"][0]["IpPermissions"]
    assert [p["IpProtocol"] for p in perms] == ["tcp"]
    assert perms[0]["IpRanges"][-1] == {"CidrIp": "192.0.2.0/24"}
    assert [e["Protocol"] for e in doc["NetworkAcls"][0]["Entries"]] == ["-1", "6"]


def test_json_remove_that_matches_nothing_is_refused() -> None:
    edits = (
        JsonEdit(
            op="remove",
            at="SecurityGroups{GroupId=sg-1}.IpPermissions",
            where={"IpProtocol": "udp"},
        ),
    )
    with pytest.raises(EditError):
        JsonEditor().apply(json.dumps(AWS), Change(("x",), ("x",), edits=edits), PLAIN)
