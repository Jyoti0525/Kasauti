"""Secret masking, reviewed vendor by vendor (TODO M2.08).

Each case is a statement as the parser hands it over (its block path, then its text), with the
text a report may show. Secret values are planted as ``S3CRET`` (or a hash) so a miss is plain;
the kind of secret stays visible, and so does everything that isn't one: a key's number, a
password policy, the name of a key chain.

Syntax was checked against the vendors' own references where it is less common:

- Cisco ``snmp-server host {addr} [vrf name | informs | traps | version {1|2c|3 [auth|noauth|priv]}]
  community-string``: SNMP Command Reference, Cisco IOS XE (cisco.com, nm-snmp-cr-book).
- Cisco IKEv2 keyring ``pre-shared-key local key1`` / ``pre-shared-key remote key2``: Security
  and VPN Configuration Guide, Cisco IOS XE 17, "Configuring Internet Key Exchange Version 2".
- Cisco ``key config-key password-encryption`` (the master key for type 6 passwords): "Encrypted
  Preshared Key", Internet Key Exchange for IPsec VPNs Configuration Guide, Cisco IOS XE.
- Cisco ``standby [group] authentication {text string | md5 {key-string [0|7] key | key-chain
  name}}``: Cisco IOS First Hop Redundancy Protocols Command Reference.
- Arista type ``8a`` (AES-256-GCM) secrets: Arista AVD encrypt/decrypt filter documentation.
- Junos ``authentication-key key-number type type value password`` at ``[edit system ntp]``:
  Junos OS, "NTP Authentication Keys" (juniper.net).
- FortiOS ``config system snmp community`` / ``edit <id>`` / ``set name`` (the community string)
  and ``config system snmp user`` ``set auth-pwd`` / ``set priv-pwd``: FortiOS CLI Reference,
  6.2 to 8.0 (docs.fortinet.com).
"""

from __future__ import annotations

import pytest

from kasauti.ingest.mask import MASK, mask_secrets

M = MASK
Case = tuple[tuple[str, ...], str, str]

CISCO: list[Case] = [
    ((), "enable secret 9 $9$salt$hash", f"enable secret 9 {M}"),
    ((), "enable secret level 15 5 $1$salt$hash", f"enable secret level 15 5 {M}"),
    ((), "enable password level 15 0 S3CRET", f"enable password level 15 0 {M}"),
    (
        (),
        "username u privilege 15 algorithm-type scrypt secret $9$salt$hash",
        f"username u privilege 15 algorithm-type scrypt secret {M}",
    ),
    ((), "username u password 7 0822455D0A16", f"username u password 7 {M}"),
    (("line vty 0 4",), "password 7 0822455D0A16", f"password 7 {M}"),
    ((), "snmp-server community S3CRET RO 10", f"snmp-server community {M} RO 10"),
    ((), "snmp-server community S3CRET view V1 RW", f"snmp-server community {M} view V1 RW"),
    ((), "snmp-server host 192.0.2.1 S3CRET", f"snmp-server host 192.0.2.1 {M}"),
    (
        (),
        "snmp-server host 192.0.2.1 version 2c S3CRET udp-port 2012",
        f"snmp-server host 192.0.2.1 version 2c {M} udp-port 2012",
    ),
    (
        (),
        "snmp-server host 192.0.2.1 vrf MGMT informs version 2c S3CRET",
        f"snmp-server host 192.0.2.1 vrf MGMT informs version 2c {M}",
    ),
    (
        (),
        "snmp-server host example.com vrf trap-vrf S3CRET",
        f"snmp-server host example.com vrf trap-vrf {M}",
    ),
    (
        (),
        "snmp-server host 192.0.2.1 version 3 priv nmsuser",
        "snmp-server host 192.0.2.1 version 3 priv nmsuser",
    ),
    (
        (),
        "snmp-server host 192.0.2.1 vrf MGMT version 3 auth nmsuser",
        "snmp-server host 192.0.2.1 vrf MGMT version 3 auth nmsuser",
    ),
    (
        (),
        "snmp-server user u g v3 auth sha S3CRET priv aes 128 S3CRET",
        f"snmp-server user u g v3 auth sha {M} priv aes 128 {M}",
    ),
    ((), "crypto isakmp key S3CRET address 192.0.2.1", f"crypto isakmp key {M} address 192.0.2.1"),
    (
        (),
        "crypto isakmp key 6 S3CRET address 192.0.2.1",
        f"crypto isakmp key 6 {M} address 192.0.2.1",
    ),
    (("crypto ikev2 keyring K", "peer p1"), "pre-shared-key S3CRET", f"pre-shared-key {M}"),
    (
        ("crypto ikev2 keyring K", "peer p1"),
        "pre-shared-key local S3CRET",
        f"pre-shared-key local {M}",
    ),
    (
        ("crypto ikev2 keyring K", "peer p1"),
        "pre-shared-key remote 6 S3CRET",
        f"pre-shared-key remote 6 {M}",
    ),
    ((), "key config-key password-encryption S3CRET", f"key config-key password-encryption {M}"),
    ((), "key config-key password-encryption", "key config-key password-encryption"),
    (("tacacs server T1",), "key 7 S3CRET", f"key 7 {M}"),
    ((), "radius-server host 192.0.2.1 key S3CRET", f"radius-server host 192.0.2.1 key {M}"),
    (
        ("interface Gi1",),
        "ip ospf authentication-key 7 S3CRET",
        f"ip ospf authentication-key 7 {M}",
    ),
    (
        ("interface Gi1",),
        "ip ospf message-digest-key 1 md5 7 S3CRET",
        f"ip ospf message-digest-key 1 md5 7 {M}",
    ),
    (
        ("interface Gi1",),
        "ip ospf authentication message-digest",
        "ip ospf authentication message-digest",
    ),
    (
        ("router bgp 65000",),
        "neighbor 192.0.2.1 password 7 S3CRET",
        f"neighbor 192.0.2.1 password 7 {M}",
    ),
    (("key chain K", "key 1"), "key-string 7 S3CRET", f"key-string 7 {M}"),
    ((), "key chain OSPF-KEYS", "key chain OSPF-KEYS"),
    (
        ("interface Gi1",),
        "standby 1 authentication text S3CRET",
        f"standby 1 authentication text {M}",
    ),
    (("interface Gi1",), "standby 1 authentication S3CRET", f"standby 1 authentication {M}"),
    (("interface Gi1",), "standby authentication S3CRET", f"standby authentication {M}"),
    (
        ("interface Gi1",),
        "standby 1 authentication md5 key-string 7 S3CRET timeout 30",
        f"standby 1 authentication md5 key-string 7 {M} timeout 30",
    ),
    (
        ("interface Gi1",),
        "standby 1 authentication md5 key-chain HSRP-KEYS",
        "standby 1 authentication md5 key-chain HSRP-KEYS",
    ),
    (("interface Gi1",), "vrrp 1 authentication text S3CRET", f"vrrp 1 authentication text {M}"),
    (
        ("interface Gi1",),
        "vrrp 1 authentication md5 key-string S3CRET",
        f"vrrp 1 authentication md5 key-string {M}",
    ),
    (("interface Se0",), "ppp chap password 0 S3CRET", f"ppp chap password 0 {M}"),
    (
        ("interface Se0",),
        "ppp pap sent-username u password 0 S3CRET",
        f"ppp pap sent-username u password 0 {M}",
    ),
    ((), "ip ftp password 0 S3CRET", f"ip ftp password 0 {M}"),
    ((), "ntp authentication-key 1 md5 S3CRET 7", f"ntp authentication-key 1 md5 {M} 7"),
    (
        (),
        "ntp authentication-key 1 hmac-sha2-256 S3CRET",
        f"ntp authentication-key 1 hmac-sha2-256 {M}",
    ),
    ((), "ntp server 192.0.2.1 key 1", "ntp server 192.0.2.1 key 1"),
    (
        (),
        "ntp server vrf MGMT 192.0.2.1 key 12 prefer",
        "ntp server vrf MGMT 192.0.2.1 key 12 prefer",
    ),
    ((), "ntp trusted-key 1", "ntp trusted-key 1"),
    (("dot11 ssid S",), "wpa-psk ascii 0 S3CRET", f"wpa-psk ascii 0 {M}"),
    ((), "service password-encryption", "service password-encryption"),
    ((), "password encryption aes", "password encryption aes"),
    ((), "security passwords min-length 15", "security passwords min-length 15"),
    ((), "crypto key generate rsa modulus 2048", "crypto key generate rsa modulus 2048"),
    (
        (),
        "aaa authentication login default group TACACS local",
        "aaa authentication login default group TACACS local",
    ),
]

ARISTA: list[Case] = [
    (
        (),
        "username admin privilege 15 role network-admin secret sha512 $6$salt$hash",
        f"username admin privilege 15 role network-admin secret sha512 {M}",
    ),
    ((), "enable password sha512 $6$salt$hash", f"enable password sha512 {M}"),
    ((), "snmp-server community S3CRET ro", f"snmp-server community {M} ro"),
    (
        (),
        "snmp-server host 192.0.2.1 vrf MGMT version 2c S3CRET",
        f"snmp-server host 192.0.2.1 vrf MGMT version 2c {M}",
    ),
    (
        (),
        "snmp-server user u g v3 auth sha S3CRET priv aes S3CRET",
        f"snmp-server user u g v3 auth sha {M} priv aes {M}",
    ),
    ((), "tacacs-server host 192.0.2.1 key 7 S3CRET", f"tacacs-server host 192.0.2.1 key 7 {M}"),
    ((), "radius-server host 192.0.2.1 key 7 S3CRET", f"radius-server host 192.0.2.1 key 7 {M}"),
    (
        ("router bgp 65000",),
        "neighbor 192.0.2.1 password 7 S3CRET",
        f"neighbor 192.0.2.1 password 7 {M}",
    ),
    (
        ("router bgp 65000",),
        "neighbor 192.0.2.1 password 8a S3CRET",
        f"neighbor 192.0.2.1 password 8a {M}",
    ),
    (
        ("interface Et1",),
        "ip ospf authentication-key 7 S3CRET",
        f"ip ospf authentication-key 7 {M}",
    ),
    (
        ("interface Et1",),
        "ip ospf message-digest-key 1 sha256 7 S3CRET",
        f"ip ospf message-digest-key 1 sha256 7 {M}",
    ),
    (("interface Et1",), "isis authentication key 7 S3CRET", f"isis authentication key 7 {M}"),
    (
        ("interface Vl10",),
        "vrrp 1 peer authentication text S3CRET",
        f"vrrp 1 peer authentication text {M}",
    ),
    ((), "ntp authentication-key 1 sha1 7 S3CRET", f"ntp authentication-key 1 sha1 7 {M}"),
    ((), "ntp server 192.0.2.1 iburst key 1", "ntp server 192.0.2.1 iburst key 1"),
    (("management security",), "password minimum length 15", "password minimum length 15"),
    (
        (),
        "username admin privilege 15 role network-admin nopassword",
        "username admin privilege 15 role network-admin nopassword",
    ),
]

JUNOS: list[Case] = [
    (
        (),
        'set system root-authentication encrypted-password "$6$salt$hash"',
        f'set system root-authentication encrypted-password "{M}"',
    ),
    (
        ("system", "root-authentication"),
        'encrypted-password "$6$salt$hash"',
        f'encrypted-password "{M}"',
    ),
    (
        (),
        'set system login user u authentication encrypted-password "$6$salt$hash"',
        f'set system login user u authentication encrypted-password "{M}"',
    ),
    (
        (),
        "set snmp community S3CRET authorization read-only",
        f"set snmp community {M} authorization read-only",
    ),
    (("snmp",), "community S3CRET", f"community {M}"),
    (
        (),
        'set system ntp authentication-key 1 type md5 value "S3CRET"',
        f'set system ntp authentication-key 1 type md5 value "{M}"',
    ),
    (
        ("system", "ntp"),
        'authentication-key 2 type sha256 value "$9$S3CRET"',
        f'authentication-key 2 type sha256 value "{M}"',
    ),
    (("system", "ntp"), "server 192.0.2.1 key 1", "server 192.0.2.1 key 1"),
    ((), "set system ntp server 192.0.2.1 key 1", "set system ntp server 192.0.2.1 key 1"),
    (("system", "ntp"), "trusted-key 1", "trusted-key 1"),
    (
        (),
        'set system tacplus-server 192.0.2.1 secret "$9$S3CRET"',
        f'set system tacplus-server 192.0.2.1 secret "{M}"',
    ),
    (("system", "radius-server"), '192.0.2.1 secret "$9$S3CRET"', f'192.0.2.1 secret "{M}"'),
    (
        (),
        'set security ike policy P pre-shared-key ascii-text "$9$S3CRET"',
        f'set security ike policy P pre-shared-key ascii-text "{M}"',
    ),
    (
        ("security", "ike", "policy P"),
        'pre-shared-key hexadecimal "$9$S3CRET"',
        f'pre-shared-key hexadecimal "{M}"',
    ),
    (
        (),
        'set protocols bgp group G authentication-key "$9$S3CRET"',
        f'set protocols bgp group G authentication-key "{M}"',
    ),
    (
        (),
        'set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key "$9$S3CRET"',
        f'set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key "{M}"',
    ),
    (
        ("snmp", "v3", "usm", "local-engine", "user u", "authentication-sha"),
        'authentication-key "$9$S3CRET"',
        f'authentication-key "{M}"',
    ),
    (
        ("snmp", "v3", "usm", "local-engine", "user u", "privacy-aes128"),
        'privacy-key "$9$S3CRET"',
        f'privacy-key "{M}"',
    ),
    (
        (),
        'set access profile P client C chap-secret "$9$S3CRET"',
        f'set access profile P client C chap-secret "{M}"',
    ),
    (
        ("interfaces", "pp0", "unit 0", "ppp-options", "pap"),
        'local-password "$9$S3CRET"',
        f'local-password "{M}"',
    ),
    (
        ("system",),
        "authentication-order [ tacplus password ]",
        "authentication-order [ tacplus password ]",
    ),
    # The whole line, as fingerprint evidence shows it: `];` is one word there.
    (
        (),
        "    authentication-order [ tacplus password ];",
        "    authentication-order [ tacplus password ];",
    ),
    ((), "set system authentication-order password;", "set system authentication-order password;"),
    (("system", "login", "password"), "minimum-length 15", "minimum-length 15"),
]

FORTIOS: list[Case] = [
    (("config system admin", 'edit "admin"'), "set password ENC SH2abc", f"set password ENC {M}"),
    (("config user local", 'edit "u"'), "set passwd ENC abc", f"set passwd ENC {M}"),
    (
        ("config vpn ipsec phase1-interface", 'edit "vpn1"'),
        "set psksecret ENC abc",
        f"set psksecret ENC {M}",
    ),
    (
        ("config vpn ipsec phase1-interface", 'edit "vpn1"'),
        "set ppk-secret ENC abc",
        f"set ppk-secret ENC {M}",
    ),
    (("config user radius", 'edit "R"'), "set secret ENC abc", f"set secret ENC {M}"),
    (
        ("config user radius", 'edit "R"'),
        "set secondary-secret ENC abc",
        f"set secondary-secret ENC {M}",
    ),
    (
        ("config user radius", 'edit "R"'),
        "set tertiary-secret ENC abc",
        f"set tertiary-secret ENC {M}",
    ),
    (("config user tacacs+", 'edit "T"'), "set key ENC abc", f"set key ENC {M}"),
    (
        ("config user tacacs+", 'edit "T"'),
        "set secondary-key ENC abc",
        f"set secondary-key ENC {M}",
    ),
    (("config user tacacs+", 'edit "T"'), "set tertiary-key ENC abc", f"set tertiary-key ENC {M}"),
    (("config user ldap", 'edit "L"'), "set password ENC abc", f"set password ENC {M}"),
    (("config system snmp user", 'edit "u"'), "set auth-pwd ENC abc", f"set auth-pwd ENC {M}"),
    (("config system snmp user", 'edit "u"'), "set priv-pwd ENC abc", f"set priv-pwd ENC {M}"),
    (("config system snmp community", "edit 1"), 'set name "S3CRET"', f'set name "{M}"'),
    (("config system snmp community", "edit 1"), "set name S3CRET", f"set name {M}"),
    (("config system snmp community", "edit 1"), "set status enable", "set status enable"),
    (("config system interface", 'edit "port1"'), 'set name "port1"', 'set name "port1"'),
    (("config firewall policy", "edit 1"), 'set name "allow-web"', 'set name "allow-web"'),
    (
        ("config wireless-controller vap", 'edit "v"'),
        "set passphrase ENC abc",
        f"set passphrase ENC {M}",
    ),
    (
        ("config router bgp", "config neighbor", 'edit "192.0.2.1"'),
        "set password ENC abc",
        f"set password ENC {M}",
    ),
    (
        ("config router ospf", "config ospf-interface", 'edit "o"'),
        "set authentication-key ENC abc",
        f"set authentication-key ENC {M}",
    ),
    (("config system ntp", "config ntpserver", "edit 1"), "set key ENC abc", f"set key ENC {M}"),
    (("config system ntp", "config ntpserver", "edit 1"), "set key-id 1", "set key-id 1"),
    (
        ("config system ntp", "config ntpserver", "edit 1"),
        "set key-type SHA256",
        "set key-type SHA256",
    ),
    (("config system ha",), "set password ENC abc", f"set password ENC {M}"),
    (("config system password-policy",), "set minimum-length 15", "set minimum-length 15"),
]

PANOS: list[Case] = [
    (("config", "mgt-config", "users", "entry admin"), "phash $5$salt$hash", f"phash {M}"),
    (
        ("config", "shared", "server-profile", "tacplus", "entry T", "server", "entry t1"),
        "secret -AQ==S3CRET",
        f"secret {M}",
    ),
    (
        ("config", "shared", "server-profile", "ldap", "entry L"),
        "bind-password -AQ==S3CRET",
        f"bind-password {M}",
    ),
    (
        ("deviceconfig", "system", "snmp-setting", "access-setting", "version", "v2c"),
        "snmp-community-string S3CRET",
        f"snmp-community-string {M}",
    ),
    (
        ("shared", "log-settings", "snmptrap", "entry S", "version", "v2c", "server", "entry m"),
        "community S3CRET",
        f"community {M}",
    ),
    (
        (
            "deviceconfig",
            "system",
            "snmp-setting",
            "access-setting",
            "version",
            "v3",
            "users",
            "entry u",
        ),
        "authpwd -AQ==S3CRET",
        f"authpwd {M}",
    ),
    (
        (
            "deviceconfig",
            "system",
            "snmp-setting",
            "access-setting",
            "version",
            "v3",
            "users",
            "entry u",
        ),
        "privpwd -AQ==S3CRET",
        f"privpwd {M}",
    ),
    (
        ("network", "ike", "gateway", "entry G", "authentication", "pre-shared-key"),
        "key -AQ==S3CRET",
        f"key {M}",
    ),
    (
        ("deviceconfig", "system", "ntp-servers", "primary-ntp-server", "authentication-type"),
        "authentication-key -AQ==S3CRET",
        f"authentication-key {M}",
    ),
    (
        (
            "network",
            "virtual-router",
            "entry default",
            "protocol",
            "ospf",
            "auth-profile",
            "entry A",
        ),
        "password -AQ==S3CRET",
        f"password {M}",
    ),
    (("shared", "certificate", "entry C"), "private-key -AQ==S3CRET", f"private-key {M}"),
    (("config", "mgt-config", "password-complexity"), "minimum-length 15", "minimum-length 15"),
    (
        (
            "deviceconfig",
            "system",
            "ntp-servers",
            "primary-ntp-server",
            "authentication-type",
            "symmetric-key",
        ),
        "key-id 1",
        "key-id 1",
    ),
]


@pytest.mark.parametrize(
    ("path", "text", "shown"),
    [
        pytest.param(*case, id=f"{vendor}:{case[1]}")
        for vendor, cases in {
            "cisco": CISCO,
            "arista": ARISTA,
            "junos": JUNOS,
            "fortios": FORTIOS,
            "panos": PANOS,
        }.items()
        for case in cases
    ],
)
def test_each_vendor_s_secrets_are_masked_and_the_rest_left_readable(
    path: tuple[str, ...], text: str, shown: str
) -> None:
    assert mask_secrets(text, path) == shown
    assert "S3CRET" not in mask_secrets(text, path)
