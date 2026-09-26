# Review record: Cisco IOS XE seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/cisco_ios_xe` (pack_version 2), rules in `packs/rules/` |
| Date | 2026-09-26 |
| Reviewer | Claude, delegated by the maintainer on 2026-09-26 (the maintainer asked for the review to be done here rather than by hand) |
| Tasks | TODO C.06 (authored configs vs vendor docs), M1.09 / M2.26 (seed pack), S.01 (review before approval) |
| Result | Approved as `approved_by: [maintainer]` after the fixes listed in section 4 |

This is a documented single review, not the four-eyes approval that trainer mappings get in
the Studio (TODO M3.24). Anyone can re-check it: every statement below quotes the Cisco page it
comes from.

## 1. Vendor defaults (`defaults.yaml`)

A default decides a verdict when the configuration is silent, so each one needs Cisco's own
words. **Rule applied: no quote, no default.** A missing default gives REVIEW, never a guess.

| Default | Value | Releases | What Cisco says | Source |
|---|---|---|---|---|
| `exec-timeout` | 600 s | ≥16.1 | "The default timeout is 10 minutes and 0 seconds." | [Configuration Fundamentals CR](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/D_through_E.html) |
| `ntp-server-without-key` | not authenticated | ≥16.1 | when a server is configured "an authentication key is not used" unless `key` is given | [NTP, IOS XE 17.x](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_bsm-time-calendar-set.html) |
| `ntp-authentication-off` | off | ≥16.1 | `ntp authenticate` "enables the NTP Authentication feature"; off unless configured | same page |
| `no-snmp-communities` | none exist | ≥16.1 | "The first snmp-server command that you enter enables the supported versions of SNMP" | [Configure SNMP Community Strings](https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7282-12.html) |
| `proxy-arp-on` | on | ≥16.1 | "Proxy Address Resolution Protocol (ARP) is enabled by default" | [ARP, IOS XE 17.x](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/ip-addressing/b-ip-addressing/m_arp-config-arp-0.html) |
| `ssh-compatibility-mode` | version 1.99 | ≥16.1, <17.10 | "If you do not configure this command, SSH by default runs in compatibility mode; that is, both SSH Version 1 and SSH Version 2 connections are honored." | [SSH Version 2 Support, IOS XE 17.x](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-secure-shell-v2-0.html) |
| `ssh-v2-only` | version 2 | ≥17.10 | "From Cisco IOS XE Release 17.10, the Secure Shell Version 1.99 is not supported." | same page |
| `pad-on` | on | ≥16.1 | "All PAD commands and associated connections are enabled." (bug CSCug16792 asks for the opposite, confirming it); the conservative direction | [WAN CR, service pad](https://www.cisco.com/c/en/us/td/docs/ios/wan/command/reference/wan_book/wan_s1.html) |
| `bootp-server-on` | on | ≥16.1 | BOOTP server: "This small server is enabled by default." | [Basic System Management, IOS XE 17.x](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_bsm-basic-sys-manage-xe.html) |
| `tcp-/udp-small-servers-off` | off | ≥16.1 | "Minor services are disabled by default." | same page |
| `finger-off` | off | ≥16.1 | "Cisco IOS software releases later than 12.1(5) and 12.1(5)T disable this service" | [Configuration Fundamentals CR, F–K](https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book/cf_f1.html) |
| `password-encryption-off` | off | ≥16.1 | Command Default: "Passwords are not encrypted." | [Security CR S1](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s1.html) |
| `log-timestamps-off` | off | ≥16.1 | Default System Message Logging Settings: time stamps "Disabled" | [System Message Logs, IOS XE 17.15](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/sys_mgmt/b_1715_sys_mgmt_9300_cg/configuring_system_message_logs.html) |
| `config-change-logging-off` | off | ≥16.1 | "The logging actions described above are disabled by default." | [Config Change Notification and Logging, IOS XE 17.x](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_cm-config-logger-0.html) |

**Model defaults** (how IOS XE's design maps onto the vendor-neutral model, marked `curated` in
the file, not factory settings): `no-global-telnet-service` (Telnet exposure lives in each vty
line's `transport input`, which the mappings read), `no-interface-mgmt-protocol-list`
(management access is per line and ACL, not per interface) and `no-filter-rules` (every ACL
appears in the running-config, so none there means none exist).

**Deliberately left out**, because Cisco's documentation doesn't state them:

- the vty `transport input` default (not stated for IOS XE 17 routers; a vty line without
  `transport input` gives REVIEW for the Telnet rule);
- the `username` privilege default (the command reference only gives the range 1–15);
- a minimum password length when `security passwords min-length` is absent (the rule treats
  "no enforced minimum" as the violation instead);
- the `ip http server` default (varies by platform and factory config; absent gives REVIEW).

Removed from pack version 1: `username-privilege` (value 1), which was stated from memory, not
from Cisco's documentation. No rule depended on it.

## 2. Syntax of the authored configurations (C.06)

Commands in `datasets/authored/cisco_ios_xe/*.cfg` that the mappings or rules depend on,
checked against Cisco's references:

| Command | Confirmed form | Source |
|---|---|---|
| `exec-timeout <min> <sec>`, `0 0` = never | yes | Configuration Fundamentals CR (above) |
| `ip ssh version 2`; `ip ssh server algorithm encryption aes256-ctr …` / `mac hmac-sha2-512 …` | yes | [SSH algorithms, IOS XE 17.x](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/sec-vpn/b-security-vpn/m_sec-secure-shell-algorithm-ccc.html) |
| `login block-for <s> attempts <n> within <s>` | yes | [Login Block](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16/sec-usr-cfg-xe-16-book/sec-login-enhance.html) |
| `logging host <ip> transport tcp port <n>` (and `vrf`) | yes; TCP default port 601 | [ESM command reference](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/esm/command/esm-xe-3se-3850-cr-book.pdf) |
| `ntp authentication-key 1 hmac-sha2-256 …`, `ntp authenticate`, `ntp server … key 1` | yes; hmac-sha2-256 is a listed key type | NTP, IOS XE 17.x (above) |
| `archive` / `log config` / `logging enable` / `hidekeys` / `notify syslog` | yes | Config Change Notification and Logging (above) |
| `ip http access-class ipv4 <acl>` (also covers HTTPS) | yes; the older form without `ipv4` is deprecated, and both are read | [WebUI ACL](https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-xe-17/221107-filter-traffic-destined-to-cisco-ios-xe.html) |
| `tacacs server <name>` / `address ipv4` / `key 7 …`; `aaa group server tacacs+` | yes | [TACACS+, IOS XE 16.12](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_tacacs/configuration/xe-16-12/sec-usr-tacacs-xe-16-12-book/sec-cfg-tacacs.html) |
| `service password-encryption` (type 7), `no ip proxy-arp`, `no service pad`, `no ip bootp server`, `no ip finger`, `no service tcp/udp-small-servers` | yes | sources in section 1 |

Two changes to `hardened.cfg` came out of the review, so the "hardened" twin really is hardened
under the full rule set: `security passwords min-length 15` (was 12; NIST SP 800-63B-4 requires
15 for single-factor passwords) and `no ip proxy-arp` on GigabitEthernet3.

## 3. Mappings (every one read line by line)

Checked for each mapping:

- the pattern matches Cisco's syntax;
- the entity key can't merge two different things or expose a secret;
- the effect means what the attribute says;
- negation behaves correctly (`no …` flips booleans, resets values, or is disabled where
  "no" would be wrong);
- the result is never *more* confident than the line justifies.

Beyond the fixes below, the notable judgements:

- **`transport input all` / `none`** have their own, more specific mappings. Read as protocol
  lists, `all` would have hidden Telnet: a false-PASS path, now covered by construction.
- **SNMP communities** are keyed `community-{#}`, and the string is only compared in memory
  against well-known values. A string not on the list is `is_well_known: false` (`otherwise`);
  an unknown access keyword gives *unknown*.
- **Line passwords** (`password 7 …` under `line vty`) are modelled as a `LocalUser` named after
  the line, so the password-storage rule catches them too (W18).
- **Timestamps** only count with the date and time. `service timestamps log uptime` is
  explicitly *false*, and `no service timestamps log …` turns them off.
- **ACL entries:** all entries become `FilterRule`s with position, action and protocol. Source
  and destination are read for `any`, `host`, and address+wildcard forms; anything else
  (object groups, port operators) leaves them absent, so "permits everything?" is REVIEW for
  that entry, not a guess. Numbered-ACL remarks become entries with action `remark`, which no
  rule counts as a permit.

## 4. Problems found and fixed in this review

| Problem | Effect before | Fix |
|---|---|---|
| `ntp server vrf <name> <ip>` didn't match any mapping | the server was dropped, so the NTP rule said N/A instead of judging it | optional `[vrf <STR>]` and `[prefer]`; regression test |
| Password type 4 (unsalted SHA-256, deprecated by Cisco as broken) wasn't in the type map | REVIEW instead of FAIL | mapped to `cisco-type-4`, which isn't a strong hash; test |
| `username-privilege` default came from memory | an undocumented default | removed |
| Logging mappings didn't accept `vrf` together with `transport` | `logging host X vrf V transport tcp` was an unreadable line | optional groups |

Changed mappings carry `provenance.version: 2`, so reports show which revision decided a fact.

## Addendum, 2026-09-26: which methods logins use

AAA-CENTRAL-AUTH-01 now asks whether administrator logins *use* a central server
(`AuthPolicy.login_methods`, derivation `aaa.central_login_in_use`), not only whether one is
configured. `aaa authentication login default <methods>` is read; its first method decides (`group
tacacs+`/`radius`/`ldap`, a named group through `aaa group server <kind> <name>`, else
`local`, `enable`, `line`, `none`). `local` first is not central authentication. A vty line
naming a list other than `default` (`login authentication VTY`) makes the methods unknown,
since named lists aren't resolved yet (REVIEW); a console list is left alone for break-glass
access. The hardened twin was already compliant (`group TACACS-GRP local`).

## Addendum (v5.1.12): named login lists, first-match ACLs

- **Named login lists are read.** `aaa authentication login <name> <methods>` becomes an
  object (`login_list:<name>`) read like the default list: its first method, a named server
  group counting as its kind. A vty line's `login authentication <name>` takes that list
  (`MgmtSession.login_methods`); `default` means the device default. Remote logins are judged
  by what every vty line's list has in common, a line naming no list using the default, so a
  TACACS+ default doesn't help vty lines whose own list is local (fixtures
  `vty_login_list_central.cfg` PASS, `vty_login_list_local.cfg` FAIL). A line naming a list
  that doesn't exist is REVIEW here and FAIL on REF-DANGLING-01. Rare limit: vty ranges using
  *different* central protocols (one TACACS+, one RADIUS) share only `local` and FAIL; a false
  FAIL to explain, never a false PASS. Console lines don't take part (break-glass access).
- **ACLs are evaluated first match** (`kasauti/policy/firstmatch.py`). Cisco: "Cisco software
  tests the packet against each criteria statement in the order in which these statements
  are created. After a match is found, no more criteria statements are checked." and
  "Although all access lists end with an implicit deny statement, we recommend use of an
  explicit deny statement" (`acl-implicit-deny`). `deny any` before `permit any` now
  restricts (was a false FAIL; fixture `vty_acl_first_match.cfg`).
- **An empty access list permits everything**: "An interface or command with an empty access
  list applied to it permits all traffic into the network." (`acl-empty-permits-all`). The
  old check read an empty ACL as "permits no one": **a false PASS on MGMT-VTY-ACL-02**, now a
  FAIL (fixture `vty_acl_empty.cfg`).
- **Extended entries for any protocol** read their destination (`acl-ext-proto-*`: `any`,
  `host`, network × the same); the ports after it aren't read, so the entry covers some of
  that protocol, never all of it.

Source: [IP Access List Overview, IOS XE 16.9](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_data_acl/configuration/xe-16-9/sec-data-acl-xe-16-9-book/sec-access-list-ov.html).
