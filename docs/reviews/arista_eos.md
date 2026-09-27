# Review record: Arista EOS seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/arista_eos` (pack_version 1), 56 mappings |
| Date | 2026-09-26 |
| Reviewer | Claude, delegated by the maintainer (as for the Cisco and Junos packs) |
| Tasks | TODO M2.27 (seed pack), C.06 (authored configs vs vendor docs), S.01 |
| Result | Approved as `approved_by: [maintainer]` after the changes in section 4 |

Same rule as the other packs: **no quote, no default.** Every vendor default below is stated in
Arista's documentation; model defaults are marked `curated` and say what they model.

## 1. Vendor defaults (`defaults.yaml`)

| Default | Value | What Arista says | Source |
|---|---|---|---|
| `telnet-off` | off | "By default, EOS disables Telnet" | [Connection Management](https://www.arista.com/en/um-eos/eos-connection-management) |
| `ssh-on` | on | "The switch always enables the console and SSH." | [Connection Management](https://www.arista.com/en/um-eos/eos-connection-management) |
| `eapi-http-off`, `eapi-https-off` | off | the Command API server is `shutdown` until `no shutdown`; once on it serves HTTPS, HTTP off | [Arista eAPI](https://www.arista.com/assets/data/pdf/Whitepapers/Arista_eAPI_FINAL.pdf) |
| `passwords-stored-encrypted` | true | "running-config stores encrypted versions of these passwords and keys." | [User Security](https://www.arista.com/en/um-eos/eos-user-security) |
| `no-snmp-communities` | none exist | "SNMP is enabled with any snmp-server community or snmp-server user command" | [SNMP](https://www.arista.com/en/um-eos/eos-snmp) |
| `proxy-arp-off` | off | "EOS disables Proxy ARP by default." | [IPv4](https://www.arista.com/en/um-eos/eos-ipv4) |
| `ntp-authentication-off` | off | "Disable the NTP authentication by default." | [System Clock and Time Protocols](https://www.arista.com/en/um-eos/eos-system-clock-and-time-protocols) |
| `ntp-server-without-key` | not authenticated | authentication uses "the trusted-key for a specific server"; a server line without `key` has none | same page |

**Model defaults** (`curated`): EOS has no PAD, finger, BOOTP server or TCP/UDP small servers;
interfaces carry no per-interface management-service list; every ACL appears in the
running-config, so none there means none exist.

**Deliberately left out** (the rule says REVIEW, never PASS or FAIL):

- **SSH protocol version.** EOS has no SSH version setting, and none of the Arista pages checked
  states which versions the server accepts. MGMT-SSH-V2-01 is REVIEW on every EOS config,
  hardened included. We will not write "v2 only" from memory.
- **Idle-timeout defaults** for `management ssh` and `management console`. Both authored
  configs set them explicitly.
- **Whether EOS syslogs configuration changes without command accounting.** LOG-CONFIG-CHANGE-01
  passes on `aaa accounting commands all default … logging|group …` and is REVIEW otherwise.
- **The syslog timestamp format default.** Both authored configs state
  `logging format timestamp`.

## 2. Modelling decisions

- **Identity lives in a comment.** EOS prints model and release only in the running-config
  header (`! device: LEAF-1 (DCS-7050SX3-48YC8, EOS-4.30.1F)`). Identity sources can now be an
  RE2 regex with a `value` group over raw lines, comments included. The evidence is the header
  line, masked like every other line.
- **Banners end with a line that is just `EOF`.** The indent parser consumes the banner text
  as one statement, so a banner containing `management telnet` is never read as
  configuration. A `banner` line with no `EOF` swallows nothing. Both cases have regression
  tests.
- **Sessions.** `management ssh` and `management console` are `MgmtSession`s (kinds `vty` and
  `console`). The SSH block's `ip access-group … in` is the session's access filter, so the vty
  ACL rules and the reference resolver work unchanged.
- **Command accounting counts as config-change logging** when it covers every session
  (`default`, not `console`) and goes to syslog (`logging`) or to the AAA servers (`group`).
  Arista documents that `logging` "tells EOS to send the accounting messages to the system
  log", with the user and command in each record
  ([Using AAA to log all commands](https://eos.arista.com/using-aaa-to-log-all-commands-from-users-on-arista-eos/)).
- **Password hashes** are classified by keyword and crypt prefix (`sha512` / `$6$`, `5` /
  `$1$` MD5-crypt, `nopassword` → none). The hash itself is never kept.
- **The device is a switch by default** (`default_role: switch`). An EOS box with a routed
  uplink to an ISP faces the outside as much as a router does, so FILTER-UNTRUSTED-INGRESS-01
  now applies to switches too. Only interfaces known to be untrusted are judged, so a plain
  access switch stays N/A.

## 3. Commands in the authored configs (C.06)

Checked against the Arista pages above: `no aaa root`, `aaa authentication policy lockout
failure … duration …`, `username … role … secret sha512`, `management security` /
`password minimum length`, `tacacs-server host … key 7`, `aaa group server tacacs+`,
`aaa authentication login default group …`, `aaa accounting commands all default start-stop
group … logging`, `logging host … protocol tcp`, `logging format timestamp high-resolution|traditional`,
`ntp authentication-key … sha1`, `ntp trusted-key`, `ntp authenticate`, `ntp server … key`,
`ip access-list [standard]` with sequence numbers, `ip access-group … in` (interface and
`management ssh`), `management console|ssh|telnet` with `idle-timeout` and `[no] shutdown`,
`management api http-commands` / `protocol http`, `snmp-server community … ro|rw`,
`ip proxy-arp`, and `banner login` … `EOF`.

## 4. Changes made while building and reviewing this pack

| Problem | Effect before | Fix |
|---|---|---|
| EOS identity is only in a comment header | model and release unknown: every version-scoped default unusable | regex identity sources over raw lines; header evidence masked |
| EOS banners end with `EOF`, not a delimiter | banner text read as configuration (a banner mentioning Telnet could turn it "on") | `EOF` banners in the indent parser; regression tests |
| FILTER-UNTRUSTED-INGRESS-01 applied only to routers and firewalls | an unfiltered ISP uplink on a switch was N/A: a missed weakness (E11) | the rule applies to every role; only untrusted interfaces are judged |
| NTP authentication was left out as unverified | a keyless NTP server was REVIEW, not FAIL | Arista's "disabled by default" quoted; two defaults added |
| No EOS mapping for command accounting | the hardened config couldn't pass LOG-CONFIG-CHANGE-01 | two accounting mappings (`default` only), with tests for the `console` case |
| The `default` keyword was listed as a negation word | `default <cmd>` would have been read as "off" | removed; only `no` negates on EOS |

## 5. Result

Golden cases `arista_eos_weak` and `arista_eos_hardened` are hand-labelled from the weakness
catalogue (E1–E20 in `datasets/SOURCES.md`), not from engine output. False-PASS rate across all
six golden cases: 0/68. The weak twin is caught on 19 of its 20 planted weaknesses. The
twentieth (E7, no command accounting) is REVIEW, because Arista's pages don't say what EOS logs
without it.

## Addendum, 2026-09-26: which methods logins use

AAA-CENTRAL-AUTH-01 now asks whether administrator logins *use* a central server
(`AuthPolicy.login_methods`, derivation `aaa.central_login_in_use`), not only whether one is
configured. `aaa authentication login default <methods>` is read as on
Cisco: the first method decides, and a named `aaa group server tacacs+ <name>` counts as
`tacacs`. The hardened twin was already compliant (`group TACACS-GROUP local`).

## Addendum (v5.1.12): first-match ACLs

- `acl-implicit-deny` (`Ruleset.unmatched: deny`) quotes the ACL Structure section: "The
  interface drops packets that do not match at least one rule." and "The switch processes
  ACLs, Service ACLs, route maps, and prefix lists in order, beginning with the first rule
  and continuing until a match is found." The Service ACL section (where `management ssh` /
  `ip access-group` belongs) doesn't restate the first sentence; it is taken as the ACL
  structure service ACLs share. What an ACL with no rules does isn't stated, so there is no
  `when_empty` entry: an empty ACL on SSH management is REVIEW.
- Extended entries for any protocol read their destination (`acl-ext-proto-*`), as for Cisco;
  the interface ACL's `permit tcp any host … eq ssh` again counts as letting any source in.

Source: [ACLs and Route Maps](https://www.arista.com/en/um-eos/eos-acls-and-route-maps).

## Addendum (v5.1.18, M2.05): companion outputs

`show version` is read before the configuration header (PLAN §7): the model alone on the first
line (`Arista DCS-7150S-64-CL-F`), `Hardware version:`, `Serial number:`, `Software image
version:`. It names no host. Source: [EOS User Manual, Command-Line Interface (CLI), Viewing
the Model Number](https://www.arista.com/en/um-eos/eos-command-line-interface-cli).

Fixed: the model pattern was `Arista <STR:value> <LIST>`, and a `LIST` slot needs at least one
token, so it could never match the documented line. It is now `Arista <STR:value>`.

## Addendum (v5.1.28, M2.22): addresses, routes and switch ports

Read on 2026-09-27. These lines feed role inference only (TODO M2.22): an interface with a
public IPv4 address, or the one a default route leaves by, is inferred untrusted, which can
raise a finding's severity by one level with the reason shown. No rule judges them, so none
of them can turn a verdict into PASS. Where a line says the route leaves somewhere the pack
doesn't follow, the route's exit is *unknown* and nothing is inferred from it.

| Mappings | Syntax quoted | Source |
|---|---|---|
| `interface-ip-address` | "The ip address command specifies the IPv4 address of an interface and the mask for the subnet": `ip address 10.0.0.1/24`; `ip address … secondary` | [EOS 4.36.2F: IPv4](https://www.arista.com/en/um-eos/eos-ipv4) |
| `interface-ipv6-address`, `-link-local` | "ipv6 address [ *ipv6_address* \| *ipv6_prefix* \| auto-config ]", e.g. `ipv6 address 2001:db8:1::/64`; link-local read and ignored | [EOS 4.36.2F: IPv6](https://www.arista.com/en/um-eos/eos-ipv6) |
| `ip-route-via-*` | "ip route [*vrf_instance*] *dest_net* *next-hop* [*distance*][*tag_varname*][*rt_name*]"; *dest_net* "Destination IPv4 subnet (CIDR or address-mask notation)"; *next-hop* an IPv4 address or an interface (ethernet, loopback, management, port-channel, vlan, VXLAN, null0); example `ip route 0.0.0.0/0 192.14.0.4` | [EOS 4.36.2F: IPv4](https://www.arista.com/en/um-eos/eos-ipv4) |
| `ipv6-route-via-*` | "ipv6 route *dest_prefix* *next-hop* [*distance*][*tag_opt*][*rt_name*]", next hop an address, an interface, or both ("Combination route"); example `ipv6 route ::/0 fd7a:629f:52a4:fe61::2` | [EOS 4.36.2F: IPv6](https://www.arista.com/en/um-eos/eos-ipv6) |
| `switchport-mode` | "The switchport mode command specifies the switching mode … access, trunk, dot1q-tunnel, tap, and tool". Access, trunk and dot1q-tunnel read; tap and tool unknown | [EOS 4.36.2F: Virtual LANs (VLANs)](https://www.arista.com/en/um-eos/eos-virtual-lans-vlans) |

A known limit: this pack's `default_role` is `switch`, applied after inference, so the
default-route signal can't see it. A routed leaf with a default route (like the authored
configs) is treated as a router for that signal. The authored configs gained
`ip route 0.0.0.0/0 198.51.100.1 name ISP` (hardened) and `ip route 0.0.0.0/0 198.51.100.5`
(weak); every verdict is unchanged.
