# Review record: Juniper Junos OS seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/juniper_junos` (pack_version 1), 67 mappings |
| Date | 2026-09-26 |
| Reviewer | Claude, delegated by the maintainer (as for the Cisco pack) |
| Tasks | TODO M2.28 (seed pack), C.06 (authored configs vs vendor docs), S.01 |
| Result | Approved as `approved_by: [maintainer]` after the fixes in section 4 |

Same rule as the Cisco pack: **no quote, no default.** Every default below is stated in
Juniper's documentation; model defaults are marked `curated` and say what they model.

## 1. Vendor defaults (`defaults.yaml`)

| Default | Value | What Juniper says | Source |
|---|---|---|---|
| `services-off`, `http-off`, `finger-off` | off | remote access services "are all disabled by default" | [Enable Remote Access Services](https://www.juniper.net/documentation/us/en/software/junos/junos-getting-started/topics/task/remote-access.html) |
| `ssh-v2` | version 2 (≥11.4) | "v2—SSH protocol version 2 is the default, introduced in Junos OS Release 11.4" | [protocol-version](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/protocol-version-edit-system.html) |
| `class-never-times-out` | 0 (never) | without `idle-timeout` "a user is never forced off the system after extended idle times"; predefined classes can't have one | [idle-timeout (System)](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/idle-timeout-edit-system-login.html) |
| `passwords-always-hashed` | true | a plain-text password is encrypted as soon as it is configured; the configuration shows only the encrypted string | [Root Password](https://www.juniper.net/documentation/en_US/junos/topics/example/authentication-root-password-plain-text-configuring.html) |
| `no-snmp-communities` | none exist | without the community statement all SNMP requests are denied | [SNMP Communities](https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/snmp-communities.html) |
| `community-read-only` | ro | the default authorization of a community is read-only | [community (SNMP)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/community-edit-snmp.html) |
| `ntp-server-without-key`, `ntp-authentication-off` | not authenticated / not enforced | "Only time servers that transmit network time packets containing one of the specified key numbers are eligible", once `trusted-key` is set | [NTP Authentication Keys](https://www.juniper.net/documentation/us/en/software/junos/time-mgmt/topics/concept/ntp-authentication-keys.html) |
| `syslog-date-timestamps` | on | the timestamp "specifies the month, date, hour, minute, and second" by default | [time-format](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/time-format-edit-system.html) |
| `proxy-arp-off` | off | proxy ARP is not enabled by default | [proxy-arp](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/proxy-arp-edit-interfaces.html) |
| `term-matches-every-source/-destination/-protocol` | any | "If you omit the from statement, all packets are considered to match" | [Configuring Firewall Filters](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/task/firewall-filter-qfx-series-cli.html) |
| `no-host-inbound-services` | none | "By default, a security zone has all system services disabled" | [system-services (host inbound)](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/security-edit-system-service-zone-host-inbound-traffic.html) |

**Model defaults** (`curated`): Junos has no PAD, BOOTP server or TCP/UDP small servers; no user
filters or policies exist unless the configuration shows them (`no-filter-rules`).

**Deliberately left out:** whether `file messages { any notice; }` captures commit messages. The
facility and severity of commit events aren't stated in the pages checked, so a Junos config
without `interactive-commands`/`change-log` logging gives REVIEW for LOG-CONFIG-CHANGE-01, not
PASS or FAIL.

## 2. Modelling decisions

- **Sessions.** Junos has no vty lines. CLI sessions take their idle timeout from the user's
  login class, so each class used or defined is a `MgmtSession` of kind `cli` (the
  session-timeout rule now covers `cli`). Users in a predefined class (super-user, operator,
  read-only) never time out, which is exactly Juniper's documented behaviour.
- **Interfaces** are modelled at the logical unit (`ge-0/0/0.0`), where Junos applies
  addresses, filters and security zones. Descriptions are read at the unit; a physical-level
  description is left unmapped rather than guessed onto a unit.
- **Zone-based filtering.** On SRX, a security zone denies traffic between zones unless a policy
  permits it, so zone membership satisfies FILTER-UNTRUSTED-INGRESS-01 (the rule now says so,
  for every zone-based firewall).
- **Password hashes** are classified by crypt prefix (`$6$` SHA-512, `$5$` SHA-256, `$1$`
  MD5-crypt) with the new `prefix` transform; the hash itself is never kept.
- **SNMP communities** are keyed by the line of their block (`community-{@}`), so the header
  and its `authorization` child meet on one entity without the string becoming a key.
- **Firewall filter terms** become `FilterRule`s (`<filter>:<term>`), SRX security policies
  too (`<from>-><to>:<policy>`, with zones, so the device infers as a firewall).

## 3. Commands in the authored configs (C.06)

Checked against the Juniper pages above: `system services ssh/telnet/finger/web-management`,
`protocol-version v2`, `login class … idle-timeout`, `retry-options tries-before-disconnect /
lockout-period`, `password minimum-length`, `tacplus-server <ip> secret`, `syslog host … /
interactive-commands any`, `time-format millisecond`, `ntp authentication-key … type sha256`,
`server … key`, `trusted-key`, `snmp community … authorization read-write`, `firewall family inet
filter … term … from source-address … then accept|discard`, `security zones security-zone …
interfaces … host-inbound-traffic system-services`, `family inet proxy-arp unrestricted`.

Changed in `hardened.conf`: a user-defined class `NETADMIN` with `idle-timeout 10` (a
predefined class can't time out) and `minimum-length 15` (NIST SP 800-63B-4).

## 4. Problems found and fixed while building and reviewing this pack

| Problem | Effect before | Fix |
|---|---|---|
| Host-inbound services granted to a **whole zone** weren't read | Telnet allowed zone-wide read as "not reachable": a false-PASS path | zone-wide grants recorded on a `zone:<name>` interface; regression test |
| The Telnet derivation only looked at vty sessions | on a platform without vty lines the answer was "nothing seen" (REVIEW) instead of "no" | every session is judged; derivation version 2 |
| MGMT-WEB-ACL-01 used the strict view | a documented "web management is off" default couldn't take the device out of scope (REVIEW noise) | the rule uses the defaults view |
| The YAML generator emitted aliases, and one duplicate mapping id | the pack loader refused the file (its billion-laughs guard) | generator writes plain YAML; ids fixed |

## Addendum, 2026-09-26: which methods logins use

AAA-CENTRAL-AUTH-01 now asks whether administrator logins *use* a central server
(`AuthPolicy.login_methods`, derivation `aaa.central_login_in_use`), not only whether one is
configured. `system authentication-order` is read; its first method
decides (`tacplus` → tacacs, `radius`, `password` → local). With no `authentication-order`,
the rule fails, as before. The hardened twin was already compliant (`[ tacplus password ]`).
