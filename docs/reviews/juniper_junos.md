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

## Addendum (v5.1.12): first-match filters

- `filter-implicit-discard` (`Ruleset.unmatched: deny`): "The device evaluates the packet
  against the terms in the firewall filter sequentially, beginning with the first term in the
  filter." and "If the packet does not match any term in the firewall filter, the device
  implicitly discards the packet." ([How Standard Firewall Filters Evaluate Packets](https://www.juniper.net/documentation/us/en/software/junos/routing-policy/topics/concept/firewall-filter-stateless-evaluate-packets.html))
- Term ports (`destination-port`, `source-port`, `port`) mark a term `narrowed`: it covers part
  of its protocol's traffic, never all. `then { syslog; log; count X; }` is read as not
  changing what the term matches. A term whose `then` has no terminating action (Junos then
  accepts) has no action read, so first-match evaluation treats it as uncertain.
- No rule reads a Junos filter's `permits_any` yet (the lo0 filter is an interface filter); the
  hardened `PROTECT-RE` evaluates to "no unlisted source gets through", as before.

## Addendum (v5.1.18, M2.05): companion outputs

Read before the configuration (PLAN §7):

- `show version`: `Hostname:`, `Model:`, `Junos:`, then `JUNOS … [build]` package lines.
  Source: [show version, Junos OS CLI reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-version.html).
- `show chassis hardware`: `Hardware inventory:`, the `Item Version Part number Serial number
  Description` header, then one row per component, `Chassis` first with the chassis serial
  and model; sub-components are indented, built-in parts show `BUILTIN` for the serial and
  fan trays none. Source: [show chassis hardware, Junos OS CLI reference](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-chassis-hardware.html).

## Addendum (v5.1.28, M2.22): addresses, routes and switch ports

Read on 2026-09-27. These lines feed role inference only (TODO M2.22): an interface with a
public IPv4 address, or the one a default route leaves by, is inferred untrusted, which can
raise a finding's severity by one level with the reason shown. No rule judges them, so none
of them can turn a verdict into PASS. Where a line says the route leaves somewhere the pack
doesn't follow, the route's exit is *unknown* and nothing is inferred from it.

| Mappings | Syntax quoted | Source |
|---|---|---|
| `unit-inet-address`, `unit-inet6-address` | `set interfaces lo0 unit 0 family inet address 10.0.0.1/32`; `family inet6 address 2001:db8:1:10::1/128`. Keyed at the unit (`ge-0/0/0.0`) like the pack's other interface facts | [Configure Static Routes](https://www.juniper.net/documentation/us/en/software/junos/static-routing/topics/topic-map/config_static-routes.html) (its examples) |
| `static-route-next-hop`, `-block`, `-block-next-hop` | `show routing-options static { route 0.0.0.0/0 next-hop 172.16.1.1; }`; IPv6 under `rib inet6.0 static { route ::/0 next-hop 2001:db8:1:1::1; }`. The context `static` covers both | same |
| `static-route-discard`, `-reject` | "route *route-name* { (discard \| … \| next-hop [ *next-hop-address* ... ] \| next-table … \| receive \| reject); …": a discard or reject route leaves by no interface. `next-hop [ a b ]` lists and `qualified-next-hop` aren't read (the route stays unknown) | [static (Routing Options)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/static-edit-routing-options.html) |
| `ethernet-switching-interface-mode`, `-port-mode` | `interface-mode (access \| trunk)` at `[edit interfaces … unit … family ethernet-switching]` (ELS); `port-mode` on software without ELS | [interface-mode](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/interface-mode-edit-interfaces.html), [port-mode](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/port-mode-interfaces-qfx-series.html) |

The authored configs gained `routing-options { static { route 0.0.0.0/0 next-hop
198.51.100.1; } }`, the ISP side of the WAN /30; every verdict is unchanged.

## Addendum (v5.1.31, M2.28): `display set` exports

Read on 2026-09-27. `show configuration | display set` is a common way to take a Junos
configuration off a device. Before this change such a file was read line by line: every rule
was left for review, and without `--vendor` it wasn't recognised as Junos at all (fingerprint
score 0).

**The format, as Juniper documents it.** [Displaying set Commands from the Junos OS
Configuration](https://www.juniper.net/documentation/en_US/junos12.1x46/topics/concept/junos-cli-configuration-displaying-as-set-commands-overview.html)
shows a configuration whose `unit 1` is `inactive:` printed as
`set interfaces fe-0/0/0 unit 0 family inet address 192.107.1.230/24`, …,
`set interfaces fe-0/0/0 unit 1 family inet address 10.0.0.1/8`, then
`deactivate interfaces fe-0/0/0 unit 1`. Each line is the full path from the top of the
hierarchy, and inactive configuration is printed and then deactivated. A test reads that
example and gets the same statements as its brace form.

**How it is read** (`kasauti/mapping/setform.py`). A line doesn't say where its blocks end:
`set system ntp server 10.0.0.1 key 1` is one statement in `system ntp`, while
`set system syslog host 10.0.0.2 any notice` is a statement inside the block `host 10.0.0.2`.
The pack already records which blocks it reads, in its mappings' contexts and patterns, so
each line is split there:

1. If the rest of the line is a statement a mapping reads at that point, it is that statement.
2. Otherwise, the next words become a block if a mapping reads them there with more words
   after them, or if a context names them. A block that continues the current context is
   preferred.
3. Otherwise, an unknown word becomes a block only if a known context starts later in the
   line (`routing-options` before `static`). Failing that, the rest of the line is one
   statement that no mapping reads, as it would be in braces.

The result is the brace tree (`input.shape_family: brace`, with `rebuilt_from: set_path` in the
report), read by the same 84 mappings. Other commands:

- `deactivate` and `delete` drop the path; `activate` undoes a `deactivate`.
- `protect`, `unprotect` and `annotate` are ignored, since the device behaves the same.
- Any other command, such as `insert` (which reorders first-match policies) or `rename`, makes
  the file be read line by line with the reason, and every verdict is left for review.

**Checked.** The authored configurations were converted into `hardened_set.conf` and
`weak_set.conf`. Both are fingerprinted as Junos, and they give the same facts, verdicts and
identity as the brace files. They are rule fixtures and golden cases.

Three more brace configurations were written so that together every one of the 84 mappings
reads at least one of them. They include inactive blocks, several communities, RADIUS, TACACS+
and ordered lists. Each gives the same facts from its export as from its braces.

**One false PASS was caught while building this.** `set system services web-management http
interface ge-0/0/0.0` was first read as one statement no mapping knows, so HTTP looked off. In
braces, `http` is a block that the pack reads. Rule 2 above was added for that case.

**Lists.** The page above shows no multi-value list. Both forms are read:
- brackets on one line (`set system authentication-order [ tacplus password ]`);
- one value per line, which is joined back into one list in order for the statements the pack
  reads as ordered (`leaf_lists: [authentication-order, protocol-version]` in `pack.yaml`).
  Other lists are read one value at a time, which their mappings accumulate.

**Fixed along the way.** The `{@}` entity key gave a block's header its parent's line. Junos
`community public { authorization read-write; }` therefore became two communities: one with
the default `read-only` access, one with `read-write`. Every one-line community in an `snmp`
block also merged into one. It now keys the header and its lines alike and siblings apart. The
weak golden case lost its phantom read-only community, and no verdict changed.

**Limits.**
- `display set relative` prints paths from the current edit level, not from the top. Such a
  file is a fragment: its lines are statements no mapping reads, and its fingerprint doesn't
  claim it, so the operator must name the vendor and is warned. The same holds for a brace
  fragment.
- In braces, `application [ junos-ssh junos-telnet ]` in a security policy leaves the policy's
  service unknown (REVIEW, never PASS). The `set` form reads each value.
