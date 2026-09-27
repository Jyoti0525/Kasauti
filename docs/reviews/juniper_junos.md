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
| `static-route-discard`, `-reject` | "route *route-name* { (discard \| … \| next-hop [ *next-hop-address* ... ] \| next-table … \| receive \| reject); …": a discard or reject route leaves by no interface. `next-hop [ a b ]` lists, interface next hops and `qualified-next-hop` are read since v5.1.32 (addendum below) | [static (Routing Options)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/static-edit-routing-options.html) |
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

**Limits** as first recorded here (relative exports, brace `[ … ]` lists, `insert`/`rename`,
the unseen list form): all closed in v5.1.32, below.

## Addendum (v5.1.32, M2.28): the limits closed

Read on 2026-09-27. Each limit the M2.28 addendum recorded, and each found while closing them,
is closed here. The CLI's own wording is from Juniper's CLI User Guide: [CLI Configuration Mode
Overview](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/cli-configuration.html)
(below "Mode Overview"), [Modify the Configuration of a
Device](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/modifying-configuration.html)
("Modify"), [View the
Configuration](https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuartion-viewing.html)
("View") and [show \| display
set](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/command/show-pipe-display-set.html).

**Every form the CLI writes is replayed** (`kasauti/mapping/commands.py`), and the statements
it leaves go through the splitter above:

| Command or line | Juniper's words | Read as |
|---|---|---|
| `[edit a b]` banner | `top`: "Return to the top level of configuration command mode, which is indicated by the [edit] banner" (Mode Overview); samples print `[edit interfaces ge-0/0/0]` above each prompt | the level the next lines are relative to |
| `user@host# …`, `user@host> show configuration …` | the samples in View and show \| display set | a prompt: the command after it is replayed, its output read |
| `show \| display set` | "Display the configuration as a series of configuration mode commands required to re-create the configuration from the top level of the hierarchy" | full paths, at any level |
| `show \| display set relative` | "Display a series of set commands relative to the current edit path"; sample `[edit interfaces xe-0/0/0]` … `set unit 0 family inet address …` … `deactivate unit 1` (View) | paths from the banner's level |
| `\| display set explicit` | "the output also shows the configuration statements needed to create the hierarchy" | the extra lines are the blocks, given once |
| `show` at a level, `show system authentication-order` | `user@host# show system authentication-order` → `authentication-order [ radius tacplus password ];` (Authentication Order page) | braces from that level; a statement shown by name is itself |
| `edit P` | "Move inside the specified statement hierarchy. If the statement does not exist, it is created." | the level moves; P exists |
| `up [n]`, `top`, followed by a command | "The top or up command followed by another configuration command … enables you to quickly move to the top of the hierarchy or to a level above"; `[edit protocols bgp] user@host# up 2 activate system` | the level moves, or the command runs there |
| `exit`, `quit` | "Exit the current level of the statement hierarchy, returning to the level before the last edit command, or exit from configuration mode" | as quoted |
| `delete P` | "All subordinate statements and identifiers contained within the specified statement path are deleted with it" | every statement under P goes |
| `delete` alone at `[edit]` | "Delete everything under this level? [yes, no]" (Modify) | the whole configuration goes |
| `insert P id1 (before \| after) id2` | "insert <statement-path> identifier1 (before \| after) identifier2"; "If you do not use the insert command but instead configure the identifier, the identifier is placed at the end of the list"; Juniper's quick configuration `set system authentication-order radius` / `insert system authentication-order tacplus after radius` | the statements under id1 move; a new list value is added there |
| `rename P id1 to id2`, `copy P id1 to id2` | `rename interfaces lo0 unit 100 to unit 102`, `copy interfaces lo0 unit 100 to unit 101` (Modify); copy "duplicates that statement and the entire hierarchy of statements configured under that statement" | as quoted |
| `load`, `rollback`, `replace`, `update`, `wildcard`, `extension` | `load`: "Your current location in the configuration hierarchy is ignored when the load operation occurs"; `rollback`: "Return to a previously committed configuration" (Mode Overview) | their result is another file or a saved configuration: in a capture, the next whole `show` gives it; otherwise the file is read line by line with the reason |

**A part of a configuration is read as a part.** `display set relative`, `show` below the top,
output filtered with `| match` (View: "search for text matching a regular expression by
filtering output"), `ACCESS-DENIED` ("those portions of the configuration that you do not have
permissions to view are substituted with the text ACCESS-DENIED", View), a capture that never
shows the whole configuration, and a file of commands no export prints (`delete`, `insert`, …:
a change to a configuration already on the device, unless it first deletes everything): each
makes the tree partial (`ConfigTree.partial`, with the reason). The statements it shows are read
at their level, so the same mappings read them. The audit then marks every entity type as
possibly having more members in the rest of the configuration, the way it treats a type with
unread statements: a witness in the file still decides (`telnet` in it is a FAIL), while "all"
and "none" can't be true and an empty scope is REVIEW. No PASS stands, and no FAIL that rests on
a default or on something missing. A warning names the reasons.

Without a banner, lines relative to a level are placed at the one level the pack's mappings
allow for every first word (`set host-name R1`, `set services telnet` → `[edit system]`), and
the file is partial. Juniper's own table of top-level statements (Mode Overview, "Table 2")
tells a file from the top apart: if a first word is one of them, nothing is inferred. When more
than one level fits, the file is read at the top with a reason saying so, and is partial.

**Recognised as Junos when it says enough.** The fingerprint also scores a relative file as it
reads from the top, line for line. Two Junos-only statements joined the signatures:
`root-login (allow | deny | deny-password)` at `[edit system services ssh]` ([ssh (System
Services)](https://www.juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/root-login-edit-system.html))
and `authentication-order` at `[edit system]`. A fragment of `[edit system]` with host name,
authentication order and SSH settings now scores 0.8 (threshold 0.7). A file that shows too
little to tell, whole or partial, still needs the vendor named, as the short Cisco fixtures do
(M2.18).

**Lists.** "A plus sign (+) before the statement name indicates that it can contain a set of
values. To specify a set, include the values in brackets. For example: `set policy-options
community my-as1-transit members [65535:10 65535:11]`" (Modify). A set of values is now one
statement per value in both forms: `application [ junos-ssh junos-telnet ]` in braces gives the
policy both applications (it was left unknown), and so does the bracket in a `set` line, with or
without spaces inside the brackets. Only the pack's ordered lists (`leaf_lists`) are given back
as one `[ … ]` statement, their values in order wherever their lines are. How `display set`
prints a multi-value list is still not on a Juniper page; the reader no longer depends on it,
since every form gives the same statements (test `test_bracket_lists_read_the_same_in_both_forms`).

**Order.** An `insert` puts a term where first-match evaluation reads it: the tree records
configuration order (`ConfigTree.order`) and the evaluator walks entries by it. Test: an
accept-all term appended after `DENY-REST` leaves the lo0 filter closed; inserted before
`ALLOW-SSH-MGMT` it lets anyone in.

**Routes.** `next-hop` is "an IP address, an interface name, or an ISO network entity title
(NET)" ([static (Routing
Options)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/static-edit-routing-options.html)),
and `qualified-next-hop (address | interface-name)` adds next hops "each of which can have its
own preference value" ([qualified-next-hop (Static
Routes)](https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/qualified-next-hop-edit-routing-options.html)).
Six mappings read both, one-line and in the route's block, and `next-hop [ a b ]` is read one
value at a time; a route that names an interface and addresses leaves by each (role inference).
The pack has 90 mappings.

**Fixed along the way.**
- The masker read `];` after `password` in `authentication-order [ tacplus password ];` as a
  secret, so the fingerprint's evidence showed `password ****`. No secret was involved; the
  evidence line now reads as written.
- A 20,000-unit export took 12 seconds: the splitter worked out what may follow each path
  anew. It now keeps that per shape of path (the context blocks each block matches), so paths
  that differ only in names share it (3 s for the hostile case of 20,000 renamed units).
- `insert` of a term before itself raised an error; it now changes nothing.

**Checked.** Juniper's samples read as documented (relative, explicit, `show system
authentication-order`, the authentication-order `insert` sequence, `copy`/`rename`); a whole
configuration inside a capture (operational `show configuration`, `| display set | no-more`,
typed changes then `rollback 0` and `show`) gives the same facts as the file; filtered,
`ACCESS-DENIED`, answered and never-whole captures are partial; a partial `[edit system]`
capture fails Telnet and passes nothing; hostile files (an insert, rename or copy on every line,
a prompt on every line, paths of 200 lengths) read in linear time. Golden verdicts are
unchanged; the Junos cases' fingerprints gained the two signatures.
