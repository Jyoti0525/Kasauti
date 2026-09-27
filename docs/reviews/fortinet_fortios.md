# Review record: Fortinet FortiOS seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/fortinet_fortios` (pack_version 1), 162 mappings |
| Date | 2026-09-26 |
| Reviewer | Claude, delegated by the maintainer (as for the other seed packs) |
| Tasks | TODO M2.29 (seed pack), C.06 (authored configs vs vendor docs), S.01 |
| Result | Approved as `approved_by: [maintainer]` after the changes in section 4 |

Same rule as every pack: **no quote, no default.** FortiGate backups print only settings that
differ from the default, so defaults carry more weight here than for any other vendor. Every
vendor default below was read from the "Default" column of Fortinet's FortiOS 7.4 CLI
reference, rendered in a browser, because the pages load their tables with JavaScript.

## 1. Vendor defaults (`defaults.yaml`)

| Default | Value | Fortinet's words | Source |
|---|---|---|---|
| `admintimeout-5-minutes` | 5 min | "Number of minutes before an idle administrator session times out." Default 5, range 1–480 | [config system global](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/339914554/config-system-global) |
| `http-redirected-to-https` | off | `admin-https-redirect`: "Enable/disable redirection of HTTP administration access to HTTPS." Default enable | same |
| `ssh-v1-off` | version 2 | `admin-ssh-v1`: "Enable/disable SSH v1 compatibility." Default disable | same |
| `pre-login-banner-off` | no banner | `pre-login-banner` … "on the login page before an administrator logs in." Default disable | same |
| `lockout-after-3`, `lockout-60-seconds` | 3 tries, 60 s | `admin-lockout-threshold` default 3; `admin-lockout-duration` default 60 | same |
| `password-policy-off`, `password-minimum-8` | off, 8 | `status` default disable; `minimum-length` default 8 (range 8–128) | [config system password-policy](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/127236326/config-system-password-policy) |
| `passwords-stored-encoded` | true | administrator passwords shown as `ENC SH2…` (SHA-256) or `ENC PB2…` (PBKDF2, from 7.4.8) | [Enhanced administrator password security](https://docs.fortinet.com/document/fortigate/7.4.8/administration-guide/548023/enhanced-administrator-password-security-new) |
| `admin-trusted-hosts-any-ipv4`, `-ipv6` | anywhere | `trusthost1-10`: "Default allows access from any IPv4 address" (0.0.0.0 0.0.0.0); `ip6-trusthost1-10`: "Default allows access from any IPv6 address" (::/0), a separate list | [config system admin](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/390485493/config-system-admin) |
| `no-interface-mgmt-access` | none | `allowaccess`: "Permitted types of management access to this interface." No default | [config system interface](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/317104469/config-system-interface) |
| `syslog-off`, `syslog-udp` | off, UDP | `status`: "Enable/disable remote syslog logging." Default disable; `mode` default udp | [config log syslogd setting](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/141516630/config-log-syslogd-setting) |
| `config-changes-logged` | true | `event` and `system` event logging default enable; a change is event 44546/44547 "Attribute configured" with `user`, `cfgpath`, `cfgattr` | [config log eventfilter](https://docs.fortinet.com/document/fortigate/7.4.2/cli-reference/437620/config-log-eventfilter), [44547](https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr) |
| `logs-timestamped` | true | every log message has `date`, `time`, `eventtime`, `tz` fields | [44547](https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr) |
| `snmp-read-only` | ro | "The FortiGate SNMP implementation is read-only" | [SNMP](https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/62595/snmp) |
| `ntp-server-unauthenticated`, `ntp-authentication-off` | off | `authentication`: "Enable/disable authentication." Default disable (global and per server). The per-server default is not applied to FortiGuard's servers (`except_keys`) | [config system ntp](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/105110478/config-system-ntp) |
| `ntp-sync-off` | off | `ntpsync`: "Enable/disable setting the FortiGate system time by synchronizing with an NTP Server." Default disable | same |
| `ntp-fortiguard-servers` | FortiGuard in use | `type`: "Use the FortiGuard NTP server or any other available NTP Server." Default fortiguard | same |
| `policy-action-deny` | deny | `action`: "Policy action (accept/deny/ipsec)." Default deny. Local-in policies too: "Action performed on traffic matching the policy." Default deny; "if no action is set manually, then the action will default to deny" | [config firewall policy](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/333889629/config-firewall-policy), [config firewall local-in-policy](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/185227842/config-firewall-local-in-policy), [Local-in policy](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/363127/local-in-policy) |
| `https-port-443`, `ssh-port-22`, `http-port-80`, `telnet-port-23` | 443, 22, 80, 23 | `admin-sport`: "Administrative access port for HTTPS." Default 443; `admin-ssh-port` 22; `admin-port` 80; `admin-telnet-port` 23 | [config system global](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/339914554/config-system-global) |
| `no-interface-mgmt-access-ipv6` | none | `ip6-allowaccess` (under `config ipv6`): "Allow management access to the interface." No default | [config system interface](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/317104469/config-system-interface) |
| `local-in-guards-the-device`, `local-in6-…` | device | "local-in policies control inbound traffic that is going to a FortiGate interface"; "can be used to restrict administrative access" | [Local-in policy](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/363127/local-in-policy) |
| `local-in-no-implicit-deny`, `local-in-empty-permits`, `local-in6-…` | permit | "Unlike IPv4 policies, there is no default implicit deny policy. The implicit deny policy should be placed at the bottom of the list of local-in-policies." The page covers `local-in-policy` and `local-in-policy6` | same |
| `local-in-config-order`, `local-in6-config-order` | file order | "the way the policies are read by the FortiGate goes from top to bottom"; policies are reordered with `move`, so the ID isn't the order | [Fortinet Community: move the order of local-in policy](https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-to-move-the-order-local-in-policy-FortiGate/ta-p/300597) |
| `policy-implicit-deny`, `policy-config-order` | deny, file order | "The policies are checked from top to bottom. The first rule that matches is applied"; "The default action for the implicit policy is to deny every traffic" | [Fortinet Community: how policy order works](https://community.fortinet.com/t5/FortiGate/Technical-Tip-How-policy-order-works-on-FortiGate/ta-p/207381) |

**Model defaults** (`curated`, each says what it models): one administrator session kind for
GUI and CLI; HTTPS administration, like SSH, always offered (who may reach it is then judged
by trusted hosts); Telnet reachable only through `allowaccess` (the `admin-telnet` switch, default
enable, only permits the service); SSH offered wherever `allowaccess` lists it; no PAD,
finger, BOOTP or small servers; proxy ARP only for `config system proxy-arp` entries; every
AAA server, SNMP community and firewall policy appears in the configuration.

## 2. Modelling decisions

- **On/off switches kept apart from values** (SBM 0.5). FortiOS lets a syslog server or a
  password minimum be configured while the feature is off, and backups show the value but not
  the (default) `disable`. `LogTarget.enabled` and `PasswordPolicy.enforced` carry the switch;
  where a platform has no switch, the rule treats naming the value as enforcing it.
- **Interfaces are zones.** FortiOS denies traffic between interfaces unless a policy accepts
  it ("If the parameters do not match any configured policies, the traffic is denied",
  [Firewall policy](https://docs.fortinet.com/document/fortigate/7.4.4/administration-guide/656084/firewall-policy)),
  so every interface satisfies FILTER-UNTRUSTED-INGRESS-01 and the policies themselves are
  judged by FILTER-PERMIT-ANY-01.
- **Interface role is the admin's own word.** `set role wan` → untrusted and `set role lan` →
  trusted. Otherwise the description/alias inference applies.
- **Address objects are seen through** (resolver, vendor-neutral). A policy naming an address
  object or group that covers every address counts as `any`. A policy naming an object whose
  extent wasn't read (a dynamic address) is REVIEW. A range starting at 0.0.0.0 is treated as
  covering everything, because a false FAIL is safer than a false PASS.
- **Trusted hosts are per account** (SBM 0.6 `LocalUser.permitted_sources` and
  `permitted_sources_v6`). Every `config system admin` entry is an account, with or without a
  password line, so a remote wildcard admin isn't skipped. The vendor-neutral inference
  `mgmt_service.access_filter.per_account_sources` marks SSH, HTTP and HTTPS as restricted only
  when *every* account lists sources for both IPv4 and IPv6: one open account, or IPv6 left at
  its `::/0` default, keeps MGMT-WEB-ACL-01 at FAIL. Cisco, Junos and EOS have no per-account
  sources, so the inference never fires there (tested).
- **FortiGuard is a time source** (`TimeSource[fortiguard]`, SBM 0.6 `enabled`), in use unless
  `set type custom`, and only when `set ntpsync enable` (`TimePolicy.sync_enabled`). With the
  global `authentication` at its documented default (disable) the rule FAILs: no key is in
  play. With it enabled the verdict is REVIEW: Fortinet configures NTP keys only for custom
  servers ([NTP authentication](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/336196/cryptographic-hash-function-authentication-support))
  and doesn't say whether the global key covers FortiGuard's servers.
- **Service objects are seen through** like address objects. `set protocol IP` covers every IP
  protocol; `set protocol-number N` narrows it (GRE is 47). Fortinet's page gives 0 as the
  default without saying it means "all"; we treat 0 as all, which can only turn a PASS into a
  FAIL. Port ranges, ICMP and service groups are read; a service whose extent wasn't read
  (only a category, a web-proxy protocol) is REVIEW.
- **Password hashes** are classified by the prefix after `ENC`: `PB2` → pbkdf2-sha256 (passes),
  `SH2` → sha256 (fails AAA-LOCAL-PASSWORD-HASH-01: a fast hash is not a password KDF).
- **HTTP administration** counts as clear-text only when `admin-https-redirect` is disabled.
  That is judged globally even if no interface lists `http`, which is conservative.
- **Local-in policies are evaluated first match** (`kasauti/policy/firstmatch.py`, v5.1.12).
  For each interface and management protocol it offers (`allowaccess`, and `ip6-allowaccess`
  over IPv6), the question is whether a source no policy names is blocked. Policies are read
  in file order; the first whose interfaces (`intf`, `any` for all), sources, destinations and
  services all match decides; traffic none matches is allowed (no implicit deny). A deny counts
  as blocking only if it matches *all* of that traffic: sources `all` (or a negated list
  without `all`), destinations `all`, a service covering the protocol's port (`ALL`, or a
  service object or group whose `tcp-portrange` includes it; the port is `admin-sport` and the
  like, read or defaulted), in force always, and enabled. A schedule other than `always` or an
  Internet-service source marks it `narrowed`: it blocks only part, so evaluation goes on. A
  line in a policy nothing reads (`ha-mgmt-intf-only`) makes it uncertain, and an uncertain
  entry that could have decided turns the answer into "can't tell". IPv4 and IPv6 are
  separate tables: a protocol the interface offers over IPv6 needs an IPv6 local-in policy
  too. Interfaces where every unlisted source is blocked list the protocol in
  `Interface.mgmt_restricted`; the inference `mgmt_service.access_filter.device_filter.<svc>`
  restricts the service when every interface offering it does.
- **Port ranges carry their protocol** (`tcp/443`, `udp/53`) so a UDP 443 service isn't taken
  for HTTPS. Lines that don't change what a local-in policy matches (`uuid`, `comments`,
  `virtual-patch`, `logtraffic`, the Internet-service names) are read with no effect.

## 3. Commands in the authored configs (C.06)

Checked against the CLI reference pages above: `config system global` (`admintimeout`,
`admin-lockout-threshold|duration`, `admin-telnet`, `admin-https-redirect`, `admin-ssh-v1`,
`pre-login-banner`, `hostname`, `alias`, `timezone`), `config system password-policy`
(`status`, `minimum-length`), `config system interface` (`ip`, `allowaccess`, `type`, `role`,
`alias`), `config system proxy-arp` (`interface`, `ip`), `config system admin` (`accprofile`,
`vdom`, `trusthost1`, `password ENC …`), `config user tacacs+` (`server`, `key`),
`config log syslogd setting` (`status`, `server`, `mode reliable`), `config log eventfilter`
(`system`), `config system snmp community` (`name`), `config system ntp` (`ntpsync`, `type
custom`, `ntpserver` … `authentication`, `key-type SHA256`, `key`, `key-id`),
`config firewall address` (`subnet`), `config firewall service custom` (`category`, `protocol`,
`protocol-number`, `tcp-portrange`, `udp-portrange`), `config system admin` (`ip6-trusthost1`),
`config firewall policy` (`name`, `srcintf`, `dstintf`,
`action`, `srcaddr`, `dstaddr`, `schedule`, `service`, `logtraffic`, `nat`). The local-in
fixtures add `config firewall local-in-policy` (`intf`, `srcaddr`, `dstaddr`, `action`,
`service`, `schedule`, `uuid`, `comments`; [CLI reference](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/185227842/config-firewall-local-in-policy),
[example](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/363127/local-in-policy)), `config firewall service group` (`member`) and `config ipv6`
(`ip6-address`, `ip6-allowaccess`).

## 4. Changes made while building and reviewing this pack

| Problem | Effect before | Fix |
|---|---|---|
| Rules with `on_absent: fail` ignored documented defaults | a FortiGate that locks out after 3 failures by default would FAIL AAA-LOCKOUT-01 | `on_no_default: fail`: the documented default decides, FAIL only when there is none; five rules converted, no existing verdict changed |
| A syslog server or password minimum set while the feature is off | would have counted as configured: a false PASS | SBM 0.5 on/off facts; derivation `logging.remote_configured` v2; min-length rule updated |
| A catch-all address object behind a name | `dstaddr "ANY-NET"` (0.0.0.0/0) wasn't a permit-any: a false PASS | the resolver widens named address objects and groups; unread extents give REVIEW |
| The widening skipped objects whose only line was their header | a dynamic address still gave PASS (caught by the new test) | the deciding evidence falls back to any line about the object |
| Administrator trusted hosts weren't read | HTTPS administration had no access fact; MGMT-WEB-ACL-01 judged clear-text HTTP only | per-account sources (SBM 0.6) and a vendor-neutral inference; HTTPS is judged, and the hardened unit PASSes on its trusted hosts |
| FortiGuard NTP (the default `type`) had no server entry | TIME-NTP-AUTH-01 was N/A for it | `TimeSource[fortiguard]` with its on switches; FAIL with authentication off, REVIEW with it on; `except_keys` keeps the per-server default off it |
| Custom service objects weren't expanded | `set service "ANY-PROTO"` (protocol IP) wasn't a permit-all: a false PASS | the resolver widens services like addresses; `set` with a template narrows a set (`protocol-number`) |
| A TACACS+ server that no administrator used | AAA-CENTRAL-AUTH-01 passed on the server alone: a false PASS, in the hardened twin too | the rule asks which methods logins use: a remote administrator (`set remote-auth enable`) whose `remote-group` names a user group that names the server. User groups expand to their servers' kinds; a local user in the group gives REVIEW. The twin gained that administrator |
| A remote administrator has no password line | AAA-LOCAL-PASSWORD-HASH-01 was REVIEW for it | `hash_type: remote`; the rule skips accounts that store no password |
| A service limited to some destinations (`set iprange`, `set fqdn`) | protocol IP with a destination range counted as all traffic: a false FAIL | `ObjectDef.destinations` (SBM 0.8); the resolver doesn't widen a destination-limited service. No default is documented ("Not Specified"), so `0.0.0.0` and the full range are taken as no limit |
| "Management reachable from untrusted" meant "no inbound ACL" | on zone-based platforms (FortiOS, Junos) the explanation was wrong: zones don't guard the device's own services | the exposure now asks for no filter *and* no zone, or management protocols granted on the interface; only the wording of existing findings changed |
| Local-in policies weren't read | a unit restricting administration by local-in policies instead of trusted hosts got FAIL on MGMT-WEB-ACL-01 | first-match evaluation (v5.1.12, above); pass fixture `fixtures/local_in_restricted.conf`, 18 test cases (order, negation, schedule, disabled, other port, moved HTTPS port, service group, other interface, factory-default ISDB policy, unread line, IPv6) |
| `ip6-allowaccess` wasn't read | Telnet, HTTP or HTTPS offered only over IPv6 was invisible: a false PASS on MGMT-TELNET-01 and the HTTP rules (found while building the above) | read into `Interface.mgmt_protocols` (every rule sees it) and `mgmt_protocols_v6`; fail fixture `fixtures/local_in_ipv6_open.conf` |
| `tcp-portrange` and `udp-portrange` items were bare numbers | a UDP 443 service would have counted as HTTPS | items carry their protocol (`prepend` transform); mappings at provenance version 2 |

## 5. Known limits (none gives a false PASS)

The three gaps of the first review (trusted hosts, FortiGuard NTP, custom service objects) are
closed (section 4). What remains is judged conservatively:

- **Local-in policies that can't be settled give FAIL, not REVIEW.** An uncertain local-in
  policy (a line nothing reads, a service not in the file, an accept to a specific device
  address followed by a deny) makes the restriction "can't tell"; the inference then doesn't
  fire, so MGMT-WEB-ACL-01 stays at FAIL with the policy lines as evidence. That is the
  inference layer's general behaviour (never a PASS on an open question); an auditor can
  overrule it.
- **Internet-service sources** (ISDB) aren't expanded: a policy using them is `narrowed`, so
  an ISDB deny never counts as blocking everyone, and an accept restricted to ISDB sources
  counts as possibly open.
- **FortiGuard NTP with global authentication enabled** is REVIEW until Fortinet documents
  whether that key covers FortiGuard's servers.

## 6. Result

Golden cases `fortinet_fortios_weak` (F1–F16) and `fortinet_fortios_hardened` are
hand-labelled from the weakness catalogue in `datasets/SOURCES.md`. All 16 planted weaknesses
are caught; the hardened unit passes 21 rules (2 N/A: no vty lines). False-PASS rate across all
ten golden cases: 0/109. v5.1.12: local-in policies read (above); no golden verdict changed.

## Addendum (v5.1.18, M2.05): companion outputs

`get system status` is read before the configuration header (PLAN §7): `Version:
FortiGate-VM64-KVM v6.4.2,build1723,200730 (GA)` (model and release), `Serial-Number:`,
`Hostname:`. Sources: [Administration Guide 7.4, VM license, CLI troubleshooting](https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/416169/vm-license);
[Technical Tip: Explaining 'get system status' command output](https://community.fortinet.com/fortigate-3/technical-tip-explaining-get-system-status-command-output-154964).

Fixed: the pack named this source `show version`, which isn't a FortiOS command, so the report
told the user to upload the wrong thing. It now says `get system status`.

## Addendum (v5.1.28, M2.22): addresses and routes

Read on 2026-09-27. These lines feed role inference only (TODO M2.22): an interface with a
public IPv4 address, or the one a default route leaves by, is inferred untrusted, which can
raise a finding's severity by one level with the reason shown. No rule judges them, so none
of them can turn a verdict into PASS. Where a line says the route leaves somewhere the pack
doesn't follow, the route's exit is *unknown* and nothing is inferred from it.

| Default | Value | Fortinet's words | Source |
|---|---|---|---|
| `route-dst-default` | `0.0.0.0/0`, for `static:` routes only (`key_prefix`) | `dst`: "Destination IP and mask for this route." Default `0.0.0.0 0.0.0.0` | [config router static, 7.4.7](https://docs.fortinet.com/document/fortigate/7.4.7/cli-reference/200835411/config-router-static) |
| `route6-dst-default` | `::/0`, for `static6:` routes | `dst`: "Destination IPv6 prefix." Default `::/0` | [config router static6, 7.4.0](https://docs.fortinet.com/document/fortigate/7.4.0/cli-reference/525620/config-router-static6) |
| `route-enabled` | true | `status`: "Enable/disable this static route." Default enable (both tables) | both pages |

| Mappings | What they read | Source |
|---|---|---|
| `interface-ip`, `-ip-none`, `-ip6-address` | `set ip 198.51.100.2 255.255.255.252` (→ `198.51.100.2/30`); `set ip 0.0.0.0 0.0.0.0` is the attribute's default, no address; `config ipv6` `set ip6-address …/64` | [config system interface](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/317104469/config-system-interface) |
| `static-route*`, `static6-route*` | entries keyed `static:<id>` / `static6:<id>`; `dst`, `gateway` ("Gateway IP for this route"), `device` ("Gateway out interface or tunnel"), `status` | the two route pages above |
| `…-dstaddr`, `…-internet-service` | a destination named by an address object or an Internet service entry: *unknown*, so the dst default can't make it a default route | [config router static, 7.4.7](https://docs.fortinet.com/document/fortigate/7.4.7/cli-reference/200835411/config-router-static) |
| `…-sdwan-zone`, `…-blackhole` | the route leaves by an SD-WAN zone, or drops its traffic: its exit is *unknown* | same, and static6 |

The authored configs gained `config router static` `edit 1` `set gateway 198.51.100.1` (weak:
`.5`) `set device "wan1"`, which by the quoted default is a default route; every verdict is
unchanged.

## Addendum (v5.1.29, M2.23): names in policies are references

Read on 2026-09-27. Firewall and local-in policies' `srcaddr`, `dstaddr` and `service` (and the
IPv6 local-in policy's) are now `ref` effects: each name is a `Reference`, resolved or
dangling, and the policy is judged by what the object covers. A name the file doesn't define
makes the policy's field *unknown* (REVIEW); before, it was taken as some addresses, so a
permit-any behind it could pass. `all` (address) and `ALL` (service) stay values, as before.

| What a name may be | Quote | Source |
|---|---|---|
| Policy `srcaddr` / `dstaddr` / `service` | "Source IPv4 address and address group names." / "Destination IPv4 address and address group names." / "Service and service group names." | [config firewall policy (7.4.4)](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/333889629/config-firewall-policy) |
| A virtual IP as destination | "To apply a virtual IP to policy in the CLI: … set dstaddr \"Internal_WebServer\"" (a `config firewall vip` entry) | [Static virtual IPs (7.4.4)](https://docs.fortinet.com/document/fortigate/7.4.4/administration-guide/510402/static-virtual-ips) |
| A VIP group as destination | "Virtual IP addresses (VIPs) can be organized into groups. After creating the VIP group, add it to a firewall policy." `config firewall vipgrp` / `set member <vip1> <vip2> ...` | [Configuring VIP groups (7.6.4)](https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/157796/configuring-vip-groups) |
| A threat feed | `config system external-resource` / `edit "AWS_IP_Blocklist"` / `set type address`; "In the Destination field, click the + and select AWS_IP_Blocklist"; in a local-in policy, `set srcaddr "AWS_IP_Blocklist"` | [IP address threat feed (7.4.4)](https://docs.fortinet.com/document/fortigate/7.4.4/administration-guide/891236/ip-address-threat-feed) |
| IPv6 address objects | `set ip6 {ipv6-network}`: "IPv6 address prefix", default `::/0` | [config firewall address6 (7.4.1)](https://docs.fortinet.com/document/fortigate/7.4.1/cli-reference/229620/config-firewall-address6) |

New mappings read the names (and, for VIPs, `extip`; for IPv6 addresses, `ip6`) of those
objects. A threat feed's addresses are fetched by the FortiGate, so a policy naming one is
*unknown* in what it covers.

Known limits, none a false PASS:

- An `address6` without `ip6` covers `::/0` by the quoted default, and an IPv4 address without
  `subnet` likewise, but only for the object types that use those fields. The pack doesn't read
  the type yet, so such an object is *unknown* (REVIEW), not assumed narrow or wide.

Two gaps found while doing this, both of which could give a false PASS on FILTER-PERMIT-ANY-01,
are closed:

- A firewall policy's `srcaddr6` / `dstaddr6` weren't read, so a policy narrow in IPv4 but
  open from `all` to `all` in IPv6 passed. They are now references to IPv6 addresses and
  groups, added to the same `src` / `dst` ("Source IPv6 address name and address group
  names", same CLI page). One policy's IPv4 and IPv6 halves share those sets, so a policy wide
  in IPv4 at one end and in IPv6 at the other is taken as a permit-any: a FAIL to explain,
  never a PASS. A `dstaddr6` name no object has may be an IPv6 virtual IP, which the pack
  doesn't read: *unknown*, not dangling.
- `srcaddr-negate`, `dstaddr-negate` (and their IPv6 twins) and `service-negate` weren't read
  for firewall policies: "When enabled srcaddr specifies what the source address must NOT
  be." Everything but a list is taken as `any` (`ip` for services), as for PAN-OS's
  `negate-source`.
