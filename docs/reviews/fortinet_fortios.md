# Review record: Fortinet FortiOS seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/fortinet_fortios` (pack_version 1), 105 mappings |
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
| `policy-action-deny` | deny | `action`: "Policy action (accept/deny/ipsec)." Default deny | [config firewall policy](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/333889629/config-firewall-policy) |

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
`action`, `srcaddr`, `dstaddr`, `schedule`, `service`, `logtraffic`, `nat`).

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

## 5. Known limits (none gives a false PASS)

The three gaps of the first review (trusted hosts, FortiGuard NTP, custom service objects) are
closed (section 4). What remains is judged conservatively:

- **Local-in policies** (`config firewall local-in-policy`) can also restrict administrator
  access. They aren't read, so a unit relying on them instead of trusted hosts gets FAIL on
  MGMT-WEB-ACL-01, with the reason shown; an auditor can overrule it. Reading them needs
  first-match evaluation of an ordered list per interface and service, with traffic no policy
  matches allowed. AWS network ACLs (M2.31) need the same ordered evaluation, so it will be
  built once, there.
- **FortiGuard NTP with global authentication enabled** is REVIEW until Fortinet documents
  whether that key covers FortiGuard's servers.

## 6. Result

Golden cases `fortinet_fortios_weak` (F1–F16) and `fortinet_fortios_hardened` are
hand-labelled from the weakness catalogue in `datasets/SOURCES.md`. All 16 planted weaknesses
are caught; the hardened unit passes 21 rules (2 N/A: no vty lines). False-PASS rate across all
ten golden cases: 0/109.
