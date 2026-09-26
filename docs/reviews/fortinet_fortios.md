# Review record: Fortinet FortiOS seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/fortinet_fortios` (pack_version 1), 63 mappings |
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
| `no-interface-mgmt-access` | none | `allowaccess`: "Permitted types of management access to this interface." No default | [config system interface](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/317104469/config-system-interface) |
| `syslog-off`, `syslog-udp` | off, UDP | `status`: "Enable/disable remote syslog logging." Default disable; `mode` default udp | [config log syslogd setting](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/141516630/config-log-syslogd-setting) |
| `config-changes-logged` | true | `event` and `system` event logging default enable; a change is event 44546/44547 "Attribute configured" with `user`, `cfgpath`, `cfgattr` | [config log eventfilter](https://docs.fortinet.com/document/fortigate/7.4.2/cli-reference/437620/config-log-eventfilter), [44547](https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr) |
| `logs-timestamped` | true | every log message has `date`, `time`, `eventtime`, `tz` fields | [44547](https://docs.fortinet.com/document/fortigate/7.4.4/fortios-log-message-reference/44547/44547-logid-event-config-objattr) |
| `snmp-read-only` | ro | "The FortiGate SNMP implementation is read-only" | [SNMP](https://docs.fortinet.com/document/fortigate/7.4.3/administration-guide/62595/snmp) |
| `ntp-server-unauthenticated`, `ntp-authentication-off` | off | `authentication`: "Enable/disable authentication." Default disable (global and per server) | [config system ntp](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/105110478/config-system-ntp) |
| `policy-action-deny` | deny | `action`: "Policy action (accept/deny/ipsec)." Default deny | [config firewall policy](https://docs.fortinet.com/document/fortigate/7.4.4/cli-reference/333889629/config-firewall-policy) |

**Model defaults** (`curated`, each says what it models): one administrator session kind for
GUI and CLI; Telnet reachable only through `allowaccess` (the `admin-telnet` switch, default
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
`config firewall address` (`subnet`), `config firewall policy` (`name`, `srcintf`, `dstintf`,
`action`, `srcaddr`, `dstaddr`, `schedule`, `service`, `logtraffic`, `nat`).

## 4. Changes made while building and reviewing this pack

| Problem | Effect before | Fix |
|---|---|---|
| Rules with `on_absent: fail` ignored documented defaults | a FortiGate that locks out after 3 failures by default would FAIL AAA-LOCKOUT-01 | `on_no_default: fail`: the documented default decides, FAIL only when there is none; five rules converted, no existing verdict changed |
| A syslog server or password minimum set while the feature is off | would have counted as configured: a false PASS | SBM 0.5 on/off facts; derivation `logging.remote_configured` v2; min-length rule updated |
| A catch-all address object behind a name | `dstaddr "ANY-NET"` (0.0.0.0/0) wasn't a permit-any: a false PASS | the resolver widens named address objects and groups; unread extents give REVIEW |
| The widening skipped objects whose only line was their header | a dynamic address still gave PASS (caught by the new test) | the deciding evidence falls back to any line about the object |
| "Management reachable from untrusted" meant "no inbound ACL" | on zone-based platforms (FortiOS, Junos) the explanation was wrong: zones don't guard the device's own services | the exposure now asks for no filter *and* no zone, or management protocols granted on the interface; only the wording of existing findings changed |

## 5. Known gaps (not judged yet, never passed)

- **Administrator trusted hosts** (`trusthost1…10`) and local-in policies restrict where
  administrators may log in from. They aren't mapped yet, so HTTPS/SSH administration has no
  access-filter fact. MGMT-WEB-ACL-01 judges clear-text HTTP only.
- **FortiGuard NTP** (`set type fortiguard`, the default) has no server entries, so
  TIME-NTP-AUTH-01 is N/A for it. Custom servers are judged.
- **Custom service objects** that cover every protocol aren't expanded. `service "ALL"` is.

## 6. Result

Golden cases `fortinet_fortios_weak` (F1–F16) and `fortinet_fortios_hardened` are
hand-labelled from the weakness catalogue in `datasets/SOURCES.md`. All 16 planted weaknesses
are caught. False-PASS rate across all eight golden cases: 0/91.
