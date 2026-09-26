# Review record: Palo Alto Networks PAN-OS seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/paloalto_panos` (pack_version 1), 67 mappings, XML shape family |
| Date | 2026-09-26 |
| Reviewer | Claude, delegated by the maintainer (as for the other seed packs) |
| Tasks | TODO M2.30 (seed pack), C.06 (authored configs vs vendor docs), S.01 |
| Result | Approved as `approved_by: [maintainer]` after the changes in section 4 |

Same rule as every pack: **no quote, no default.** Palo Alto moved its documentation under
`/ngfw/` in 2026, and many old links now return 404. Every page below was read through the
`content/techdocs` URLs, which still serve the PAN-OS 10.2–11.1 texts.

## 1. Vendor defaults (`defaults.yaml`)

| Default | Value | Palo Alto's words | Source |
|---|---|---|---|
| `idle-timeout-60-minutes` | 60 min | Idle Timeout "(range is 0 to 1,440; default is 60)"; "A value of 0 means that inactivity does not trigger an automatic logout" | [Device > Setup > Management](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/11-1/pan-os-web-interface-help/device/device-setup-management.html) |
| `failed-attempts-unlimited` | 0 | "A value of 0 specifies unlimited login attempts. The default value is 0 for firewalls in normal operational mode and 10 for firewalls in FIPS-CC mode." | same |
| `lockout-time-zero` | 0 | "A value of 0 (default) means the lockout applies until another administrator manually unlocks the account" (see section 2 for the contradiction on the same page) | same |
| `permitted-ip-empty-means-any` | any | "An empty list (default) specifies that access is available from any IP address." | [Device > Setup > Interfaces](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/11-1/pan-os-web-interface-help/device/device-setup-interfaces.html) |
| `no-profile-no-management` | none | "If you do not assign an Interface Management profile to an interface, it denies access for all IP addresses, protocols, and services by default." | [Use Interface Management Profiles to Restrict Access](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/11-1/pan-os-networking-admin/configure-interfaces/use-interface-management-profiles-to-restrict-access.html) |
| `syslog-profile-sends-nothing-until-assigned`, `syslog-udp` | off, UDP | "create a Syslog server profile and assign it to the log settings for each log type"; port "(default is UDP on port 514)" | [Configure Syslog Monitoring](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/configure-syslog-monitoring.html) |
| `config-changes-logged`, `logs-timestamped` | true | "Config logs display entries for changes to the firewall configuration. Each entry includes the date and time, the administrator username, …" | [Config Logs](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/10-2/pan-os-admin/monitoring/view-and-manage-logs/log-types-and-severity-levels/config-logs.html) |
| `snmp-read-only` | ro | "You can't configure an SNMP manager to control Palo Alto Networks firewalls (using SET messages), only to collect statistics from them (using GET messages)." | [Monitor Statistics Using SNMP](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/10-2/pan-os-admin/monitoring/snmp-monitoring-and-traps/monitor-statistics-using-snmp.html) |

**Model defaults** (`curated`, each says what it models): one administrator session kind for
the web interface and CLI (one Idle Timeout covers both); administrator passwords held only as
`phash`; no PAD, finger, BOOTP or small servers; every TACACS+, RADIUS and LDAP server appears
in a server profile.

**Looked for and not found, so no default** (the rule says REVIEW, or FAIL where absence is the
violation):
- the MGT port's Telnet, HTTP, HTTPS and SSH state when `service` doesn't say. A knowledge-base
  article shows `disable-http yes; disable-telnet yes` as example output, not as a documented
  default. Running configurations write these switches out;
- whether minimum password complexity is on, and its minimum length (range 1–16 in 11.1);
- the SSH protocol versions the management server offers (MGMT-SSH-V2-01 stays REVIEW, as on
  EOS);
- the SNMP v2c community when none is configured. The help says "Don't use the default community
  string public", but not when v2c answers with it. With no community seen, SNMP-COMMUNITY-01 is
  REVIEW.

## 2. Modelling decisions

- **Element names** come from Palo Alto's own SDK, pan-os-python (ISC):
  - `deviceconfig/system`: `hostname`, `login-banner`, `ntp-servers/primary-ntp-server/ntp-server-address`;
  - `log-settings/syslog` servers, `log-settings/{system,config}/match-list/…/send-syslog`;
  - `mgt-config/users/entry/phash`;
  - security rule `from`, `to`, `source`, `destination`, `application`, `service`, `action`, `disabled`, `log-end`, `negate-*`;
  - `address` (`ip-netmask`, `ip-range`, `ip-wildcard`, `fqdn`), `address-group/static`;
  - `service/protocol/{tcp,udp}/port`, `service-group/members`;
  - `zone/…/network/{layer3,…}` members;
  - `network/profiles/interface-management-profile` with `<service>yes</service>` and `permitted-ip`;
  - `server-profile/ldap/…/server/…/address`.

  The remaining names match Palo Alto's `set` CLI paths, which mirror the XML:
  - `deviceconfig system service disable-telnet`;
  - `deviceconfig system permitted-ip`;
  - `deviceconfig system snmp-setting access-setting version v2c snmp-community-string`;
  - `deviceconfig setting management idle-timeout` and `admin-lockout`;
  - `mgt-config password-complexity`.

  For RADIUS and TACACS+ the server kind is read from the profile's block name, not assumed.
- **Management is on at the MGT port or in a profile.** The MGT port's `disable-*` switches and
  every interface management profile that offers a service both decide `MgmtService.enabled`.
  They are combined (`combine: any`), so a service turned on anywhere stays on whatever the
  order of the file. A profile that isn't attached to any interface still counts, which can
  only give a FAIL.
- **Who may reach management:** the MGT port's `permitted-ip` list becomes
  `MgmtService.permitted_sources` (SBM 0.7). A vendor-neutral inference treats a service as
  restricted only when that list is known and has no catch-all. A profile offering HTTPS, HTTP
  or SSH adds `any`, because its own `permitted-ip` isn't read yet.
- **Interfaces inherit their profile's protocols** through an expanding reference
  (`ref … expand`), so the exposure "management protocols allowed on an untrusted interface"
  sees them. An interface with no profile allows nothing, as Palo Alto documents.
- **Zones and roles:** interfaces take their zone from `zone/…/member`. A zone named like
  untrust or outside makes the interface untrusted (the existing zone inference).
- **Security rules match applications as well as ports** (SBM 0.7 `FilterRule.applications`):
  - a rule naming specific applications isn't a permit-all even with service `any`;
  - a disabled rule filters nothing either way;
  - `application-default` with application `any` counts as all traffic;
  - negated addresses count as `any`.

  The last two can only turn a PASS into a FAIL.
- **Lockout Time 0 contradicts itself in the vendor's help.** Under Failed Attempts, the page
  says that with Lockout Time 0 "the Failed Attempts is ignored and the user is never locked
  out". Under Lockout Time it says 0 means locked "until another administrator manually unlocks
  the account". AAA-LOCKOUT-01 therefore doesn't count a zero duration as protection. Where a
  platform has no duration setting at all (Cisco), the account stays locked and the rule is
  unchanged.
- **Password hashes** are classified by crypt prefix: `$1$` → md5-crypt (fails
  AAA-LOCAL-PASSWORD-HASH-01), `$5$`/`$6$` → sha256/sha512-crypt.
- **NTP:**
  - `authentication-type` `none` → unauthenticated;
  - `symmetric-key` → authenticated, and PAN-OS then rejects unauthenticated time;
  - `autokey` isn't mapped, so it gives REVIEW.
- **Secrets:** `phash`, `snmp-community-string`, `bind-password`, `authpwd` and `privpwd` join
  the masking keywords (`secret` and `authentication-key` were already there). No secret or
  hash reaches any output (tested on both configs).

## 3. Elements in the authored configs (C.06)

Checked against the pages and SDK above:
- **Management:** `mgt-config` (`users/entry/phash`, `permissions/role-based/superuser`,
  `password-complexity/enabled`, `minimum-length` and the character minimums);
- **Shared:** `shared/server-profile/tacplus`, `shared/log-settings/syslog`,
  `system|config/match-list/send-syslog`;
- **Network:** `network/interface/ethernet/entry/layer3` (`ip`, `interface-management-profile`,
  `comment`) and `network/profiles/interface-management-profile`;
- **Device config:** `deviceconfig/system` (`hostname`, `ip-address`, `netmask`,
  `default-gateway`, `permitted-ip`, `service/disable-*`, `login-banner`,
  `ntp-servers/…/authentication-type/{none,symmetric-key}`,
  `snmp-setting/…/v2c/snmp-community-string`, `timezone`), `deviceconfig/setting/management`
  (`idle-timeout`, `admin-lockout`);
- **vsys:** `vsys/entry/zone`, `address`, `rulebase/security/rules`, `import/network/interface`.

## 4. Changes made while building and reviewing this pack

| Problem | Effect before | Fix |
|---|---|---|
| HTTP enabled in a profile but disabled on the MGT port | whichever came last in the file decided; MGMT-HTTP-01 reads only the service flag, so "disabled" written last was a false PASS | `combine: any` for flags and sets (tested in both orders) |
| Interfaces name a profile; the protocols are in the profile | untrusted interfaces showed no management protocols, so severity wasn't raised | `ref … expand` in the resolver; a missing or unread profile makes the protocols unknown |
| A permit rule naming specific applications with service `any` | would have counted as permit-all: a false FAIL | `FilterRule.applications`; derivation `filtering.permit_all_present` v3 |
| A disabled permit-all rule | a false FAIL on every platform | the same derivation now skips disabled entries |
| "Failed attempts 5, lockout time 0" | PASS, although the vendor's help says it may never lock | AAA-LOCKOUT-01 requires a non-zero duration where one is configured or documented |
| PAN-OS secret elements | `phash` and the SNMP community weren't masked | masking keywords added; tested |

## 5. Known limits (none gives a false PASS)

- **Interface management profiles' own `permitted-ip`** isn't read, so a profile that offers
  HTTPS with a narrow list still gives FAIL on MGMT-WEB-ACL-01.
- **Proxy ARP** (for NAT pools on every release; on layer-3 interfaces from 12.2.2) isn't read,
  so SVC-PROXY-ARP-01 is REVIEW per interface.
- **Authentication profiles** (their own lockout, and which server profile administrators
  use) aren't read. AAA-CENTRAL-AUTH-01 checks that a server profile exists, as for the other
  vendors.
- **Panorama templates and device groups** (`template`, `pre-rulebase`, `post-rulebase`) aren't
  read; the seed covers a firewall's own running configuration.
- **Address ranges** other than `0.0.0.0-255.255.255.255` are treated as narrow.

## 6. Result

Golden cases `paloalto_panos_weak` (P1–P14) and `paloalto_panos_hardened` are hand-labelled
from the weakness catalogue in `datasets/SOURCES.md`. All 14 planted weaknesses are caught:
13 rules FAIL, because P8 and P9 both fail MGMT-WEB-ACL-01. The hardened unit passes 19 rules;
2 are REVIEW (SSH version, proxy ARP) and 2 N/A (no vty lines). False-PASS rate across all ten
golden cases: 0/111.
