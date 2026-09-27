# Review record: Palo Alto Networks PAN-OS seed pack and authored configs

| | |
|---|---|
| Pack | `packs/vendors/paloalto_panos` (pack_version 1), 73 mappings, XML shape family |
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
| `no-interface-proxy-arp-before-12-2-2` | off, `<12.2.2` | Configure Proxy ARP on a Layer 3 Interface: "Where Can I Use This? What Do I Need? NGFW PAN-OS 12.2.2 or a later release". Earlier releases answer ARP only for their own NAT pool addresses in an interface's subnet | [Configure Proxy ARP](https://docs.paloaltonetworks.com/ngfw/networking/using-proxy-arp-dhcp-relay-overwrite/configure-proxy-arp), [Proxy ARP for NAT Address Pools](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/10-1/pan-os-networking-admin/nat/nat-policy-rules/proxy-arp-for-nat-address-pools.html) |
| profile `permitted-ip` empty (mapping `if_empty: [any]`) | any | "(Optional) Add the Permitted IP Addresses that can access the interface. If you don't add entries to the list, the interface has no IP address restrictions." | [Use Interface Management Profiles to Restrict Access](https://docs.paloaltonetworks.com/content/techdocs/en_US/pan-os/11-1/pan-os-networking-admin/configure-interfaces/use-interface-management-profiles-to-restrict-access.html) |
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
- the element and default of the interface proxy ARP switch on 12.2.2 and later (it isn't in
  the 12.2 CLI reference), so SVC-PROXY-ARP-01 is REVIEW there;
- which lockout governs an administrator who logs in through an authentication profile: the
  profile's own Failed Attempts and Lockout Time (Configure an Authentication Profile, same
  defaults 0 and 0) or the management settings. AAA-LOCKOUT-01 is REVIEW when a profile is
  used;
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
  Authentication profiles: `authentication-profile/entry/method/<kind>/server-profile` (the
  kind from the element, `local-database` as local), `lockout/failed-attempts`,
  `lockout-time`; the device-wide profile is `deviceconfig system authentication-profile` and
  an administrator's is `mgt-config users <name> authentication-profile` (PAN-OS 11.1
  configure CLI reference).
- **Management is on at the MGT port or in a profile.** The MGT port's `disable-*` switches and
  every interface management profile that offers a service both decide `MgmtService.enabled`.
  They are combined (`combine: any`), so a service turned on anywhere stays on whatever the
  order of the file. A profile that isn't attached to any interface still counts, which can
  only give a FAIL.
- **Who may reach management:** the MGT port's `permitted-ip` list becomes
  `MgmtService.permitted_sources` (SBM 0.7). Each interface management profile's own
  `permitted-ip` list becomes `ObjectDef.permitted_sources`, and the interfaces using the
  profile inherit it as `Interface.mgmt_permitted_sources` (SBM 0.8; an empty list is `any`,
  as documented). A service counts as restricted only if the MGT port's list has no catch-all
  *and* every interface offering the service has a known list with no catch-all (one
  inference per service: SSH, HTTP, HTTPS). A profile no interface uses serves nothing, and an
  interface naming a missing profile leaves the service unproven (FAIL, with REF-DANGLING-01
  naming the profile).
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
- **Which logins are central:** an administrator (or, for accounts defined on the server, the
  device) naming an authentication profile logs in through the kinds of server that profile's
  method uses: `TACACS-AUTH` with `method/tacplus` puts `tacacs` in
  `AuthPolicy.login_methods`. A server profile that no authentication profile uses, or an
  authentication profile that nobody names, isn't central authentication.
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
| A TACACS+ server profile no administrator uses | AAA-CENTRAL-AUTH-01 passed on the server alone: a false PASS, in the hardened twin too | the rule asks which methods logins use (`AuthPolicy`, derivation `aaa.central_login_in_use`); the twin gained an authentication profile |
| A profile's own `permitted-ip` wasn't read | a profile offering HTTPS always added `any`: FAIL even when narrowed | profiles' lists flow to their interfaces (`take`, `if_empty`); unattached profiles no longer count |
| Proxy ARP wasn't read | SVC-PROXY-ARP-01 REVIEW on every release | quoted release gate: off before 12.2.2, REVIEW from 12.2.2 |
| Lockout through an authentication profile | the management lockout decided alone: a possible false PASS | REVIEW when any login goes through a profile (`unknown` effect) |
| Panorama exports and Panorama-managed firewalls | audited as if complete | `detect.yaml` warnings: audit `show config merged` |

## 5. Known limits (none gives a false PASS)

The four limits of the first review are closed or decided (section 4):

- **Interface management profiles' `permitted-ip`** is read (SBM 0.8).
- **Proxy ARP** is off by the quoted release gate before 12.2.2. From 12.2.2 it is REVIEW until
  Palo Alto publishes the setting's element and default. NAT-pool ARP answers are for the
  firewall's own addresses and aren't what SVC-PROXY-ARP-01 is about.
- **Authentication profiles** decide AAA-CENTRAL-AUTH-01. Their lockout gives REVIEW, because
  Palo Alto doesn't say which of it and the management lockout governs such a login.
- **Panorama:** Kasauti judges one firewall. Audit each firewall's `show config merged` output,
  which "shows templates from Panorama combined with local running config" (Palo Alto
  knowledge base [kA10g000000CmAYCA0](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000CmAYCA0)).
  A Panorama configuration (device groups, templates) or a Panorama-managed firewall's file
  gets a warning saying so.

Still conservative:
- **Address ranges** other than `0.0.0.0-255.255.255.255` are treated as narrow.

## 6. Result

Golden cases `paloalto_panos_weak` (P1–P14) and `paloalto_panos_hardened` are hand-labelled
from the weakness catalogue in `datasets/SOURCES.md`. All 14 planted weaknesses are caught:
13 rules FAIL, because P8 and P9 both fail MGMT-WEB-ACL-01. The hardened unit passes 19 rules;
2 are REVIEW (SSH version; lockout through its TACACS+ authentication profile) and 2 N/A (no
vty lines). False-PASS rate across all ten golden cases: 0/109.

## Addendum (v5.1.18, M2.05): companion outputs

`show system info` is read before the configuration (PLAN §7): one `key: value` per line,
`hostname`, `model`, `serial`, `sw-version`, `family`. Source: Palo Alto Networks knowledge
base [kA10g000000Cld9CAC](https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000Cld9CAC).

Fixed: the pack named this source `show version`; the PAN-OS command is `show system info`,
which the report now names.

## Addendum (v5.1.28, M2.22): addresses and routes

Read on 2026-09-27. These lines feed role inference only (TODO M2.22): an interface with a
public IPv4 address, or the one a default route leaves by, is inferred untrusted, which can
raise a finding's severity by one level with the reason shown. No rule judges them, so none
of them can turn a verdict into PASS. Where a line says the route leaves somewhere the pack
doesn't follow, the route's exit is *unknown* and nothing is inferred from it.

The XML paths are those of pan-os-python, Palo Alto Networks' own SDK (ISC licence), read in
`panos/network.py` on the `develop` branch:

| Mappings | Path | pan-os-python |
|---|---|---|
| `ethernet-ip` | `ethernet/entry/layer3/ip/entry[@name]` | `EthernetInterface`: `ip` "Layer3: Interface IPv4 addresses", `path="{mode}/ip"`, `vartype="entry"` |
| `ethernet-ipv6` | `…/layer3/ipv6/address/entry[@name]` | `IPv6Address`: xpath `/ipv6/address` |
| `static-route*` | `virtual-router/entry/routing-table/ip/static-route/entry` with `destination`, `interface`, `nexthop/ip-address` | `StaticRoute`: xpath `/routing-table/ip/static-route`; `destination`, `interface`, `nexthop` at `nexthop/{nexthop_type}`, type `ip-address`, `discard` or `next-vr` |
| `static-route6*` | `…/routing-table/ipv6/static-route/entry`, `nexthop/ipv6-address` | `StaticRouteV6`: xpath `/routing-table/ipv6/static-route`; types `discard`, `ipv6-address` |
| `static-route-next-vr`, `-discard` | a route handed to another virtual router, or dropped: its exit is *unknown* | as above |

An interface address or next hop given as an address object's name isn't read: it stays
absent, never guessed. Routes in advanced routing's logical routers aren't claimed. The
authored configs gained a virtual router whose `default-to-isp` route leaves by `ethernet1/1`
to `198.51.100.1` (weak: `.5`); every verdict is unchanged.

## Addendum (v5.1.29, M2.23): names in rules are references

Read on 2026-09-27. A security rule's `source`, `destination` and `service` members are now
`ref` effects: each name is a `Reference`, resolved or dangling, and the rule is judged by
what the object covers. A name that stays unresolved makes the rule's field *unknown*
(REVIEW); before, it was taken as some addresses.

| What a member may be | Quote | Source |
|---|---|---|
| Source / destination | "Add source addresses, address groups, or regions (default is Any)." (the same for destination) | [Building Blocks in a Security Policy Rule (11.1)](https://docs.paloaltonetworks.com/ngfw/help/11-1/policies/policies-security/building-blocks-in-a-security-policy-rule) |
| An address written in place | "Specify a Destination IP Address or leave the value set to any." | [Create a Security Policy Rule](https://docs.paloaltonetworks.com/network-security/security-policy/administration/security-rules/create-a-security-policy-rule) |
| A region | "You can choose from a standard list of countries or use the region settings described in this section to define custom regions"; a custom region's addresses: "x.x.x.x, x.x.x.x-y.y.y.y, x.x.x.x/n" | [Policy Object: Regions](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/regions) |
| An external dynamic list | "use an external dynamic list of type IP address as a source or destination address object in security rules" | [Policy Object: External Dynamic Lists](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/external-dynamic-lists) |
| Predefined services | "The default service is any, which allows all TCP and UDP ports. The HTTP and HTTPS services are predefined"; their names: "rules that control web-browsing traffic with the Service set to service-http and service-https" | [Policy Object: Services](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/services); [Safely Enable Applications on Default Ports](https://docs.paloaltonetworks.com/ngfw/administration/app-id/application-default) |

XML paths from pan-os-python (`panos/objects.py`, `develop` branch at commit 92ed648,
2026-07-22): `Region` at `/region` with `address` (`vartype="member"`), `Edl` at
`/external-list`. The pack reads custom regions (name and addresses) and external lists
(name only: the firewall fetches their contents, so a rule naming one is *unknown* in what it
covers).

Modelling decisions:

- `any`, `0.0.0.0/0`, `::/0` and `0.0.0.0-255.255.255.255` are values (`any`), as in address
  objects; `any` and `application-default` services stay `ip`, as before; `service-http` and
  `service-https` are predefined names, never references.
- An address, prefix or range written in place is a value, not a reference.
- A name no object has may be one of the firewall's standard countries, which no configuration
  lists, so it is *unknown* (REVIEW), not dangling. A service name has no such escape: only the
  two predefined services exist outside the configuration, so a missing service is dangling
  (FAIL).
- A dynamic address group's members are chosen by tags at run time: *unknown*.
