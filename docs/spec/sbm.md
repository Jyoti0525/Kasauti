# Security Baseline Model (v0.9)

Implements PLAN §8 (requirement R-01). Source of truth: `backend/kasauti/sbm/`; JSON Schema:
`schemas/sbm.schema.json`; OpenConfig alignment: `backend/kasauti/sbm/openconfig.yaml`.

## Facts

Every attribute is a `Fact`: `{value, state, evidence[], default_source}`.

| State | Value | Evidence | Meaning |
|---|---|---|---|
| `explicit` | required | ≥ 1 line | stated in the configuration |
| `vendor_default` | required | optional; `default_source` required | not stated; resolved from `defaults.yaml` for this OS version |
| `absent` | none | none | not stated, no default known |
| `unknown` | none | ≥ 1 line (the unread statements) | statements exist but no approved mapping understood them |

Evidence is `{file, line_start, line_end, raw, mapping_id, mapping_version, approved_by}`.
The model enforces these combinations, so an impossible fact can't be constructed.

## Entities

Twenty-four entity types: the eighteen in PLAN §8.1 plus six additions it needs elsewhere:

- `LoggingPolicy` (singleton) holds the device-wide logging flags §8.1 lists beside
  `LogTarget` (timestamps, admin_logged, config_change_logged). They describe the device,
  not a target.
- `ObjectDef` (`key` = `<kind>:<name>`) holds named ACLs, address/service objects and groups:
  the targets of the `ref` primitive and the reference resolver (§9.1, v5.1).
- `Reference` (0.4): one statement pointing at another named thing, created by the reference
  resolver (PLAN §9.1): `source`, `attribute`, `target_kind`, `name`, `resolved`, `target`, and
  for ACL targets `permits_any` (the chain vty line → ACL → permitted sources): can a source
  the ACL doesn't name get through? Answered by ordered first-match evaluation (0.9) with the
  vendor's quoted implicit action, *unknown* where an entry that might decide wasn't read.
  Dangling references are ordinary facts that rules judge (REF-DANGLING-01).
- `Ruleset` (0.9, `key` = the name entries give in `FilterRule.ruleset`): what an ordered list
  of filter entries does as a whole. `order` (`position` or `config`), `unmatched` and
  `when_empty` (`permit`/`deny`), `applies_to` (`device`: it guards traffic addressed to the
  device itself, like FortiOS local-in policies) and `family` (`ipv4`/`ipv6`). These are quoted
  vendor facts in `defaults.yaml`, never assumed: Cisco access lists end in an implicit deny
  and an empty one permits everything; FortiOS local-in policies have no implicit deny. The
  mapper creates one for every ruleset with entries and every ACL object.
- `AuthPolicy` (singleton, 0.8) holds `login_methods`: what administrator logins are checked
  against (`tacacs`, `radius`, `ldap`, `local`; OpenConfig `authentication-method`). A named
  server group, FortiOS user group or PAN-OS authentication profile counts as the kinds of
  server it holds, so a TACACS+ server that no login uses is not in the set, and
  AAA-CENTRAL-AUTH-01 (derivation `aaa.central_login_in_use`) doesn't pass on it. Where vty
  lines name their own login list (`MgmtSession.login_methods`, 0.9), it holds what every vty
  line's list has in common, a line naming none using the device default: a TACACS+ default
  doesn't help lines whose list is local.
- `TimePolicy` (singleton, 0.2) holds `auth_enforced`: whether the device rejects time from
  unauthenticated sources (`ntp authenticate`; OpenConfig `enable-ntp-auth`).
  `TimeSource.authenticated` only says a key is configured for that server, which isn't
  enforcement on its own.

Every entity also has `evidence` (0.2): the statements that opened or named it
(`line vty 0 4`), so a finding can point at the entity even when the attribute in question was
never set.

Singletons: `Device`, `PasswordPolicy`, `AuthPolicy`, `LockoutPolicy`, `LoggingPolicy`,
`TimePolicy`. Every entity has a
`key` unique within its type; findings name entities as `Type[key]`, e.g. `MgmtSession[vty 0-4]`.
Secrets are never keys: an SNMP community is `community-1`, with `is_well_known` recorded
before masking.

Other refinements to the §8.1 table: `CryptoProfile.lifetimes` → `lifetime_s` (seconds);
`dh_group` → `dh_groups` (a set, since a profile can offer several); `PasswordPolicy` and
`LockoutPolicy` got concrete attributes (min length, complexity, reversible-encryption block,
max age; attempts, lockout duration).

## Document-level sets (0.2)

- `known_empty`: entity type → the vendor default saying none exist
  (`SnmpCommunity` → `cisco_ios_xe/defaults.yaml#no-snmp-communities`). Without an entry,
  "no entities of this type" means "nothing seen", never "none exist".
- `unread`: entity type → the lines that looked like that type but couldn't be read. Rules
  can't claim "all" or "none" over such a type.
- `derived`: the derived facts, evaluated in the defaults view, with their evidence.

## Determinism

Entities are sorted by `(type, key)` and set values serialised sorted, so the same input
always gives byte-identical JSON (`canonical_json()`), which golden tests and report hashes
rely on (PLAN §3.1, principle 5).

## Versioning

`sbm_version` is `"0.9"`. Loading a document with another version fails with a pointer to
`kasauti.sbm.migrations`, which upgrades stored documents step by step (one pure function per
version change, never edited after release). 0.1 → 0.2 adds the empty sets above; 0.2 → 0.3
adds four optional attributes (`MgmtService.access_filter`, `Interface.description`,
`Interface.proxy_arp`, `PasswordPolicy.cleartext_passwords_encrypted`); 0.3 → 0.4 adds
`Reference` and `ObjectDef.expanded` (members after recursive group expansion, *unknown* on a
cycle or a missing member); 0.4 → 0.5 adds `PasswordPolicy.enforced` and `LogTarget.enabled`,
the on/off switches FortiOS keeps apart from the values they govern (a minimum length or a
syslog server can be configured while the feature is off); 0.5 → 0.6 adds
`LocalUser.permitted_sources` and `permitted_sources_v6` (the addresses an account may log in
from, FortiOS trusted hosts), `TimeSource.enabled` (a known source may be unused: FortiGuard's
servers unless `set type custom`) and `TimePolicy.sync_enabled` (FortiOS `ntpsync`, OpenConfig
`ntp/config/enabled`); 0.6 → 0.7 adds `MgmtService.permitted_sources` (PAN-OS `permitted-ip`)
and `FilterRule.applications` (PAN-OS matches by application as well as port); 0.7 → 0.8 adds
the `AuthPolicy` singleton, `Interface.mgmt_permitted_sources` and
`ObjectDef.permitted_sources` (a PAN-OS interface management profile's `permitted-ip`, which
the interfaces using it inherit) and `ObjectDef.destinations` (a FortiOS service limited to
some destinations by `iprange`/`fqdn`, so it doesn't cover all traffic); 0.8 → 0.9 adds the
`Ruleset` entity, `FilterRule.interfaces`, `negated` and `narrowed` (what first-match
evaluation needs from FortiOS local-in policies), `MgmtService.port` (a filter naming ports is
matched against it), `Interface.mgmt_protocols_v6` (FortiOS `ip6-allowaccess`),
`Interface.mgmt_restricted` (the management protocols a device filter blocks for every
unlisted source) and `MgmtSession.login_methods` (a Cisco vty line's own login list).
Everything an older document says is kept (tested).

## OpenConfig alignment

Every attribute is either mapped to a real OpenConfig path (checked against the
openconfig/public release models on 2026-09-26) or listed as an `x-sbm` extension; a test fails
if any attribute is in neither list. Attributes with only an approximate OpenConfig equivalent
are listed as extensions rather than given a misleading path (e.g. `LogTarget.transport`:
OpenConfig has only a TLS boolean).
