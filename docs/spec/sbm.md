# Security Baseline Model (v0.1)

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

Twenty entity types: the eighteen in PLAN §8.1 plus two additions it needs elsewhere:

- `LoggingPolicy` (singleton) holds the device-wide logging flags §8.1 lists beside
  `LogTarget` (timestamps, admin_logged, config_change_logged). They describe the device,
  not a target.
- `ObjectDef` (`key` = `<kind>:<name>`) holds named ACLs, address/service objects and groups:
  the targets of the `ref` primitive and the reference resolver (§9.1, v5.1).

Singletons: `Device`, `PasswordPolicy`, `LockoutPolicy`, `LoggingPolicy`. Every entity has a
`key` unique within its type; findings name entities as `Type[key]`, e.g. `MgmtSession[vty 0-4]`.
Secrets are never keys: an SNMP community is `community-1`, with `is_well_known` recorded
before masking.

Other refinements to the §8.1 table: `CryptoProfile.lifetimes` → `lifetime_s` (seconds);
`dh_group` → `dh_groups` (a set, since a profile can offer several); `PasswordPolicy` and
`LockoutPolicy` got concrete attributes (min length, complexity, reversible-encryption block,
max age; attempts, lockout duration).

## Determinism

Entities are sorted by `(type, key)` and set values serialised sorted, so the same input
always gives byte-identical JSON (`canonical_json()`), which golden tests and report hashes
rely on (PLAN §3.1, principle 5).

## Versioning

`sbm_version` is `"0.1"`. Loading a document with another version fails with a pointer to
`kasauti.sbm.migrations`, which upgrades stored documents step by step (one pure function per
version change, never edited after release).

## OpenConfig alignment

Every attribute is either mapped to a real OpenConfig path (checked against the
openconfig/public release models on 2026-09-26) or listed as an `x-sbm` extension; a test fails
if any attribute is in neither list. Attributes with only an approximate OpenConfig equivalent
are listed as extensions rather than given a misleading path (e.g. `LogTarget.transport`:
OpenConfig has only a TLS boolean).
