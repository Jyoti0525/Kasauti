# Pack format (format_version 1, frozen in M0)

Implements PLAN §4.4. Source of truth: `backend/kasauti/packs/model.py`; JSON Schemas in
`schemas/`. Validate everything with `uv run kasauti packs validate packs`.

```
packs/
  vendors/<vendor_os>/          directory name == pack id (lower_snake)
    pack.yaml                   manifest: shape family, negation words, comment markers, time unit;
                                `set_form` (brace packs only): the configuration may also come as
                                `set` commands (Junos `display set`), rebuilt into the brace tree
                                by splitting each line where the pack's mappings expect blocks;
                                `leaf_lists` names statements whose one-value-per-line form is
                                joined back into one ordered list
    detect.yaml                 fingerprint signatures (contains | line_prefix | regex | json_key | xml_path),
                                and `warnings`: patterns saying the file isn't what the audit
                                expects (a Panorama export); a match adds a warning, never a verdict;
                                and `excludes`: patterns naming another OS the pack isn't written
                                for (NX-OS against IOS XE); a match rules the pack out of
                                fingerprinting, and warns if the operator chooses it anyway
    identity.yaml               where hostname / os_version / model / serial / hardware appear
    defaults.yaml               vendor defaults, each with os_versions and a documented reference
    mappings/*.yaml             statements -> facts (seeded, plus learned in the Studio)
    recipes/*.yaml              fix intents -> pre-check / change / verify / save / rollback
    verify.yaml                 pre-check and verify show-commands per rule domain
    manual/                     optional ingested command-manual corpus (S3)
  frameworks/<framework>/
    catalog.json                official control IDs (+ titles where the licence allows)
    crosswalk.yaml              our rule IDs -> this framework's control IDs, with source
  rules/*.yaml                  vendor-neutral rules with fixtures
  derivations/*.yaml            device-level security meanings (addition to PLAN §4.4, see below)
  inferences/*.yaml             roles a config implies (untrusted interfaces, device role)
  exposures/*.yaml              severity modifiers: base × exposure (PLAN §12.7)
```

## Rules for every pack

- **Data only.** The loader refuses any file that isn't `.yaml .yml .json .md .txt .html .sig`,
  so a pack can never carry code or pickles. YAML is read with a SafeLoader that also
  refuses anchors and aliases (billion laughs); files are capped at 5 MB.
- **Schema-validated, with every problem reported at once** (file, field, message), not only
  the first.
- **Cross-file checks:** mapping ids start with the pack id; no duplicate mapping, default,
  recipe or rule ids; rules type-check against the SBM and the derivations; `fix_intent`
  names a real fact; crosswalk and catalog agree on the framework.
- **Signed** (M5.08): an Ed25519 signature over the pack; unsigned packs are quarantined.

## Defaults

```yaml
defaults:
  - id: telnet-off
    attr: MgmtService.enabled
    entity_key: telnet        # which entity; null for singletons / every entity of the type
    value: false
    os_versions: ">=17.1"
    source: vendor_doc        # vendor_manual | vendor_doc | curated
    reference: "Cisco IOS XE 17 Security Configuration Guide, Secure Shell chapter"
```

A default decides verdicts when a config is silent, so `reference` is mandatory and every
fact resolved from it carries `default_source: <pack>/defaults.yaml#<id>`.

How a vendor's filters behave as a whole is a default too, on `Ruleset` (SBM 0.9): what
happens to traffic no entry matches (`unmatched`), what an empty list does (`when_empty`), the
evaluation order, and whether a ruleset guards the device itself (`applies_to: device`, with
`entity_key` naming it, e.g. FortiOS `local-in`). Without a quoted entry, first-match
evaluation assumes nothing and the answer is unknown.

The second form is a **closed-world default**: the vendor ships *none* of a type.

```yaml
  - id: no-snmp-communities
    none_of: SnmpCommunity
    os_versions: ">=16.1"
    source: curated
    reference: "…: no community string exists until one is configured"
```

Rules (checked when the pack loads and when the defaults are applied):

- The value must fit the attribute's type (a bool for `enabled`, an int for `idle_timeout_s`,
  a list for a set).
- `entity_key` names one entity and creates it if the config never mentions it. Without it,
  the default fills the attribute on every existing entity of the type (or the singleton),
  except the keys listed in `except_keys` (FortiOS: the per-server NTP default doesn't
  describe the implicit FortiGuard source, whose authentication Fortinet doesn't document),
  or only the entities whose key starts with `key_prefix` (FortiOS: IPv4 routes, `static:…`,
  default to `0.0.0.0/0`, IPv6 routes, `static6:…`, to `::/0`).
- A default only fills an **absent** fact: never an explicit one, never an unknown one.
- If the device's OS version is unknown, only defaults scoped `*` apply.
- If two entries for the same target apply with different values, neither is used and the
  audit reports the conflict; the fact stays absent and the rule says REVIEW.

## Identity and catalogs

- An `identity.yaml` pattern must capture a slot named `value` (`hostname <STR:value>`).
- A source gives either `pattern` or `regex`, never both. A `regex` is RE2 (linear time)
  with a named group `(?P<value>…)`, matched against each raw line, comments included. It is for
  identity that vendors print only in comments (EOS `! device: … EOS-4.30.1F)`); it takes no
  `context`, and its evidence line is masked like any other.
- A framework `catalog.json` may record `source_sha256`, the hash of the official file its IDs
  were extracted from. `tools/import_oscal.py` writes it for NIST SP 800-53 r5.

## Evidence for defaults

A default's `reference` quotes the vendor's own documentation and gives its URL. A behaviour the
vendor doesn't document gets no entry: the fact stays absent and the rule says REVIEW. The
Cisco IOS XE pack's review record, with every default's source, is `docs/reviews/cisco_ios_xe.md`.
*Model* defaults (how a vendor's design maps onto the SBM, e.g. "Telnet exposure lives in the
vty lines") are marked `source: curated` and say so in their reference.

## Who approves seed mappings

Mappings shipped in a seed pack are approved through repository review: pull request, CI
gates and, from M5, the pack signature. They carry `approved_by: [maintainer]`. Mappings a
trainer teaches in the Studio carry the approvers' identities (four-eyes for verdict-flipping
changes, M3.24). A mapping with no approvers can still be read, but any verdict resting on it
is REVIEW.

## Why `derivations/` was added

PLAN §8.3 defines derived facts "once, for every vendor" but §4.4's layout has no home for
them. Following "content is data" (PLAN §3.1), they live beside the rules as a pack
directory rather than in code.
