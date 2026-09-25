# Pack format (format_version 1, frozen in M0)

Implements PLAN §4.4. Source of truth: `backend/kasauti/packs/model.py`; JSON Schemas in
`schemas/`. Validate everything with `uv run kasauti packs validate packs`.

```
packs/
  vendors/<vendor_os>/          directory name == pack id (lower_snake)
    pack.yaml                   manifest: shape family, negation words, comment markers, time unit
    detect.yaml                 fingerprint signatures (contains | line_prefix | regex | json_key | xml_path)
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
```

## Rules for every pack

- **Data only.** The loader refuses any file that isn't `.yaml .yml .json .md .txt .html .sig`,
  so a pack can never carry code or pickles. YAML is read with `safe_load`; files are capped
  at 5 MB.
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

## Why `derivations/` was added

PLAN §8.3 defines derived facts "once, for every vendor" but §4.4's layout has no home for
them. Following "content is data" (PLAN §3.1), they live beside the rules as a pack
directory rather than in code.
