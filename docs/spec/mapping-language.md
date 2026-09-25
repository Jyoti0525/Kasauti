# Mapping language (v0)

Implements PLAN §9. Source of truth: `backend/kasauti/mapping/model.py`; JSON Schema:
`schemas/mappings.schema.json`. The Training Studio (M2) is a visual editor for exactly this.

## 1. Stored form

```yaml
mappings:
  - id: fortinet_fortios/interface-allowaccess   # <pack id>/<name>
    vendor: fortinet_fortios                      # must equal the pack id
    os_versions: ">=6.0"                          # see §5; default "*"
    context: ["config system interface", "edit <STR:ifname>"]
    entity: {type: Interface, key: "{ifname}"}
    match: "set allowaccess <LIST:protocols>"
    effect: {members: Interface.mgmt_protocols, from: protocols,
             map: {ping: icmp, https: https, http: http, ssh: ssh, telnet: telnet, snmp: snmp}}
    negation: "unset allowaccess"                 # or "auto" (default) or null
    provenance: {version: 3, proposed_by: "trainer:asha", approved_by: ["approver:ravi"],
                 signals: [S3, S5]}
```

**Entity keys use braces for slots**: `key: "{ifname}"`, `key: "vty {first}-{last}"`. A bare
word is a literal key (`key: telnet`). PLAN §9.3 writes `key: ifname` as shorthand; the schema
rejects that form with a hint, because stored literally it would merge every interface into
one entity.

## 2. Patterns

Whitespace-separated tokens. A token is a literal word or a slot `<TYPE>` / `<TYPE:name>`:

| Slot | Matches | Value |
|---|---|---|
| `INT` | a decimal integer | int |
| `IP` | an IPv4/IPv6 address or prefix | text |
| `IFNAME` | an interface name (`GigabitEthernet0/1`, `ge-0/0/0.0`, `port1`, `wan1`) | text |
| `STR` | any single token; surrounding quotes are removed | text |
| `LIST` | the rest of the line, one item per token; must be the last token | set |

Slot names are unique within a pattern. Literal words match case-sensitively.

**Context** is a list of patterns that must match a contiguous run of the statement's block
path **ending at its parent** (a suffix match), so a mapping can say
`["deviceconfig", "system", "service"]` without spelling out the whole XML path. Slots
captured in the context are available to the entity key and effects.

Family conventions that make one language serve all shapes (fixed by the shape parsers, M1–M2):

- **XML / JSON / YAML:** a leaf renders as `"<key> <value>"` and its ancestors form the path;
  an element or list item identified by a name renders as `"<element> <name>"`
  (`entry localhost.localdomain`).
- **Path-command (MikroTik):** `key=value` is tokenised as two tokens, `key=` and `value`, so
  `set telnet disabled=yes` matches `set telnet disabled= <STR:v>`.
- **Brace (Junos):** `telnet;` becomes the statement text `telnet` under path
  `system`, `services`.

## 3. Effects (the primitives)

| Form | Primitive | Meaning |
|---|---|---|
| `{set: Entity.attr, from: slot, map?, transform?}` | set | slot value becomes the attribute |
| `{set: Entity.attr, from: {min: 60, sec: 1}}` | set | weighted sum of INT slots (unit normalisation: `exec-timeout 10 0` → 600) |
| `{assert: Entity.attr, value: v}` | assert | the statement's presence means attr = v |
| `{members: Entity.attr, from: slot, map?}` | members | each LIST item joins a set attribute |
| `{ref: Entity.attr, from: slot, target: acl}` | ref | the attribute names another entity; the resolver links it (M2.23) |
| `entity: {type, key}` | entity | the statement opens/names an entity |
| `negation:` | negation | the negated form inverts the fact |
| `defaults.yaml` | default | what holds when nothing is stated, per OS version (see pack format) |

An effect's attribute must belong to the mapping's `entity` type, or to a singleton
(`Device`, `PasswordPolicy`, `LockoutPolicy`, `LoggingPolicy`). `members` needs a set attribute,
`set` a scalar one, a weighted sum an int one. Every slot an effect or key uses must be
captured by `match` or `context`.

**Order of operations for a value:** slot text → `map` (vendor word → SBM word or value) →
`transform`s in order (`invert`, `lower`, `upper`, `{unit: minutes}` → seconds,
`{split: ","}`).

**Negation.** `auto` (the default) means: if the statement starts with one of the pack's
`negation_words` (`no`, `undo`, `unset`, `delete`, …) followed by text that matches this
mapping, the effect is inverted: a boolean `assert` flips, a `members` item is removed, a `set`
reverts to absent (so the default applies). An explicit pattern overrides `auto`; `null`
disables negation.

## 4. Provenance

`version` increments on every approved change; `approved_by` lists approvers (four-eyes for
verdict-flipping changes, M3.24). `signals` records which suggestion signals proposed it
(`S1`–`S8`, or `manual`). Every fact carries `mapping_id@version`, so a report line can always
be traced back to the mapping and the person who approved it.

## 5. Version scoping

`os_versions` is `*` or comma-separated clauses joined by AND: `>=16.9,<17.3`. Versions
compare by natural order (digit runs numerically, letter runs case-insensitively; an extension
sorts after its prefix). One comparator covers Cisco `17.3.4a`, Junos `21.4R3-S2`, PAN-OS
`10.2.9-h1`, FortiOS `7.2.8` and EOS `4.30.0F` without per-vendor code.
