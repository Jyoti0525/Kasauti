# Rule language, expressions and derivations (v0)

Implements PLAN §8.3 and §12.1. Source of truth: `backend/kasauti/rules/{expr,model,derivation}.py`;
JSON Schemas: `schemas/rules.schema.json`, `schemas/derivations.schema.json`.

## 1. A rule

```yaml
id: MGMT-TELNET-01                      # UPPER-KEBAB with a two-digit suffix
title: Clear-text Telnet management is not reachable
intent: Credentials must never cross the network in clear text.
domain: management_plane                # one of the ten domains (PLAN §12.3)
applies_to: [router, switch, firewall]  # roles; default: all (PLAN §12.5)
for_each: Device                        # or: MgmtSession where kind in [console, vty, web]
assert: not management.telnet_reachable
on_absent: resolve_default              # resolve_default | review | fail | not_applicable
on_unknown: review                      # review | fail | not_applicable
severity: {base: high}                  # critical | high | medium | low
exposure: [telnet_on_untrusted_interface]
fix_intent: {make: management.telnet_reachable, equal: false}
refs:
  nist_800_53r5: [CM-7, AC-17(2), SC-8] # required unless hardening_best_practice: true
  disa_stig: auto
  cis: {cisco_ios_xe_17: "<rec id>"}
  iso_27001_2022: derived               # via NIST OLIR #155, then reviewed
fixtures:
  pass: [cisco_ios_xe/hardened.cfg]     # paths under datasets/authored/
  fail: [cisco_ios_xe/weak.cfg]
```

Checked when a pack loads: the id format; a known entity in `for_each`; `assert` and `where`
parse and type-check against the SBM; derived facts exist; `fix_intent.make` names a real
fact; every rule is anchored to NIST (or explicitly marked `hardening_best_practice`).
The CI rule quality gate (`tools/lint_content.py`) additionally requires `on_absent`,
`on_unknown` and `fix_intent` to be **written out**, and at least one pass and one fail fixture
that exist on disk. **There is no `pass` option for missing data**: absence is never safety.

## 2. Expressions

```
expr       := or_expr
or_expr    := and_expr ("or" and_expr)*
and_expr   := not_expr ("and" not_expr)*
not_expr   := "not" not_expr | comparison
comparison := operand (CMP operand)?
CMP        := == | != | < | <= | > | >= | in | contains | ∋ | matches
operand    := literal | list | quantifier | exists | ref | "(" expr ")"
quantifier := (any | all | none | count) "(" EntityType ["where" expr] [":" expr] ")"
exists     := "exists" "(" ref ")"
ref        := IDENT ("." IDENT)*
list       := "[" [item ("," item)*] "]"      bare words in a list are strings
literal    := INT | 'string' | "string" | true | false
```

Names: a bare identifier is an attribute of the entity in scope (or `key`); `Device.x` is a
device attribute; any other dotted name is a derived fact. There is no arithmetic, no function
call other than the quantifiers, and no `eval`. `matches` takes a quoted pattern that is run
with RE2 (linear time) from M1.

Types are checked statically: `< <= > >=` need ints; `in` needs a scalar and a list or set;
`contains`/`∋` a set and a scalar; `==`/`!=` equal types; `and/or/not` booleans;
`count(...)` is an int, the other quantifiers booleans; a rule's `assert` must be boolean.

## 3. Evaluation semantics: four values, never a silent PASS

Evaluation (implemented in M1) works over four values: **TRUE, FALSE, ABSENT, UNKNOWN**.

- A fact in state `explicit` or `vendor_default` gives its value; `absent` gives ABSENT;
  `unknown` gives UNKNOWN.
- `and`/`or` short-circuit exactly like Kleene logic: `FALSE and X = FALSE`,
  `TRUE or X = TRUE`. Otherwise, if any operand is UNKNOWN the result is UNKNOWN, else if any
  is ABSENT the result is ABSENT. `not` keeps ABSENT/UNKNOWN.
- A comparison with an ABSENT/UNKNOWN operand is ABSENT/UNKNOWN.
- **A quantifier over zero entities is ABSENT**, not FALSE. `any(MgmtService where key ==
  'telnet': enabled)` on a device where nothing about Telnet was parsed does not mean "Telnet is
  off". Otherwise "we understood nothing" would read as "nothing is wrong", the classic false
  PASS (PLAN §1.2, test 2). Over a non-empty set, `any` is TRUE if one member is TRUE, FALSE if
  all are FALSE, and otherwise the missing value as above (same for `all`/`none`).
- The rule's verdict for an entity: TRUE → PASS; FALSE → FAIL; ABSENT → `on_absent`;
  UNKNOWN → `on_unknown`. `resolve_default` re-evaluates with the vendor pack's version-scoped
  defaults filled in (which materialise the missing entities in state `vendor_default`); if
  it's still ABSENT, the result is REVIEW.

## 4. Derivations

```yaml
derivations:
  - id: management.telnet_reachable   # dotted, lower_snake
    version: 1
    type: bool                        # bool | int | str
    description: ...
    expr: >
      any(MgmtService where key == 'telnet': enabled)
      or any(MgmtSession where kind == 'vty': transport contains 'telnet')
      or any(Interface: mgmt_protocols contains 'telnet')
```

Derivations live in `packs/derivations/*.yaml`. They're type-checked, may reference each
other, and are evaluated in dependency order; cycles and duplicates are load errors. A derived
fact's evidence is the union of the evidence of the facts it read (PLAN §8.3).
