# Specifications

The precise, testable definitions behind PLAN.md. Each spec names its source-of-truth code;
the JSON Schemas in `schemas/` are generated from that code (`uv run python tools/export_schemas.py`)
and CI fails if they drift.

| Spec | Plan sections | TODO |
|---|---|---|
| [sbm.md](sbm.md): Security Baseline Model, facts, entities, OpenConfig | §8 | M0.13–M0.16 |
| [mapping-language.md](mapping-language.md): patterns, primitives, transforms, negation | §9 | M0.18 |
| [rule-language.md](rule-language.md): rules, expressions, four-valued evaluation, derivations | §8.3, §12.1 | M0.17, M0.20 |
| [pack-format.md](pack-format.md): pack layout, data-only rule, defaults | §4.4 | M0.21 |
