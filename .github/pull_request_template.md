## What and why

<!-- What changes, which TODO task(s) it closes (e.g. M1.05), which PLAN section it implements. -->

## Definition of done (docs/TODO.md S.01)

- [ ] Tests (unit + fixtures) added or updated; `uv run pytest` green
- [ ] `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy` clean
- [ ] Docs/specs updated if behaviour or a format changed; schemas regenerated
- [ ] Reviewed: separate review pass on the diff, then approved by the maintainer

## Principles (PLAN §3.1, TODO S.04)

- [ ] Every verdict still traces to file, line, mapping and approver
- [ ] Missing information resolves to a vendor default or REVIEW, never a silent PASS
- [ ] AI only suggests; only approved mappings and deterministic rules decide
- [ ] Content stays data (packs), not code
- [ ] Same input + KB + rule-set version -> byte-identical output
- [ ] Works offline; no new network calls in the core

## Non-goals respected (PLAN §3.2, TODO S.05)

- [ ] No per-vendor parser, cloud AI, LLM verdicts, auto-push, blockchain network,
      compliance % without coverage %, invented control IDs or copied CIS/ISO text

## Licences (TODO S.03)

- [ ] No new dependency, **or** each new one listed here with its licence verified at the source:
