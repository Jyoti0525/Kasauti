# Kasauti (कसौटी)

**AI-Driven Multi-Vendor Network Security Compliance Auditor**
*हर डिवाइस, हर मानक की कसौटी पर*: every device, held to every standard.

Smart India Hackathon 2026 · Problem statement 26155 · National Technical Research Organisation (NTRO)

A *kasauti* is the touchstone used to test whether gold is pure. Kasauti tests whether a network
device's configuration meets CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001, for any vendor,
including ones it has never seen.

> **Status: Milestone 0 (foundations).** The schemas, languages and pack format are in place;
> the first end-to-end audit arrives with Milestone 1. Progress is tracked task by task in
> [docs/TODO.md](docs/TODO.md).

## What it does (target design)

1. **Reads configurations by their shape, not their vendor.** Seven structural families cover
   practically every network OS, so a new vendor almost never needs new code.
2. **Turns every line into facts with proof** in a vendor-neutral Security Baseline Model, using a
   small, precise mapping language. Independent AI signals propose mappings for unseen vendors,
   including by reading the vendor's own command manual. Humans approve.
3. **Judges those facts against all four frameworks at once.** Every finding carries its evidence,
   a fix verified by re-auditing it, and a digital signature with a transparency-log proof.

The full design is in [docs/PLAN.md](docs/PLAN.md).

## Developer setup

Measured development environment: Windows 11, Python 3.12.8, Node 20, [uv](https://docs.astral.sh/uv/).
Development is native; Docker is used only for packaging.

```bash
uv sync                     # create .venv from the hash-locked uv.lock
uv run pytest               # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy                 # strict type checking
uv run kasauti packs validate packs    # schema-check every content pack
uv run pre-commit install   # run the same checks before every commit
```

## Repository layout

```
backend/kasauti/   the Python package (one module per pipeline stage, PLAN §4.3)
backend/tests/     unit, spec and golden tests
packs/             data-only content: vendors, frameworks, rules, derivations
datasets/          authored and third-party configs; every file listed in SOURCES.md
eval/              evaluation harness (datasets E1–E5, metrics, reports)
tools/             importers and CI checks (licences, rule quality, crosswalk lint)
frontend/          web UI (from Milestone 2)
docs/              PLAN.md, TODO.md, SECURITY.md, spec/ (language and format specs)
```

## Security

The auditor holds every configuration in an organisation, so it's built to pass its own audit.
See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and how to report a vulnerability.

## Licence

Apache-2.0 (see [LICENSE](LICENSE)). Every dependency, model and dataset is licence-verified;
framework content respects its licence (CIS and ISO: identifiers and our own wording only).
