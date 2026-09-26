# Kasauti (कसौटी)

**AI-Driven Multi-Vendor Network Security Compliance Auditor**
*हर डिवाइस, हर मानक की कसौटी पर*: every device, held to every standard.

Smart India Hackathon 2026 · Problem statement 26155 · National Technical Research Organisation (NTRO)

A *kasauti* is the touchstone used to test whether gold is pure. Kasauti tests whether a network
device's configuration meets CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001, for any vendor,
including ones it has never seen.

> **Status: Milestone 1 (walking skeleton) complete.** A Cisco IOS XE configuration goes end to
> end: parse → mappings → Security Baseline Model → 23 rules → JSON + PDF report. Parsers for all
> seven shape families are in place. Seed packs for Cisco IOS XE, Juniper Junos, Arista EOS,
> Fortinet FortiOS and Palo Alto PAN-OS (XML) take every default from the vendor's own documentation
> ([review records](docs/reviews/)). Progress is tracked task by task in
> [docs/TODO.md](docs/TODO.md).

## Try it

```bash
uv sync
uv run kasauti audit datasets/authored/cisco_ios_xe/weak.cfg --framework nist --out reports
```

```
EDGE-R1  (cisco_ios_xe@1, chosen by fingerprint)
  NIST SP 800-53 Rev. 5: compliance 0.0%, coverage 100.0% (0 pass, 21 fail, 0 review, 0 n/a)
  FAIL   high     MGMT-TELNET-01: Clear-text Telnet management is not reachable
  ...
  wrote reports/weak.kasauti.json
  wrote reports/weak.kasauti.pdf
```

Configurations rarely hold a serial number. Add the device's command outputs (`show version`,
`show inventory`, `get system status`, `show system info`, `show chassis hardware`) and the
report names the serial, model, exact release and every hardware component, each with the file
and line it came from. An output from another device is refused, with the reason:

```bash
C=datasets/authored/cisco_ios_xe
uv run kasauti audit $C/weak.cfg --companion $C/companions/show_version.txt \
    --companion $C/companions/show_inventory.txt --out reports
# EDGE-R1  (cisco_ios_xe@2, chosen by fingerprint)
#   model C8000V, serial 9KXQ2TGA7LM, release 17.09.04a
```

The web API runs on this machine only (the web screens arrive with M2.75):

```bash
uv run kasauti serve            # http://127.0.0.1:8000/api/health
uv run kasauti serve --workers 4  # background job processes (default 2; 0 for none)
uv run kasauti serve --worker-memory 4096  # MiB each job process may use (default 2048)
```

Long work (parsing uploads, bulk audits) runs as background jobs: the queue is a table in the
database, and each job runs in its own worker process, so a file that crashes or hangs the
parser stops only that job, and a file too large for a worker's memory fails its job with a
message saying so. `GET /api/jobs/{id}` reports a job's progress and `GET /api/jobs/{id}/result`
gives its result, sent gzip-compressed as it is stored (`curl --compressed`).

Uploading from a script (the web UI will do the same). Requests that change something need the
`X-Kasauti-Request: 1` header, so that no other website can send them through your browser:

```bash
H='X-Kasauti-Request: 1'
curl -s -X POST localhost:8000/api/uploads -H "$H" -H 'Content-Type: application/json' -d '{"label": "Q3"}'
# -> {"id": "<upload>", ...}
curl -s -X POST localhost:8000/api/uploads/<upload>/files -H "$H"      -H 'Content-Type: application/octet-stream' -H 'X-File-Name: core/r1.cfg' --data-binary @r1.cfg
curl -s -X POST localhost:8000/api/uploads/<upload>/start -H "$H"
curl -s localhost:8000/api/uploads/<upload>     # each file's audit state and job id
curl -s --compressed localhost:8000/api/jobs/<job>/result -o result.json
```

Send a folder file by file (named by its path), or as one `.zip`. Every file you send is listed,
and the ones that can't be audited say why. An uploaded configuration stays on disk only until its
audit reads it, and only encrypted, under a key the server keeps in memory; restarting the server
makes uploads not yet audited unreadable, so start them before a restart.

Audit history is kept in a SQLite file under `./var` (set `KASAUTI_DATA_DIR` to move it);
`kasauti serve` creates and upgrades it. For a shared PostgreSQL server instead:

```bash
uv sync --extra postgresql
export KASAUTI_DATABASE_URL='postgresql://kasauti@db.internal/kasauti?sslmode=verify-full'
uv run kasauti db upgrade       # run by the operator; `serve` won't migrate PostgreSQL itself
uv run kasauti db status        # exit 1 when the schema needs an upgrade
```

Every finding names the exact configuration lines (secrets masked), the NIST controls it
supports, and any vendor default it relied on. A missing or unreadable fact is never counted
as a pass: it becomes REVIEW, and the report says so. `datasets/authored/cisco_ios_xe/hardened.cfg`
is the same router with every weakness fixed.

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
uv run python tools/lint_content.py    # rule quality gate (runs every rule's fixtures) + crosswalk lint
cd eval && uv run python -m harness golden   # golden regression + zero-false-PASS gate
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
