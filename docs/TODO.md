# Kasauti (कसौटी): Build TODO

Companion to [PLAN.md](PLAN.md) v5.1 (frozen). This file turns the whole plan into tasks we can tick off. Created 2026-09-26.

**How this file works**
- Every task cites the plan section it comes from (`§x.y`) and, where one applies, the official requirement (`R-xx`, `D-x`).
- Tasks are grouped by milestone (PLAN §25), in build order: spine → pillars → stretch. A milestone is done when its **gate** is ticked, not when a date passes.
- The **coverage map** at the bottom lists every section of PLAN.md and the tasks that implement it. A section with no task is a bug in this file.
- If building proves the plan wrong, change PLAN.md first (log it in Appendix C), then this file.
- Status: `[ ]` to do · `[~]` in progress · `[x]` done · `[-]` dropped (write the reason and add an Appendix C entry).

**Work areas** (PLAN §24). The team is **one developer (you) + Claude** (decided 2026-09-26), so the tags mark the *area* of work, not a person. Claude writes most of the code; you review, decide, and run the demo.

| Tag | Area | Who |
|---|---|---|
| `@lead` | 1 · Lead / architect: SBM, mapping and rule languages, integration, final demo | You + Claude |
| `@parse` | 2 · Parsing & identity: ingestion, shape families, identity, manual ingester | You + Claude |
| `@ml` | 3 · AI/ML: signals, fusion, evaluation, LOVO, ablations | You + Claude |
| `@content` | 4 · Compliance & network content: rules, fixtures, crosswalks, importers, recipes | You + Claude |
| `@ui` | 5 · Frontend & UX: all screens, Training Studio, provenance drawer | You + Claude |
| `@sec` | 6 · Security, reporting & DevOps: hardening, signing, transparency log, PDF, CI, packaging, video | You + Claude |

---

## Standing rules (apply to every task, in every milestone)

- [ ] **S.01** Definition of done: unit and fixture tests, types, docs, security checks green, and reviewed. With a solo team, "reviewed" means: Claude does a separate review pass over the diff (as a fresh reviewer, not the author's view), **and** you read and approve it before merge. *(§23, adapted for a solo team)*
- [ ] **S.02** Branching: short-lived feature branch → PR → review → `main`. `main` stays demo-able from M1 on. *(§23)*
- [ ] **S.03** Before adding any dependency, model or dataset: verify its licence at the source (PyPI / npm / Hugging Face / GitHub) and add it to the PLAN §19 table. Permissive licences only; no GPL/AGPL/SSPL/RSAL and no custom model licences. *(§19, §19.5, §28, §3.1 principle 6)*
- [ ] **S.04** Every PR is checked against the seven principles: proof-carrying verdicts, absence ≠ safety, AI proposes / humans dispose / rules decide, content is data, deterministic core, offline and open, the auditor passes its own audit. *(§3.1)*
- [ ] **S.05** Non-goals guard. We don't write per-vendor parsers, send configs to cloud AI, let an LLM decide, auto-push fixes, run a blockchain network, show compliance % without coverage %, invent control IDs, copy CIS/ISO text, or build microservices. *(§3.2)*
- [ ] **S.06** Framework IDs come only from imported official catalogs. CIS and ISO content is IDs plus our own wording, never copied text. *(§3.2, §12.2, §20.1)*
- [ ] **S.07** Every dataset file gets a line in `datasets/SOURCES.md` (source, licence, SHA-256). *(§20.2)*
- [ ] **S.08** Keep the repo **private** until submission. *(§26, §28)*
- [ ] **S.09** Plan change control: PLAN.md changes only on evidence (a milestone result, a failed assumption, a new official requirement), and every change is logged in Appendix C. *(PLAN header, Appendix C)*
- [ ] **S.10** Determinism: same input + same KB version + same rule-set version → byte-identical results. The golden tests enforce it. *(§3.1 principle 5)*
- [ ] **S.11** Offline: the core makes no network calls at runtime, and tests run with the network disabled. *(§3.1 principle 6, §17 air gap)*
- [ ] **S.12** Laptop limits: native dev day to day, Docker only for packaging. Don't commit model weights. Watch the ~30 GB free disk and ~3 GB free RAM. *(Appendix B, §28)*

---

## Decisions to close (PLAN §29)

- [x] **DEC.1** Product name: **Kasauti (कसौटी)**, decided 2026-09-25.
- [x] **DEC.2** Team: **one developer + Claude**, decided 2026-09-26. Every task is ours; the tags mark work areas (§24).
- [x] **DEC.3** NCIIPC outreach: **you**, by email only, since the site doesn't open for us (C.01). Claude drafts the email. Decided 2026-09-26.
- [ ] **DEC.4** Does live collection make the demo? Depends on lab availability and disk. *Decide at the M5 gate* (X.04, X.05).
- [ ] **DEC.5** What evaluators run: Docker image or native installer. *Decide before M7* (M7.06).

---

## Tech stack at a glance (PLAN §19; licences verified 2026-09-25)

Every item below is installed or used by a task in this file. Re-verify each licence at install time (S.03).

| Layer | What we use | Licence | Tasks |
|---|---|---|---|
| Language / runtime | Python 3.12, Node 20 | PSF, MIT | M0.03, M2.75 |
| API server | FastAPI, Uvicorn, python-multipart | MIT, BSD-3, Apache-2.0 | M2.01 |
| Schema | Pydantic v2 | MIT | M0.13 |
| Database | SQLAlchemy 2 + Alembic; SQLite (WAL, default) / PostgreSQL via psycopg 3 | MIT; public domain; PostgreSQL; LGPL-3.0 (unmodified) | M2.02 |
| Workers | multiprocessing pool + DB job table (no broker, no Redis) | PSF | M2.03, M5.02 |
| Pattern keys | in-house, keyword-literal (Drain3 dropped, PLAN v5.1.3) | ours | M1.03 |
| Encoding detection | charset-normalizer | MIT | M1.01 |
| Show-output parsing | TextFSM, ntc-templates, TTP | Apache-2.0, Apache-2.0, MIT | M2.19 |
| XML / YAML | defusedxml (SAX), PyYAML (safe loader, aliases refused) | PSF, MIT | M2.07, M2.14, M2.15 |
| Safe regex | google-re2 (in use since M1 for `matches` and fingerprints) | BSD-3 | M1.10, M3.03, M5.06 |
| Templates | Jinja2 (SandboxedEnvironment) | BSD-3 | M4.02, M5.07 |
| Remediation | hier_config; Aerleon | MIT; Apache-2.0 | M4.07, M4.12 |
| PDF + charts + signing | ReportLab, matplotlib, pyHanko | BSD, PSF-style, MIT | M1.13, M2.74, M5.12 |
| Crypto | cryptography (AES-256-GCM, Ed25519) | Apache-2.0 / BSD-3 | M5.01, M5.08, M5.14 |
| Auth | argon2-cffi, pyotp | MIT, MIT | M5.03 |
| Logging | structlog | MIT / Apache-2.0 | M0.04 |
| Live collection (stretch) | NAPALM, Netmiko (Paramiko) | Apache-2.0, MIT (LGPL-2.1 unmodified) | X.04 |
| Embeddings runtime | sentence-transformers | Apache-2.0 | M3.11 |
| Embedding models (benchmark) | Qwen3-Embedding-0.6B, granite-embedding-small-english-r2, SecureBERT2.0-biencoder, bge-small-en-v1.5 | Apache-2.0 ×3, MIT | M3.11 |
| Rerankers (benchmark) | Qwen3-Reranker-0.6B, bge-reranker-v2-m3 | Apache-2.0 | M3.11 |
| Classical ML | scikit-learn, numpy | BSD-3 | M3.18, M3.12 |
| Few-shot fine-tune | SetFit / sentence-transformers trainer | Apache-2.0 | M3.15 |
| Calibration | MAPIE | BSD-3 | M6.05 |
| Label audit | cleanlab | Apache-2.0 | M3.26 |
| Fuzzy matching | rapidfuzz | MIT | M2.61 |
| Model files | safetensors | Apache-2.0 | M3.13, M5.09 |
| LLM (stretch, optional) | Ollama / llama.cpp; Granite 4.2-3B or Qwen3.5-4B | MIT; Apache-2.0 | X.02 |
| Frontend | React 19, Vite, TypeScript, Tailwind 4, Radix + shadcn/ui, TanStack Query/Table, Zustand, Recharts, Monaco, react-dropzone, lucide | MIT (TypeScript Apache-2.0, lucide ISC) | M2.75 |
| Frontend tests | Vitest, Playwright | MIT, Apache-2.0 | M2.75, M6.11 |
| Python tooling | uv, ruff, mypy, pytest, Hypothesis, pre-commit | MIT / Apache-2.0 / MPL-2.0 (Hypothesis) | M0.03 |
| JS tooling | eslint, prettier | MIT | M2.75 |
| Security CI | CycloneDX, pip-audit, npm audit, bandit, gitleaks, trivy | Apache-2.0 / MIT | M0.06, M2.75 |
| Packaging | Docker Compose | Apache-2.0 | M7.06 |
| **Still to choose** | Encoding detection (M1.01); PDF text extraction for manuals (M3.02, not PyMuPDF) | Verify first, then log in PLAN Appendix C | M1.01, M3.02 |
| **Our own licence** | Apache-2.0 | | M0.01 |

---

## Datasets named in the PS → where we handle them

The PS's dataset line: *nciipc.gov.in, helpdesk1@nciipc.gov.in; CIS Benchmarks, NIST SP 800-53, DISA STIGs, ISO/IEC 27001; vendor-specific CLI configuration samples.*

| PS dataset | Licence / status | What we ship | Tasks |
|---|---|---|---|
| **nciipc.gov.in** | Unreachable from our machines: connection refused (2026-09-25) and timed out from the dev laptop (2026-09-26). Try from a normal browser on another network (mobile data / college network) | An NCIIPC framework pack if content is obtained and its use is permitted | C.01, C.02 |
| **helpdesk1@nciipc.gov.in** | Email outreach by a human teammate | Ask for published guidelines, sanctioned sample configs, or a hardening baseline | C.01 |
| **CIS Benchmarks** | CC BY-NC-SA 4.0 (free PDFs) | Recommendation IDs + our own wording + attribution; no copied text | C.04, M2.54, M2.70 (attribution) |
| **NIST SP 800-53 r5** | Public domain / CC0 (official OSCAL JSON) | Full catalog; the hub every rule anchors to | M2.50, M2.48, M6.08 |
| **DISA STIGs** (+ CCI list) | US Government work, public domain | Titles, severity (CAT → base severity), check/fix text, CCIs | C.03, M2.51, M2.52, M2.49, M4.04 |
| **ISO/IEC 27001:2022** | Copyrighted standard | Annex A control numbers + our own short descriptions, derived via NIST OLIR #155 | M2.53, M2.55 |
| **Vendor-specific CLI configuration samples** | Varies per source; each file recorded in `datasets/SOURCES.md` | (1) authored hardened/weak configs per seed vendor, (2) Batfish example configs (Apache-2.0), (3) mutation-generated violations, (4) containerised NOS labs (stretch), (5) NCIIPC samples if given, (6) NAssim manuals for the unseen demo | M0.23, M2.26–M2.33, M4.23, X.05, C.01, M3.01, C.07 |

---

## M0 · Foundations

**Exit criteria (§25):** private repo + CI + security scanners; SBM v0; mapping and rule languages v0; pack format frozen; 3 authored configs; eval harness skeleton; `SECURITY.md` draft.

### Repo and tooling
- [~] **M0.01** `git init`; private GitHub repo `kasauti`; Apache-2.0 `LICENSE`; `.gitignore` for model weights, vault, `*.db` and raw datasets. *(§19.4, §23, §26, D-1)* `@sec` **Done locally:** git repo, Apache-2.0 `LICENSE` (official text, SHA-256 `cfc7749b…3d30`), `NOTICE`, `.gitignore`, `.gitattributes`. **Open:** creating the private GitHub repo needs your GitHub login (GitHub CLI not installed).
- [x] **M0.02** Create the repo layout exactly as in §23: `backend/kasauti/{ingest,shape,identity,mapping,semantic,studio,sbm,rules,policy,remediation,report,trust,packs,auth,api,cli}`, `frontend/`, `packs/{vendors,frameworks,rules}`, `datasets/{authored,batfish,mutations,SOURCES.md}`, `eval/{harness,reports}`, `tools/{import_oscal,import_stig,import_cci,import_olir,ingest_manual,mutate,sign_pack}`, `docs/{PLAN.md,ARCHITECTURE.md,SECURITY.md,archive/}`, `README.md`, `LICENSE`, `docker-compose.yml`. Move the existing `docs/` in. *(§23, §4.3)* `@lead` Done 2026-09-26. `docker-compose.yml` is created with packaging in M7.06 rather than as an empty placeholder.
- [x] **M0.03** Python 3.12 project on uv with a hash-locked lockfile; ruff, mypy (strict on the core), pytest, Hypothesis; pre-commit hooks. *(§19.4)* `@sec` Done 2026-09-26 (uv 0.12.5, `uv.lock` committed, pre-commit hooks in `.pre-commit-config.yaml`).
- [x] **M0.04** Logging with structlog; secrets never logged. *(§19.1, §17)* `@sec` Done: `kasauti/log.py` with a secret-redaction processor, tested.
- [~] **M0.05** CI pipeline: lint, types, tests. *(§23)* `@sec` Written (`.github/workflows/ci.yml`) and every step verified locally; first real run once the GitHub repo exists.
- [~] **M0.06** CI security scanners: pip-audit, bandit, gitleaks, trivy, plus a CycloneDX SBOM artefact. *(§17 supply chain, §19.4)* `@sec` Written; pip-audit (0 known vulnerabilities in the locked set), bandit (0 issues) and SBOM verified locally. gitleaks and trivy run as digest-pinned containers on GitHub (Docker isn't running locally).
- [x] **M0.07** CI licence check on the lockfile. Allowlist MIT/BSD/Apache/PSF/ISC, plus LGPL for unmodified psycopg and Paramiko, and MPL-2.0 for the dev-only Hypothesis (verified on PyPI 2026-09-26). Denylist the rejected items from §19.5 (ciscoconfparse2, PyMuPDF, redis, WeasyPrint, and Llama/Gemma model files). The other §19.5 rejections are design choices guarded by S.05, M2.33, M3.12 and M5.04: cloud LLM APIs, Batfish as the core parser, FAISS/pgvector, JWT in the browser, microservices. *(§19.5, §28)* `@sec` Done: `tools/check_licences.py`. Strict for the 7 runtime dependencies; dev-only tools may use unmodified LGPL/MPL (e.g. chardet via cyclonedx-bom). Tested.
- [x] **M0.08** Wire the CI job stubs now (filled in later): rule quality gate (M2.46), crosswalk lint (M2.57), golden regression (M1.16). *(§23)* `@sec` Done: rule quality gate + crosswalk lint (`tools/lint_content.py`), golden regression (`pytest -m golden`), schema drift check. All real, all tested.
- [x] **M0.09** PR template: definition-of-done checklist, principles (S.04), non-goals (S.05), licence line (S.03). *(§23)* `@lead` Done: `.github/pull_request_template.md`.
- [x] **M0.10** `datasets/SOURCES.md` template: file, source URL, licence, SHA-256, date, notes. *(§20.2)* `@content` Done, plus a CI test that fails if any dataset file is unlisted or its hash changed.
- [x] **M0.11** `SECURITY.md` draft: threat model built from the §17 asset/attack/control table, OWASP ASVS L2 as the checklist, how to report vulnerabilities, and what "verified" means (§14.6). *(§17)* `@sec` Draft done: `docs/SECURITY.md` (threat model with delivering milestone per control; private reporting via GitHub advisory).
- [x] **M0.12** README developer section with the measured environment: Python 3.12.8, Node 20, native dev, Docker for packaging only. *(Appendix B)* `@sec` Done: `README.md`.

### Specs frozen at v0
- [x] **M0.13** SBM v0 as Pydantic v2 models for **every** §8.1 entity with its listed attributes: `Device`, `MgmtService`, `MgmtSession`, `Interface`, `LocalUser`, `AuthServer`, `LogTarget`, `TimeSource`, `SnmpCommunity`, `SnmpUser`, `CryptoProfile`, `FilterRule`, `Banner`, `PasswordPolicy`, `LockoutPolicy`, `RoutingAuth`, `L2Port`, `Tunnel`. *(§8.1, R-01)* `@lead` Done: `kasauti/sbm/entities.py`, 20 entity types (§8.1's 18 + `LoggingPolicy`, `ObjectDef`; see `docs/spec/sbm.md`).
- [x] **M0.14** `Fact` type: `{value, state: explicit | vendor_default | absent | unknown, evidence: [{file, lines, raw, mapping_id@version, approved_by}]}`. *(§8.2)* `@lead` Done: state/evidence combinations are enforced by the model.
- [x] **M0.15** SBM versioning: a `sbm_version` field plus a migration mechanism. *(§8.4)* `@lead` Done: `sbm_version` 0.1 + `kasauti/sbm/migrations.py`.
- [x] **M0.16** OpenConfig alignment table (SBM attribute → OpenConfig path, e.g. `/system/ssh-server/config/protocol-version`, `/system/telnet-server/config/enable`, `/system/aaa`, `/system/logging`, `/system/ntp`) and the `x-sbm` extension list for everything else (hash types, lockout, rule hygiene). *(§8.4)* `@lead` Done: `kasauti/sbm/openconfig.yaml`, paths checked against openconfig/public; a test fails if any attribute is unmapped.
- [x] **M0.17** Derivation format (small, versioned formulas; derived facts carry the union of their inputs' evidence) and the first derivation, `management.telnet_reachable`. *(§8.3)* `@lead` Done: `kasauti/rules/derivation.py` + `packs/derivations/management.yaml`.
- [x] **M0.18** Mapping language v0 spec + JSON Schema. It covers:
  - the six primitives (`entity`, `set`, `assert`, `members`, `negation`, `default`)
  - `ref`
  - transforms: value maps, boolean inversion, unit normalisation, list splitting, case folding
  - typed slots `<INT> <IP> <IFNAME> <STR> <LIST>`
  - `context`, `os_versions` and `provenance`

  The stored form follows §9.3. *(§9.1, §9.3, §9.4, R-01, R-08)* `@lead` Done: `kasauti/mapping/model.py`, `docs/spec/mapping-language.md`, JSON Schema.
- [x] **M0.19** Turn the §9.2 worked example into spec tests: all 8 telnet rows as mapping YAML plus expected facts. They go green over M1–M3. *(§9.2)* `@lead` Done: `backend/tests/spec/test_worked_example_9_2.py`. The mappings validate now; the 10 engine cases are strict-xfail until M1.
- [x] **M0.20** Rule language v0 spec + JSON Schema:
  - Fields: `id`, `title`, `intent`, `for_each`, `where`, `assert`, `on_absent`, `on_unknown`, `severity.base`, `exposure`, `fix_intent`, `refs` (`nist_800_53r5`, `disa_stig`, `cis`, `iso_27001_2022`), `fixtures{pass,fail}`.
  - Declarative operators only: `== != < <= in ∋ any all none count matches exists`.
  - No `eval`.

  *(§12.1, R-02)* `@lead` Done: `kasauti/rules/{expr,model}.py` (parser, static type checker, no eval), `docs/spec/rule-language.md` including four-valued evaluation semantics.
- [x] **M0.21** Freeze the pack format. It covers the layout and JSON Schemas for:
  - `pack.yaml`, `detect.yaml`, `identity.yaml`, `defaults.yaml`, `mappings/*.yaml`, `recipes/*.yaml`, `verify.yaml`, `manual/`
  - `frameworks/<fw>/catalog.json` and `crosswalk.yaml`
  - `rules/*.yaml`

  What each file holds:
  - `pack.yaml`: shape family, negation words (`no`, `undo`, `unset`, `delete`, `disable`, `disabled=yes`), comment markers, unit conventions
  - `detect.yaml`: fingerprint signatures
  - `identity.yaml`: where hostname, version, model and serial appear (config and show outputs)
  - `defaults.yaml`: vendor defaults scoped by OS version range
  - `recipes/`: fix intents → command sequences, scoped by OS version
  - `verify.yaml`: pre-check and verify show-commands per domain
  - `manual/`: an optional ingested command-manual corpus
  - `catalog.json`: official control IDs and titles (licence-safe)
  - `crosswalk.yaml`: our rule IDs → framework control IDs, with their source

  Packs are data only: no code, no pickle. *(§4.4, R-08)* `@lead` Done: `kasauti/packs/{model,loader}.py`, `docs/spec/pack-format.md`, 12 JSON Schemas in `docs/spec/schemas/`.
- [x] **M0.22** Pipeline core interfaces (ports and adapters): pure functions text → tree → facts → findings → fixes, with no I/O in the core. *(§4.1, §4.2)* `@lead` Done: `kasauti/pipeline.py`.

### Data and evaluation
- [x] **M0.23** Three authored configs, peer-reviewed and in SOURCES: Cisco IOS-XE hardened, Cisco IOS-XE weak (for M1), and one Junos config to keep the SBM honest. *(§20.2, §25)* `@content` Done: `datasets/authored/cisco_ios_xe/{hardened,weak}.cfg`, `juniper_junos/hardened.conf`, with 20 catalogued weaknesses in SOURCES.md. Vendor-doc cross-check is tracked in C.06.
- [x] **M0.24** Eval harness skeleton in `eval/harness`:
  - a dataset registry for E1–E5
  - metric functions: false-PASS rate, precision/recall, coverage, Recall@k, fix success
  - a report writer to `eval/reports`

  *(§21)* `@ml` Done: `eval/harness` (E1–E5 registry, metrics as num/den ratios, report writer), tested.
- [x] **M0.25** Close DEC.2 and DEC.3 and fill the owner table. Done 2026-09-26. *(§24, §29)* `@lead`

- [ ] **M0.G · Gate:** every M0 exit criterion met.

---

## M1 · Walking skeleton

**Exit criteria (§25):** one Cisco config → tree → mappings → SBM → 10 rules → unsigned PDF, end to end. **Fallback:** simplify the entity model before adding breadth.

- [x] **M1.01** Minimal ingest: read the file, SHA-256, encoding detection, binary sniffing. Use **charset-normalizer** (MIT, verified on PyPI 2026-09-26), not chardet, which is LGPL. *(§5.2)* `@parse` Done: `kasauti/ingest/read.py`. 20 MB limit checked before reading, BOM-aware decoding, charset-normalizer fallback, binary sniffing. Tested.
- [x] **M1.02** Indent-family parser → Universal Config Tree. Statement = `{path, tokens, text, line_start, line_end, family}`, with `!`/`#` separators. *(§6.1, §6.2)* `@parse` Done: `kasauti/shape/indent.py`. Headers are statements too; Cisco delimited banners are one multi-line statement, so banner text is never read as config.
- [x] **M1.03** Drain3 pattern keys that abstract `<INT> <IP> <IFNAME> <STR> <LIST>`. Test: 48 interface blocks collapse into one pattern. *(§6.2)* `@parse` Done without Drain3 (PLAN v5.1.3): `kasauti/shape/patterns.py`, keyword-literal typed keys built from masked text. Tests: 48 interfaces → `interface <IFNAME>`; `ip ssh version` and `ip ssh time-out` stay apart.
- [x] **M1.04** Cisco identity from the config (hostname, version). *(§7 source 3)* `@parse` Done: `kasauti/identity/{detect,resolve}.py`. Fingerprint from `detect.yaml` (ties are never guessed); hostname and version from `identity.yaml`, each with its source line.
- [x] **M1.05** Mapping compiler and matcher: all six primitives and all transforms. Unit tests: `exec-timeout 10 0` → 600 s; FortiOS `admintimeout 5` (minutes) → 300 s; `enable/disable` → true/false value map; boolean inversion `disable-telnet yes` → telnet false. *(§9.1)* `@lead` Done: `kasauti/mapping/{match,effects,engine}.py`. All six primitives + `ref`, value maps with `otherwise`, `invert`, units, weighted sums, split, specificity, auto and explicit negation, near misses → *unknown*. The four named unit tests are in `backend/tests/mapping/test_engine.py`; the §9.2 spec (10 cases, 7 families) is green.
- [x] **M1.06** Fact emission with evidence (file, lines, raw, `mapping_id@version`, approved_by). *(§8.2, §3.1 principle 1)* `@lead` Done: every fact carries file, lines, masked raw text, `mapping_id@version` and approvers; entities carry the lines that named them.
- [x] **M1.07** Defaults resolver with `os_versions` ranges, producing the `vendor_default` state. *(§8.2, §9.4)* `@lead` Done: `kasauti/mapping/defaults.py`. Version-scoped; unknown version → only `*` defaults; conflicting entries are ignored and reported; `none_of` for closed-world types.
- [x] **M1.08** Derivation engine, starting with `telnet_reachable`. *(§8.3)* `@lead` Done: `kasauti/rules/evaluate.py`. Four-valued Kleene evaluation with witnesses; `telnet_reachable` plus four more derivations in `packs/derivations/`.
- [x] **M1.09** Seed Cisco IOS-XE mappings that cover the first 10 rules. *(§20.4)* `@content` Done: `packs/vendors/cisco_ios_xe/` with 62 mappings in 4 files, 7 curated defaults (each with a reference), fingerprint and identity sources.
- [x] **M1.10** Rule engine: `for_each` / `where` / `assert`, `on_absent`, `on_unknown` → PASS / FAIL / REVIEW / N/A, giving per-entity findings with exact lines. *(§12.1, §12.6, §3.1 principle 2)* `@lead` Done: `kasauti/rules/engine.py`. Per-entity findings with exact lines, expected vs actual; the defaults view only for `resolve_default`; unapproved mappings → REVIEW; nothing in scope → N/A unless statements were unread.
- [x] **M1.11** First 10 rules, including `MGMT-TELNET-01` and `MGMT-SESSION-TIMEOUT-01`, each with Cisco pass and fail fixtures. Write `MGMT-TELNET-01` exactly as in §12.1 (NIST CM-7, AC-17(2), SC-8; exposure `telnet_on_untrusted_interface`; `fix_intent`). NIST refs only for now. *(§12.1, §12.2, R-02)* `@content` Done: 10 rules in `packs/rules/` covering W3–W6, W8, W12–W15, W17–W19, each with a pass and a fail fixture that the content gate now *executes*. NIST refs checked against the official catalog (imported early: M2.50).
- [x] **M1.12** Compute Compliance % and Coverage % together, always. *(§12.6)* `@lead` Done: `kasauti/rules/scoring.py`. Both numbers per framework, plus the NIST control roll-up.
- [x] **M1.13** Unsigned ReportLab PDF: cover/device profile, summary, and findings with evidence lines. *(§15.1 partial, R-07)* `@sec` Done: `kasauti/report/pdf.py`. All seven §15.1 sections at M1 depth, config text escaped, byte-reproducible, and marked unsigned on the cover.
- [x] **M1.14** CLI: `kasauti audit router.cfg --framework nist`. *(§4.2)* `@lead` Done: `kasauti audit router.cfg --framework nist [--vendor] [--out] [--date] [--no-pdf]`. Exit 1 with a readable message on bad input.
- [x] **M1.15** Determinism test: two runs → byte-identical JSON. *(§3.1 principle 5, S.10)* `@lead` Done: `test_two_runs_are_byte_identical_json_and_pdf`. `audit()` is pure; the report date is passed in.
- [x] **M1.16** First E1 golden snapshot, with the golden-regression CI job live. *(§21.1, §23)* `@ml` Done: `datasets/golden/cisco_ios_xe_{weak,hardened}/`, with hand labels from the W1–W20 catalogue and reviewed snapshots; `python -m harness golden [--update]`; the CI golden job runs `pytest -m golden`.
- [x] **M1.17** Zero-false-PASS gate: CI fails on any false PASS in E1 (E3 is added in M4.23). *(§21.3, §28)* `@ml` Done: `test_zero_false_pass` per golden case; the false-PASS rate is 0/10 on the weak case.

- [x] **M1.G · Gate:** end-to-end run works from the CLI, and `main` is demo-able from here on. Passed 2026-09-26: weak.cfg → 10/10 FAIL (0% compliance, 100% coverage), hardened.cfg → 10/10 PASS, with every local CI gate green.

---

## M2 · Spine

**Exit criteria (§25):** 7 seed vendors, ~50 rules with fixtures, 4 frameworks via the crosswalk hub, identity resolver, PDF v1, Studio v1 (teach, approve, hot reload), dashboard. **Fallback:** cut to 5 seed vendors, but keep SONiC and AWS because they're the PS's own examples.

### 2A · Server, storage, workers
- [ ] **M2.01** FastAPI + Uvicorn + python-multipart app, bound to localhost by default. *(§19.1, §17 exposure)* `@lead`
- [ ] **M2.02** SQLAlchemy 2 + Alembic. SQLite in WAL mode by default; PostgreSQL as an option via psycopg 3. *(§4.2, §19.1)* `@lead`
- [ ] **M2.03** Worker pool on multiprocessing with a DB job table, no broker. *(§4.2, §19.1)* `@lead`

### 2B · Ingestion (§5, R-04)
- [ ] **M2.04** Upload API: single file, bulk, `.zip` and folder. Accepted types: `.txt .cfg .conf .log .xml .json .yaml`. *(§5.1)* `@parse`
- [ ] **M2.05** Companion files: `show version`, `show inventory`, `get system status`, `show system info`, `show chassis hardware`, `display version`, `display esn`. *(§5.1, §7)* `@parse`
- [ ] **M2.06** Group files into devices by hostname and filename stem, with a manual correction UI. *(§5.1)* `@parse` `@ui`
- [ ] **M2.07** Input limits:
  - file size, archive entries and nesting depth
  - zip-slip path normalisation
  - defusedxml (XXE, billion laughs)
  - encoding detection and binary sniffing

  *(§5.2)* `@parse`
- [~] **M2.08** Kind-preserving secret masking (`password 7 ****`, `secret 9 ****`, `snmp community ****(RO)`), so reversible-password rules still work. *(§5.2)* `@parse` First cut done in M1 (`kasauti/ingest/mask.py`, vendor-generic, with tests); evidence, pattern keys and reports only ever show masked text. Per-vendor review pending.
- [ ] **M2.09** Acceptance test: 100 mixed files including a zip all get ingested; malformed files are reported and nothing crashes. *(R-04 AC)* `@parse`

### 2C · Shape families (§6.1)
- [x] **M2.10** Brace family: Junos, VyOS, PAN-OS CLI. `@parse` Done early (M1, needed by the §9.2 spec): `kasauti/shape/brace.py`, with comments, `inactive:` (ignored, as the device does) and `protect:`.
- [x] **M2.11** Set-path family: `set` forms of Junos/VyOS/PAN-OS, Check Point Gaia, Extreme EXOS. `@parse` Done early (M1): `parse_set_path`; only `set` is dropped, so `delete`/`deactivate` act as negation words.
- [x] **M2.12** Block-edit family: FortiOS `config / edit / set / next / end`. `@parse` Done early (M1): `parse_block_edit`, including multi-line quoted values.
- [x] **M2.13** Path-command family: MikroTik `/ip service` + `set … key=value`. `@parse` Done early (M1): `parse_path_command`; both export styles and `\` continuations; `key=value` → `key=` `value`.
- [x] **M2.14** XML family: PAN-OS XML, pfSense/OPNsense, Sophos (defusedxml + lxml). `@parse` Done early (M1) with defusedxml's SAX parser (DTDs and entities forbidden) for line numbers; lxml isn't needed.
- [x] **M2.15** JSON/YAML family: SONiC `config_db.json`, AWS/Azure/GCP exports, Meraki API, Cumulus NVUE (PyYAML `safe_load` only). `@parse` Done early (M1): composed with SafeLoader, aliases refused, named list items rendered as `key <name>`.
- [x] **M2.16** Flat fallback: one statement per line. `@parse` Done early (M1): the flat fallback, used automatically when a family's parser rejects the text, with the reason kept as a warning.
- [~] **M2.17** Family detection by scoring: indent regularity, brace balance, `config/edit/next/end` markers, XML/JSON validity, leading `set` or `/`. Tested on every corpus. *(§6.1)* `@parse` Scoring detector done early (M1) and tested on every current corpus and six family samples; re-test as corpora grow.

### 2D · Identity (§7, R-07a)
- [~] **M2.18** Vendor/OS fingerprinting from `detect.yaml`. *(§7, §4.4)* `@parse` Engine done early (M1) for all five signature kinds; only the Cisco pack exists yet.
- [~] **M2.19** Identity resolver, in priority order: Source 3 (config) done early (M1) with a source per field; companion outputs and manual entry pending.
  1. live facts (stretch, X.04)
  2. companion show outputs via TextFSM / ntc-templates / TTP, else the mapping language
  3. config headers: FortiGate `#config-version`, Junos `version`, PAN-OS XML `version` attributes, Cisco `version`/`hostname`, SONiC `DEVICE_METADATA`
  4. manual entry

  The source is recorded for each field. *(§7)* `@parse`
- [x] **M2.20** A missing field is stated explicitly, never left blank: "Serial: not present in supplied artefacts; upload `show inventory` to populate". *(R-07a AC)* `@parse` Done early (M1): missing fields are stated with what to upload, e.g. "Serial: not present in supplied artefacts; upload `show inventory` or `show version` to populate".
- [ ] **M2.21** UI for manual identity entry. *(§7 source 4)* `@ui`
- [~] **M2.22** Role inference (router / switch / firewall / cloud filter / white-box), which drives rule applicability and report sections. *(§7)* `@parse` Engine done: data-driven inferences (`packs/inferences/roles.yaml`, `kasauti/rules/enrich.py`) for untrusted interfaces (zone/description) and device role (zones → firewall, L2 ports → switch), plus a pack `default_role`. Public-address and default-route signals come with the packs that carry addresses.

### 2E · Mapping and SBM, completed
- [~] **M2.23** `ref` primitive and reference resolver: Resolver done (`kasauti/mapping/resolve.py`): `Reference` entities (SBM 0.4), dangling detection, vty → ACL → permits-any chain, recursive group expansion with cycle detection; rules REF-DANGLING-01, MGMT-VTY-ACL-02; tests. The Cisco case is live; the FortiOS, PAN-OS, AWS and Huawei cases land with their packs.
  - link references to their targets
  - expand address/service objects and groups recursively, with cycle detection
  - raise dangling-reference findings
  - support derivation chains such as vty → ACL → permitted sources
  - test cases from the plan's own examples: Cisco `access-class MGMT-ACL in` on a vty line; FortiOS `set srcaddr "LAN_GRP"`; PAN-OS `<source><member>web-servers</member>`; AWS security groups referenced by other groups; Huawei `user-interface … acl 2001`

  *(§9.1, v5.1)* `@lead`
- [x] **M2.24** Version-scoping test: two OS versions of one vendor resolve mappings and defaults differently. *(§9.4, R-08)* `@lead` Done early (M1): `test_two_os_versions_resolve_mappings_and_defaults_differently`.
- [x] **M2.25** Run one real SBM migration (v0 → v1). *(§8.4)* `@lead` Done early (M1): SBM 0.1 → 0.2 (entity evidence, `TimePolicy`, `known_empty`, `unread`), with a test that a stored 0.1 document loads unchanged.

### 2F · Seed vendor packs (§20.4)
Each pack has `pack.yaml`, `detect.yaml`, `identity.yaml`, version-scoped `defaults.yaml`, `mappings/`, `verify.yaml`, authored hardened and weak configs, and a pass and fail fixture for every applicable rule. `@content` with `@parse`
- [~] **M2.26** Cisco IOS-XE (indent) Pack v2 done early: 94 mappings, 15 defaults quoted from Cisco docs plus 3 model defaults, reviewed (`docs/reviews/cisco_ios_xe.md`); a pass and a fail fixture executed for all 21 rules. Remaining: NX-OS/IOS separation in `detect.yaml` once those packs exist.
- [ ] **M2.27** Arista EOS (indent)
- [ ] **M2.28** Juniper Junos/SRX (brace + set-path)
- [ ] **M2.29** Fortinet FortiOS (block-edit)
- [ ] **M2.30** Palo Alto PAN-OS (XML)
- [ ] **M2.31** AWS security groups + NACLs (JSON)
- [ ] **M2.32** SONiC `config_db.json` (JSON)
- [ ] **M2.33** Import the Batfish example configs (Apache-2.0) into `datasets/batfish` as data only, with SOURCES entries. *(§20.2, §19.5)*
- [ ] **M2.34** Golden SBM snapshots for all seeds: the same posture written in 7 syntaxes gives identical SBM facts. *(R-01 AC, §21.1 E1)* `@ml`
- [ ] **M2.35** CI guard: no Huawei VRP or MikroTik pack in the seeds, because they're the unseen-vendor demo. *(§20.4)* `@sec`

### 2G · Rules: about 50 in 10 domains (§12.3)
Every rule has intent, official refs, `on_absent`/`on_unknown`, a pass and a fail fixture per applicable seed vendor, and a `fix_intent`. `@content`
- [ ] **M2.36** Management plane
- [ ] **M2.37** AAA
- [ ] **M2.38** Logging, including "log all admin access" (a PS example)
- [ ] **M2.39** Time
- [ ] **M2.40** SNMP
- [ ] **M2.41** Services, including disabling Telnet/HTTP (a PS example)
- [ ] **M2.42** Crypto, including strong crypto suites and `ssh_version == 2` (PS examples)
- [ ] **M2.43** Filtering, including granular ACLs (a PS example)
- [ ] **M2.44** L2
- [ ] **M2.45** Routing authentication
- [ ] **M2.46** Rule quality gate live in CI: all required fields, fixtures per seed vendor, a fix intent. A check with no benchmark is labelled "hardening best practice", never given an invented number. *(§12.2)* `@sec`
- [ ] **M2.47** Applicability by role and feature. N/A rules are listed, not hidden. *(§12.5)* `@lead`
- [ ] **M2.48** Per-framework scoring, and NIST control roll-up (satisfied / partially satisfied). *(§12.6)* `@lead`
- [x] **M2.49** Severity = base × exposure: Done: `packs/exposures/exposures.yaml` + `adjust_severity`; one level per exposure, capped, missing facts never trigger; the reason reads "High (base) → Critical: …". STIG CAT-based bases arrive with the STIG import (M2.51).
  - **Base:** STIG CAT I → High, II → Medium, III → Low; otherwise our reviewed rating.
  - **Raised:** when the weakness is reachable from an untrusted interface or zone (inferred from zone names like untrust/outside/wan, public addressing and default-route egress; the admin can override), and for perimeter-firewall roles.
  - **Lowered:** when a compensating control exists.
  - **Shown:** as a derivation string, e.g. "High (base) → Critical: telnet on `wan1` (untrusted)".

  *(§12.7, R-07b)* `@lead`

### 2H · Crosswalk hub (§12.4, R-06)
- [x] **M2.50** `tools/import_oscal`: NIST SP 800-53 r5 OSCAL catalog → `frameworks/nist_800_53r5/catalog.json`. *(§20.1)* `@content` Done early (M1): `tools/import_oscal.py`; official OSCAL 5.2.0 at a pinned commit, 1,014 active controls, IDs and titles only, with the source SHA-256 recorded.
- [ ] **M2.51** `tools/import_stig`: XCCDF for each seed vendor's STIG → titles, severity, check/fix text, CCIs. *(§20.1)* `@content`
- [ ] **M2.52** `tools/import_cci`: the DISA CCI list, translated from Rev4 to Rev5 through NIST's mapping, with gaps flagged. *(§12.4)* `@content`
- [ ] **M2.53** `tools/import_olir`: NIST OLIR #155 → derived ISO/IEC 27001:2022 refs, then human review. *(§12.4)* `@content`
- [ ] **M2.54** CIS: recommendation IDs per vendor and version from the free benchmark PDFs, in our own wording, with attribution (CC BY-NC-SA). *(§12.4, §20.1)* `@content`
- [ ] **M2.55** ISO/IEC 27001:2022: Annex A control numbers plus our own short descriptions only. *(§20.1)* `@content`
- [ ] **M2.56** Rule ↔ STIG matching. Proposals are lexical at M2 and semantic from M3.31; a human confirms each one. Consistency check: the STIG's CCIs → NIST must overlap our NIST anchors. *(§12.4)* `@content`
- [ ] **M2.57** Crosswalk lint in CI: rejects unknown IDs, missing NIST anchors and inconsistent STIG↔NIST pairs. *(§12.4)* `@sec`
- [ ] **M2.58** Framework selection end to end: toggling frameworks changes the report's control matrix, and every control ID traces to an official source. *(R-06 AC)* `@lead`

### 2I · Training Studio v1 (§11, R-03, R-05)
- [ ] **M2.59** Signal S1 (structure): block context, negation form, pattern key, value types. *(§10.2)* `@ml`
- [ ] **M2.60** Signal S2 (approved knowledge base) is the only source for verdicts; anything unapproved → REVIEW. *(§10.2, §3.1 principle 3)* `@lead`
- [ ] **M2.61** Signal S4 (security lexicon): curated YAML of cross-vendor synonyms aligned to OpenConfig names, plus rapidfuzz. Seed it with at least `telnet`/`stelnet`/`admin-telnet`, `logging`/`info-center`/`syslog` and `snmp-server`/`snmp-agent`. *(§10.2)* `@ml`
- [ ] **M2.62** Queue of **patterns**, not lines, ranked by security relevance × devices affected, with a coverage bar per vendor. *(§11.1 step 1)* `@ui` `@ml`
- [ ] **M2.63** Card: raw lines with block context, vendor/OS, top suggestions with explanations, and a slot for the manual excerpt. *(§11.1 step 2)* `@ui`
- [ ] **M2.64** Teach by example:
  - click tokens to make them slots (value, name, list) or literals
  - anti-unification proposes the least general pattern
  - list the other lines it would match
  - click to tighten or loosen

  *(§11.1 step 3)* `@ui` `@lead`
- [ ] **M2.65** Pick meaning: a searchable SBM attribute tree plus one of the six primitives, with transform and unit pickers. The Studio is a visual editor for the mapping language. *(§11.1 step 4, §9.5)* `@ui`
- [ ] **M2.66** Impact preview: lines and devices matched, facts changed, and FAIL→PASS / PASS→FAIL counts. *(§11.1 step 5)* `@lead` `@ui`
- [ ] **M2.67** Approve / Ignore (trains the relevance filter) / Defer. *(§11.1 step 6)* `@ui` `@ml`
- [ ] **M2.68** After approval: KB v(n+1) → hot reload → affected audits re-run → coverage bar moves. Test: the server PID never changes. *(§11.2, R-03 AC)* `@lead`
- [ ] **M2.69** Ergonomics:
  - keyboard-first (approve / next / skip)
  - bulk-approve for high-confidence clusters
  - undo
  - every decision recorded with author, time, signals and KB version

  *(§11.3)* `@ui`

### 2J · Reports and exports (§15, R-07)
- [ ] **M2.70** PDF v1 with every §15.1 section:
  1. **Cover and device profile:** identity with a source per field, config SHA-256, audit ID, date, KB and rule-set versions, frameworks selected.
  2. **Executive summary:** both numbers, severity distribution, top 5 risks.
  3. **Control matrix.**
  4. **Detailed findings,** FAIL first: expected vs actual, evidence lines with line numbers, severity derivation.
  5. **Policy analysis:** a placeholder until M4.22.
  6. **Assurance and transparency:** lines understood, unmapped patterns, REVIEW items, who taught which mappings.
  7. **Appendix:** methodology, framework attributions (CIS attribution is required), glossary, provenance.

  Remediation arrives in M4.16, and the signature and proof in M5. *(§15.1)* `@sec`
- [ ] **M2.71** Customisation by model and version: remediation chosen by OS-version range, sections chosen by role, and version-specific notes (such as defaults that changed in this release). *(§15.2)* `@sec`
- [ ] **M2.72** Bulk audit of N devices → N PDFs, plus a bulk zip download. *(R-07 AC)* `@sec`
- [ ] **M2.73** Exports: JSON (full SBM, findings, evidence), CSV (findings), and a fleet summary PDF. *(§15.4)* `@sec`
- [ ] **M2.74** Summary charts with matplotlib. *(§19.1)* `@sec`

### 2K · Frontend (§18.1, §19.3, R-09)
- [ ] **M2.75** Scaffold:
  - React 19, Vite, TypeScript, Tailwind 4
  - Radix primitives + shadcn/ui patterns, TanStack Query/Table, Zustand, Recharts, Monaco, react-dropzone, lucide
  - eslint, prettier, Vitest
  - npm audit in CI

  *(§19.3, §19.4)* `@ui`
- [ ] **M2.76** Dashboard: fleet Compliance % and Coverage % per framework and per vendor, top failing controls, riskiest devices, coverage per vendor. `@ui`
- [ ] **M2.77** New audit: name → frameworks → scope domains → drop files (single, bulk, zip, companions) → start. `@ui`
- [ ] **M2.78** Audit results: device list with scores, identity completeness, and signed-PDF download (single or bulk zip). `@ui`
- [ ] **M2.79** Device view:
  - findings table with framework and severity filters
  - Monaco config viewer with evidence highlighted
  - entity/SBM explorer
  - a policy-analysis tab (filled in M4.22)
  - fix preview (filled in M4.16)

  `@ui`
- [ ] **M2.80** Provenance drawer: raw line → mapping (who approved it, when, which signals) → fact → rule → framework controls → fix → verification. *(§3.1 principle 1)* `@ui`
- [ ] **M2.81** Training Studio screen, which brings together M2.62–M2.69. `@ui`
- [ ] **M2.82** Knowledge base screen: mappings per vendor, versions and diffs. Rollback comes in M3.27; pack import/export and signature status in M5.08. `@ui`
- [ ] **M2.83** Frameworks & rules screen: enable frameworks; browse rules with their crosswalks and fixtures. `@ui`

- [ ] **M2.G · Gate:** every M2 exit criterion met. If it's blocked, apply the fallback and log it in Appendix C.

---

## M3 · P1 Learns any vendor

**Exit criteria (§25):** S3 manual grounding, S5 benchmarked, S6 two-speed learning, governance (four-eyes, regression gate), LOVO results. **Fallback:** if S3 Recall@5 on Huawei stays below 40%, present S3 as supporting evidence and lead the demo with teach-by-example and instant learning.

### 3A · S3 vendor-manual grounding (§10.4)
- [ ] **M3.01** NAssim corpus (MIT; Huawei NE40E + Nokia 7750 SR), downloaded at setup and not vendored, with a SOURCES entry. *(§20.3)* `@parse`
- [ ] **M3.02** `tools/ingest_manual`:
  - input: a vendor CLI reference in HTML or PDF
  - segment it into command entries with a vendor-agnostic section lexicon ("Format/Syntax", "Function/Description", "Parameters", "Views/Modes", "Default")
  - PDF text extraction needs a library the plan doesn't list yet, so pick one, verify its licence (S.03; not PyMuPDF) and log it in Appendix C

  *(§10.4 steps 1–2)* `@parse`
- [ ] **M3.03** Compile each syntax line (`{a | b}`, `[optional]`, `<param>`) into a linear-time RE2 matcher. *(§10.4 step 3)* `@parse`
- [ ] **M3.04** Extract the description, the `undo`/`no` form, parameter types and ranges, and "*By default, …*" sentences. *(§10.4 step 4)* `@parse`
- [ ] **M3.05** Ground an unknown line by syntax match first, falling back to embedding search over descriptions; then map the description to SBM attribute descriptions (S5). *(§10.4 steps 5–6)* `@ml`
- [ ] **M3.06** By-products: proposed `defaults.yaml` entries and negation forms, reviewed in the Studio. *(§10.4)* `@parse`
- [ ] **M3.07** Admins can upload their own vendor manuals at runtime. *(§20.3, §10.4 step 1)* `@parse` `@ui`
- [ ] **M3.08** The Studio card shows the manual excerpt when S3 matched. *(§11.1 step 2)* `@ui`

### 3B · S5 embeddings and reranker (§10.2, §21.2)
- [ ] **M3.09** Write the SBM attribute descriptions that S5 matches against. `@lead`
- [ ] **M3.10** E2 mapping set: 400–600 labelled (statement → attribute) pairs across the seeds and Huawei, NAssim-assisted. *(§21.1)* `@ml` `@content`
- [ ] **M3.11** Benchmark on E2 under LOVO:
  - embeddings: Qwen3-Embedding-0.6B, granite-embedding-small-english-r2, SecureBERT2.0-biencoder, bge-small-en-v1.5
  - rerankers: Qwen3-Reranker-0.6B, bge-reranker-v2-m3
  - pick by Recall@1 and Recall@5, with speed as the tie-breaker
  - re-check each licence on Hugging Face at download time

  *(§19.2, §21.2)* `@ml`
- [ ] **M3.12** Adopt the winner, with cached embeddings, meeting < 300 ms per pattern. Nearest-neighbour search uses plain numpy: no FAISS and no pgvector, which are unnecessary at our scale. *(§22, §19.5)* `@ml`
- [ ] **M3.13** Store models as safetensors with pinned SHA-256 hashes (the start-up check comes in M5.09). *(§10.5)* `@ml`

### 3C · S6 two-speed learning (§10.5)
- [ ] **M3.14** Instant: every approval goes into a prototype/kNN memory over frozen embeddings, and the pending queue re-ranks immediately. `@ml`
- [ ] **M3.15** Background: once enough new labels accumulate, run a contrastive fine-tune (SetFit / sentence-transformers trainer). The GPU is optional. `@ml`
- [ ] **M3.16** Eval gate: a candidate model is promoted only if it beats the current one on E2, including the LOVO split. `@ml`

### 3D · Fusion, confidence, trust (§10.3)
- [ ] **M3.17** Signal interface: each signal returns `(candidate attribute, score)` or abstains. `@ml`
- [ ] **M3.18** Stacking model (scikit-learn logistic regression over signal scores), retrained from Studio decisions. `@ml`
- [ ] **M3.19** Calibrated thresholds. No confident candidate means "don't know", never a guess. (Conformal prediction comes in M6.05.) `@ml`
- [ ] **M3.20** Every suggestion explains itself: which signals agreed, the manual excerpt, and the 3 nearest approved lines from other vendors. `@ml` `@ui`
- [ ] **M3.21** Trust-policy test: a suggestion never reaches a verdict until it's approved. `@lead`
- [ ] **M3.22** Test every row of the degradation ladder:
  - all core signals
  - no GPU (identical results)
  - no manual
  - a completely novel vendor and shape
  - LLM absent

  *(§10.6, §10.1)* `@ml`

### 3E · Governance: a loop that can't be quietly poisoned (§11.4)
- [ ] **M3.23** `trainer` proposes and `approver` approves, as separate roles (full RBAC in M5.05). `@sec`
- [ ] **M3.24** Four-eyes: if the impact preview shows **any** FAIL → PASS, a second approver (not the trainer) is required. The product enforces two different *accounts*; for the demo we use two seeded accounts (trainer, approver), and the README says real deployments must give them to two different people. `@sec` `@ui`
- [ ] **M3.25** Regression gate before activation: every vendor's golden configs must reproduce their SBM snapshots and verdicts, apart from the intended changes. `@ml`
- [ ] **M3.26** cleanlab label audit: flags approvals that strongly disagree with the other signals and the fleet, for re-review. `@ml`
- [ ] **M3.27** KB versioning: every version kept and diffable, with one-click revert on the KB screen. Transparency-log entries are hooked up in M5.13. `@lead` `@ui`

### 3F · Unseen-vendor proof (§20.4, §21.2)
- [ ] **M3.28** Huawei VRP, never in the seeds, run through the full teach flow. Target: ≥ 80% coverage after ≤ 20 approvals. Rehearse the demo beat: 22% → 85% after 6 approvals. *(§21.3, Executive summary)* `@content` `@ml`
- [ ] **M3.29** MikroTik: a new shape family with no manual, proving the no-manual path of the ladder. *(§20.4, §10.6)* `@content`
- [ ] **M3.30** LOVO runs: zero-shot Recall@5 per vendor with and without the manual (targets ≥ 60% / ≥ 40%), and learning curves after 0 / 5 / 10 / 20 approvals. *(§21.2, §21.3; PS hint "NLP for unseen keywords")* `@ml`
- [ ] **M3.31** Upgrade rule ↔ STIG matching to semantic-engine proposals. *(§12.4)* `@ml` `@content`
- [ ] **M3.32** Hallway test: someone who has never seen Kasauti (a friend or classmate, 5 minutes, no network background needed) maps a Huawei pattern unaided in < 60 s. You can't be the tester, because you already know the UI. *(R-05 AC)* `@ui`
- [ ] **M3.33** Kill-criterion check: is S3 Recall@5 on Huawei ≥ 40%? Record the decision; if not, apply the fallback and log it in Appendix C. *(§25, §28)* `@ml`

- [ ] **M3.G · Gate:** every M3 exit criterion met.

---

## M4 · P2 Proves its fixes

**Exit criteria (§25):** fix intents, recipes for the top 25 rules × seed vendors, inverse mappings, fix preview with hier_config / JSON Patch, rollback, policy analysis. **Fallback:** keep fix preview for the indent and brace families; plain recipes elsewhere.

### 4A · Remediation (§14, R-07c)
- [ ] **M4.01** A fix intent on every rule, turned into changes for **the specific entities in evidence**: this device's own vty ranges, interfaces and policy IDs. *(§14.1)* `@lead`
- [ ] **M4.02** Curated recipes for the top 25 rules × 7 seeds, scoped by OS version and rendered with Jinja2 (sandboxed). *(§14.2 source 1, §12.3)* `@content`
- [ ] **M4.03** Inverse-mapping renderer: approved mapping + desired value + negation form → a command. It must work for Studio-taught vendors such as Huawei. *(§14.2 source 2, §9.5)* `@lead`
- [ ] **M4.04** STIG fix text used as reference wording. *(§14.2 source 3)* `@content`
- [ ] **M4.05** Enforce the source order (curated → inverse → STIG → AI draft), with a Source badge. *(§14.2)* `@lead`
- [ ] **M4.06** `verify.yaml` per vendor per domain: pre-check and verify show-commands. *(§4.4, §14.5)* `@content`
- [ ] **M4.07** Fix preview for text families: running config + fix → hier_config → minimal, correctly ordered commands, a predicted future config and a generated rollback. *(§14.3)* `@lead`
- [ ] **M4.08** Fix preview for XML/JSON (PAN-OS, SONiC, AWS): an RFC 6902 JSON Patch or XML edit applied to a copy. *(§14.3)* `@lead`
- [ ] **M4.09** Re-parse and re-audit the predicted config. A fix is **Verified** only if its target finding flips FAIL → PASS and no other finding regresses. *(§14.3, R-07c AC)* `@lead`
- [ ] **M4.10** Syntax assurance: check against the manual grammar (S3) where a manual was ingested, otherwise hier_config platform rules. Badges: ✓ Re-audit verified · ✓ Syntax checked (manual/platform) · Source. *(§14.4)* `@lead`
- [ ] **M4.11** 5-step output (pre-check → change → verify → save → rollback) for every FAIL on a seed vendor. Non-CLI platforms get their native form: AWS CLI, PAN-OS `set`, SONiC `config` commands or JSON patch. *(§14.5, R-07c)* `@content`
- [ ] **M4.12** Aerleon for rendering ACL/filter fixes where it fits (re-verify its licence). *(§19.1)* `@content`
- [ ] **M4.13** No push path anywhere in the code (fixes are never auto-applied), enforced by a CI grep/test guard. *(§14.5, §3.2)* `@sec`
- [ ] **M4.14** Honesty statement in both the report and the UI: "verified against our model of the device, not on hardware". *(§14.6)* `@sec`
- [ ] **M4.15** Two IOS versions of the same config produce version-specific remediation. *(PS hint "dynamic PDF per version" AC, §15.2)* `@content`
- [ ] **M4.16** Remediation with badges goes into PDF section 4; "Preview fix" goes into the Device view. *(§15.1, §18.1)* `@sec` `@ui`

### 4B · Firewall and cloud policy analysis (§13)
- [ ] **M4.17** `FilterRule` normalisation across seeds (position, src, dst, service, action, log, enabled, zone_from, zone_to, name), run **after** the reference resolver (M2.23). `@lead`
- [ ] **M4.18** Interval arithmetic on address and port sets with Python `ipaddress`. `@lead`
- [ ] **M4.19** Anomalies (Al-Shaer & Hamed): shadowing, redundancy, generalisation, correlation. `@lead`
- [ ] **M4.20** Hygiene checks:
  - any-any allows
  - allow rules without logging
  - clear-text or legacy services (Telnet/FTP/SMBv1) from untrusted zones
  - disabled or stale rules
  - management ports exposed to the internet

  `@content`
- [ ] **M4.21** AWS two-layer analysis: stateless NACLs plus stateful security groups. `@lead`
- [ ] **M4.22** PDF section 5 and the Device view policy tab, showing the rule pairs involved. `@sec` `@ui`

### 4C · Evaluation datasets
- [ ] **M4.23** `tools/mutate`: a mutation generator with catalogued violation operators per vendor → E3. Add E3 to the zero-false-PASS gate (M1.17). *(§20.2, §21.1)* `@ml`
- [ ] **M4.24** E4 fix set built from every E3 violation; measure fix success. *(§21.1)* `@ml`
- [ ] **M4.25** E5 policy set: synthetic rulesets with planted shadowing, redundancy and correlation, plus real examples. *(§21.1)* `@ml`

- [ ] **M4.G · Gate:** every M4 exit criterion met.

---

## M5 · P3 Trustworthy

**Exit criteria (§25):** vault encryption, MFA/RBAC, sandboxed workers, RE2 and sandboxed templates, signed packs, PAdES signing, transparency log + verifier CLI, security test suite. **Fallback:** transparency log with inclusion proofs only (no consistency proofs).

### 5A · Data protection
- [ ] **M5.01** Evidence vault:
  - originals immutable and content-addressed by SHA-256
  - AES-256-GCM with envelope keys (the `cryptography` library), the key coming from the OS keystore or a passphrase
  - only `admin` decrypts originals; everyone else sees the masked view
  - a retention policy

  *(§5.2, §17)* `@sec`
- [ ] **M5.02** Sandboxed parse workers with CPU, memory and time limits per file (Windows job objects or POSIX rlimits). *(§4.2, §5.2, §17)* `@sec`

### 5B · Accounts and access
- [ ] **M5.03** Argon2id password hashing (argon2-cffi); TOTP MFA (pyotp) enforced at first admin login; lockout and rate limits. *(§17)* `@sec`
- [ ] **M5.04** Server-side sessions in HttpOnly / SameSite / Secure cookies, CSRF tokens, idle timeout. No JWT in browser storage. *(§17, §19.5)* `@sec`
- [ ] **M5.05** RBAC with five roles (`viewer`, `auditor`, `trainer`, `approver`, `admin`), least privilege, and every action logged. *(§17)* `@sec`

### 5C · Hardening
- [ ] **M5.06** RE2 for every admin- or pack-supplied pattern, with a lint that forbids `re` on untrusted patterns. *(§17)* `@sec`
- [ ] **M5.07** Jinja2 `SandboxedEnvironment` with whitelisted filters for all recipe templates. *(§17)* `@sec`
- [ ] **M5.08** Signed packs:
  - Ed25519 signing via `tools/sign_pack`
  - verification and schema validation on load
  - unsigned packs quarantined
  - import/export on the KB screen, showing signature status

  *(§4.4, §17, §18.1)* `@sec`
- [ ] **M5.09** Models: safetensors only, with a SHA-256 manifest checked at start-up. *(§17)* `@sec`
- [ ] **M5.10** Network exposure: localhost by default. When exposed: TLS, CSP, HSTS and the other security headers. Ollama bound to 127.0.0.1. *(§17)* `@sec`
- [ ] **M5.11** Air gap: offline installer, bundled models, signed offline updates for packs and catalogs. *(§17, §1.2 test 5)* `@sec`

### 5D · Signatures and the transparency log (§15.3, §16)
- [ ] **M5.12** PAdES signing with pyHanko. By default it uses a key generated at install; it also accepts an organisational certificate or an officer's **Class-3 DSC on a USB token via PKCS#11**. *(§15.3)* `@sec`
- [ ] **M5.13** Merkle transparency log (RFC 9162-style hashing, the design behind Certificate Transparency and Sigstore Rekor). It records:
  - ingested evidence hashes (§5.2)
  - mapping approvals and KB versions (§11.4)
  - report hashes

  *(§16)* `@sec`
- [ ] **M5.14** Ed25519-signed checkpoints (tree roots), using the `cryptography` library. *(§16)* `@sec`
- [ ] **M5.15** Inclusion proofs embedded in the PDF appendix. *(§16, §15.1)* `@sec`
- [ ] **M5.16** Consistency proofs (drop to the fallback if blocked). *(§16)* `@sec`
- [ ] **M5.17** Offline verifier CLI `kasauti verify report.pdf`: checks the signature, inclusion proof and checkpoint without trusting our server. *(§16)* `@sec`
- [ ] **M5.18** Document the optional anchoring adapter (checkpoint export to an external ledger or witness). Documented only, not built. *(§16)* `@sec`
- [ ] **M5.19** Admin & trust screen: users and roles, MFA, transparency-log checkpoint, integrity verification. *(§18.1)* `@ui`

### 5E · Proof that it's secure
- [ ] **M5.20** Security test suite covering:
  - authentication
  - upload abuse: zip bomb, zip-slip, XXE, billion laughs, giant and binary files
  - ReDoS and SSTI
  - the poisoning gate
  - signature tampering (one edited byte → "signature invalid")

  *(§17)* `@sec`
- [ ] **M5.21** OWASP ASVS L2 self-assessment written into `SECURITY.md`. *(§17)* `@sec`
- [ ] **M5.22** A CycloneDX SBOM per release. *(§17)* `@sec`
- [ ] **M5.23** "We practise what we audit" check: Kasauti itself has MFA, lockout, admin-action logging, encrypted management and least privilege. *(§17)* `@sec`
- [ ] **M5.24** Finalise `SECURITY.md`: threat model, reporting, security test suite. *(§17)* `@sec`
- [ ] **M5.25** R-08 acceptance test: import a vendor pack, a framework pack and a version-scoped mapping **at runtime**, with zero code diff. *(§4.4, R-08 AC)* `@lead`

- [ ] **M5.G · Gate:** every M5 exit criterion met. Close DEC.4.

---

## M6 · P4 Measured + polish

**Exit criteria (§25):** full evaluation report, performance budgets met, UX polish, accessibility pass.

- [ ] **M6.01** E1 golden set complete: authored and Batfish configs with hand-verified SBM snapshots and verdicts. *(§21.1)* `@ml` `@content`
- [ ] **M6.02** Metrics report against every §21.3 target, with honest numbers even where we miss:
  - false-PASS rate = 0
  - detection recall and precision ≥ 95%
  - coverage ≥ 95%
  - LOVO Recall@5 ≥ 60% / ≥ 40%
  - Huawei coverage ≥ 80% after ≤ 20 approvals
  - fix success ≥ 95%
  - planted policy anomalies at 100%

  `@ml`
- [ ] **M6.03** Full LOVO report with the learning-curve chart. *(§21.2)* `@ml`
- [ ] **M6.04** Ablations: remove S3, S4, S5, S6 and S8 one at a time and report the change, showing there's no single point of failure and "no LLM needed". *(§21.2)* `@ml`
- [ ] **M6.05** MAPIE conformal prediction sets once E2 is large enough ("90% confident it's one of these two"); an empty set means "don't know". *(§10.3)* `@ml`
- [ ] **M6.06** Performance budgets, with a benchmark script in CI:
  - 5,000-line config in < 2 s
  - signed PDF in < 3 s
  - 100 configs in < 3 min
  - Studio suggestion in < 300 ms
  - memory < 2.5 GB
  - cold start < 20 s

  *(§22, R-09)* `@sec`
- [ ] **M6.07** Fuzz corpus (Hypothesis plus hostile files): 0 crashes, and no hangs beyond the limits. *(§22, R-09 AC)* `@sec`
- [ ] **M6.08** OSCAL assessment-results export. *(§15.4)* `@content`
- [ ] **M6.09** UX polish per §18.2:
  - evidence first, with every number clickable down to a config line
  - two numbers, never one
  - plain-language findings with technical detail one click away
  - honest empty states and error messages
  - light and dark themes

  `@ui`
- [ ] **M6.10** WCAG 2.1 AA accessibility pass. *(§18.2, R-09 AC)* `@ui`
- [ ] **M6.11** Playwright end-to-end tests for the main flows. *(§19.3)* `@ui`
- [ ] **M6.12** Completeness check: ~50 rules have fixtures on every applicable seed, and the top 25 have curated recipes on every seed. *(§12.3)* `@content`

- [ ] **M6.G · Gate:** every M6 exit criterion met.

---

## M7 · Deliverables (§27)

**Exit criteria (§25):** video, slides, 2-page architecture doc, README; clean-machine setup test; three full dry runs; repo made public.

- [ ] **M7.01** Demo video, **≤ 2:00**, following the §27.1 beats:
  - **0:00–0:10 Hook:** seven vendors, seven dialects, one question.
  - **0:10–0:30 Bulk upload:** 7 configs including SONiC and AWS; CIS + NIST + STIG; dashboard with both numbers.
  - **0:30–0:55 P2:** a shadowed Palo Alto rule; telnet on the untrusted zone → Critical; preview fix → FAIL→PASS, 0 regressions, rollback.
  - **0:55–1:30 P1:** Huawei at 22%; the manual quoted; 6 approvals → 85%; Huawei-syntax fixes.
  - **1:30–1:48 P3:** signed PDF valid, one edited byte → invalid; four-eyes block.
  - **1:48–2:00 P4:** false-PASS 0, LOVO curve, "no LLM needed"; offline, open source.

  *(D-4)* `@sec` `@lead`
- [ ] **M7.02** Live-demo safety net: a pre-recorded video, and a seeded demo database that runs fully offline. *(§28)* `@sec`
- [ ] **M7.03** Five slides:
  1. The problem and the gap.
  2. Kasauti: the pipeline, shape families + mapping language + SBM.
  3. P1: signals, manual grounding, Studio, governance, LOVO curve.
  4. P2 + P3: verified fixes, policy analysis, signed reports, transparency log, threat model.
  5. P4 + deployment: metrics, stack and licences (MeitY OSS), air gap, roadmap.

  *(§27.2, D-5)* `@lead`
- [ ] **M7.04** `docs/ARCHITECTURE.md`, **2 pages max**. Page 1: pipeline diagram, component table, the §9.2 worked example. Page 2: SBM entities, semantic engine and governance, crosswalk hub, remediation verification, security and trust. Printed and checked for readability. *(§27.3, D-3)* `@lead`
- [ ] **M7.05** README:
  - 60-second pitch, demo GIF, links to the video, slides and architecture doc
  - quick start in 3 commands (Docker) plus native setup
  - sample data, a "teach a new vendor" walkthrough and an "add a framework" walkthrough
  - evaluation results table, security model summary, licences and attributions

  *(§27.4, D-2)* `@sec`
- [ ] **M7.06** Packaging: Docker Compose, plus a native path, per DEC.5. *(§19.4, §29)* `@sec`
- [ ] **M7.07** Clean-machine setup in ≤ 3 commands, following only the README, on a machine that has never had our dev setup: a GitHub Actions fresh runner (automated, every release) **plus** one manual run in Windows Sandbox or a fresh WSL distro. If a friend is available, have them do it too. *(D-2 AC, adapted for a solo team)* `@sec`
- [ ] **M7.08** Three full dry runs of the demo. *(§25)* `@lead`
- [ ] **M7.09** Check that all 8 differentiators from §26 are visible in the video or slides: manual-grounded learning, the invertible mapping language, learning loop as a security boundary, re-audit-verified fixes, ruleset anomaly analysis, transparency log + DSC PDFs, LOVO + ablations, official-source IDs. Position us against the landscape: Titania Nipper (closed, fixed device library), Tufin / AlgoSec (firewall suites), Batfish (per-vendor grammars), Firewall Orchestrator. None of them lets an admin teach a new vendor. Keep §26's caveat honest: we saw 5 of ~500 teams. *(§26)* `@lead`
- [ ] **M7.10** Final traceability audit: tick every row of the acceptance checklist below. *(§2)* `@lead`
- [ ] **M7.11** Make the repo public at submission and submit the link. *(D-1, §26)* `@sec`
- [ ] **M7.12** Final Appendix C entry in PLAN.md summarising what changed during the build. *(Appendix C)* `@lead`

- [ ] **M7.G · Gate:** submitted.

---

## Parallel track · Content and outreach (runs alongside M0–M4)

- [ ] **C.01** NCIIPC outreach, owned by you. The site (nciipc.gov.in) doesn't open for us: refused and timed out on 2026-09-25 and 2026-09-26, including in your browser. So: (a) send the email Claude drafts to helpdesk1@nciipc.gov.in asking for published guidelines, sanctioned sample configs or a hardening baseline, mentioning SIH 2026 PS 26155 (NTRO); (b) optionally retry the site once on mobile data. **Nothing in the build depends on a reply**: without it, NCIIPC stays a documented, ready slot in the framework-pack system (C.02). *(§20.5, DEC.3)*
- [ ] **C.02** If NCIIPC content is obtained **and** its use is permitted, build an NCIIPC framework pack. *(§12.4, §20.1)* `@content`
- [ ] **C.03** Download the DISA STIGs and the CCI list for the seed vendors from cyber.mil (feeds M2.51, M2.52). *(§20.1)* `@content`
- [ ] **C.04** Download the free CIS benchmark PDFs for each seed vendor and version, and note the terms (feeds M2.54). *(§20.1)* `@content`
- [ ] **C.05** Keep the Appendix A references ready for citation in slides, the architecture doc and the README. *(Appendix A)* `@lead`
- [~] **C.06** Every authored config and curated recipe gets a second check, since there's no second teammate: (1) each line cross-checked against the vendor's official documentation, with the doc reference recorded in SOURCES; (2) a separate Claude review pass that didn't write it; (3) your read-through of the diff. Container NOS labs (X.05) give a real-device check where available. *(§20.2, §28, adapted for a solo team)* `@content` Cisco IOS XE done 2026-09-26: every default quoted from Cisco's docs and the commands the mappings rely on checked, record in `docs/reviews/cisco_ios_xe.md`. Junos config pending.
- [ ] **C.07** Look for more openly licensed vendor CLI samples to strengthen E1/E3. Candidates: the raw show-output fixtures in ntc-templates' test suite (for companion files and identity), plus vendor documentation examples. Verify each licence (S.03), record it in SOURCES, and log any new source in PLAN Appendix C. *(§20.2, PS dataset hint)* `@content`

---

## Stretch tier (in scope: we build these too, but only after the spine and pillars are done; §25)

- [ ] **X.01** S7 fleet consensus: template-with-holes plus outlier scoring against same-role peers (Selfstarter, Diffy). *(§10.2)* `@ml`
- [ ] **X.02** S8 LLM voter via Ollama / llama.cpp with Granite 4.2-3B or Qwen3.5-4B (verify the licence when pulling; **never** `qwen2.5:3b`, which has a research licence; the installed `qwen2.5:1.5b` is Apache-2.0 and fine for dev experiments), localhost only. Guards: free text stripped, delimited input, schema-constrained output; one voter among many, and it never decides. *(§10.1, §10.2, §17, §19.2)* `@ml`
- [ ] **X.03** AI-drafted remediation (only with S8), labelled "AI-drafted: verify before use" and never marked Verified. *(§14.2 source 4)* `@ml`
- [ ] **X.04** Live read-only collection:
  - NAPALM `get_config` / `get_facts`: core drivers for EOS, IOS, IOS-XR, NX-OS and Junos; community drivers for FortiOS and PAN-OS
  - or Netmiko for show commands
  - credentials held in memory only, SSH host keys verified, a read-only account recommended
  - tested against one containerised NOS
  - feeds identity source 1

  *(§5.3, §7, §17, PS hint, DEC.4)* `@parse`
- [ ] **X.05** Containerised NOS labs, if disk allows (SONiC-VS, Nokia SR Linux, Arista cEOS), for authentic configs and show outputs. *(§20.2)* `@sec`
- [ ] **X.06** A "lab-tested" recipe badge earned on a containerised NOS. *(§14.6)* `@content`
- [ ] **X.07** Build the optional anchoring adapter. *(§16)* `@sec`
- [ ] **X.08** CI/CD mode: run the CLI to check configs before deployment. *(§4.2 "future use")* `@lead`
- [ ] **X.09** A gNMI/NETCONF collection path via the OpenConfig alignment (roadmap slide if not built). *(§8.4 "future path")* `@parse`

---

## Acceptance checklist (PLAN §2): the final gate for M7.10

| ID | Acceptance criterion | Proven by |
|---|---|---|
| R-01 | Same posture in 7 vendor syntaxes → identical SBM facts | M2.34 |
| R-02 | Every rule has a pass and fail fixture per seed vendor; CI green | M1.11, M2.36–M2.46 |
| R-03 | An approved mapping changes the next audit with no server restart | M2.68 |
| R-04 | 100 mixed files incl. zip ingested; malformed ones reported, no crash | M2.09 |
| R-05 | A new user maps a Huawei pattern unaided in < 60 s | M3.32 |
| R-06 | Toggling frameworks changes the control matrix; every ID traceable | M2.57, M2.58 |
| R-07 | Bulk audit of N devices → N signed PDFs | M2.72, M5.12 |
| R-07a | Serial/model shown with its source, or "not present", never blank | M2.19, M2.20 |
| R-07b | Severity shown with its derivation (base + exposure) | M2.49 |
| R-07c | Every seed-vendor FAIL has 5-step remediation, re-audit verified | M4.09, M4.11 |
| R-08 | Runtime import of vendor pack, framework pack and version-scoped mapping; zero code diff | M5.25, M2.24 |
| R-09 | Fuzzed inputs never crash; WCAG 2.1 AA; budgets met | M6.06, M6.07, M6.10 |
| Hint | Netmiko/NAPALM read-only collection from a lab device | X.04 |
| Hint | NLP / pattern matching for unseen keywords → LOVO evaluation | M3.30, M6.03 |
| Hint | Two IOS versions → version-specific remediation | M4.15 |
| D-1 | Source code link, public at submission | M0.01, M7.11 |
| D-2 | README; clean-machine setup in ≤ 3 commands | M7.05, M7.07 |
| D-3 | Architecture doc ≤ 2 pages | M7.04 |
| D-4 | Demo video ≤ 2:00 | M7.01 |
| D-5 | Presentation ≤ 5 slides | M7.03 |

---

## Risk watch (PLAN §28)

| Risk | Tasks that mitigate it |
|---|---|
| Scope explosion | Milestone gates M0.G–M7.G; stretch tier X.* only after the pillars |
| A wrong security statement in the demo | M2.46, M2.57, C.06, M4.09, S.06 |
| False PASS | M0.14, M1.07, M1.10, M1.17, M4.23, M6.02 |
| Manual grounding underperforms | M3.33 (kill criterion + fallback) |
| No real devices | M0.23, M2.33, M4.23, M4.14, X.05 |
| Laptop limits | S.12, M3.11 (small models), X.02 stays optional |
| Licence mistakes | S.03, M0.07 |
| Live demo failure | M7.02 |
| Other teams converge on similar ideas | S.08, M6.02, M7.09 |

---

## Coverage map: every section of PLAN.md → tasks

| PLAN section | Tasks |
|---|---|
| Header / change control | S.09 |
| Executive summary (4 pillars, restraint) | M3.28, M4.09, M5.12, M6.02, M7.01, M7.03, S.05 |
| §1.1 Explicit asks | See the acceptance checklist |
| §1.2 Implicit tests | (1) unseen vendor M3.28–M3.30 · (2) correct, provable verdicts M1.10, M1.17, M3.25 · (3) runnable remediation M4.11 · (4) tool is secure M5.01–M5.24 · (5) Indian CI: air gap M5.11, OSS S.03, DSC M5.12, Huawei M3.28 |
| §1.3 Hard parts | Semantics M0.13–M0.19, M2.23 · unseen vendors M3.01–M3.33 · remediation M4.01–M4.16 · trust M3.24, M5.13 |
| §2 Traceability | Acceptance checklist, M7.10 |
| §3.1 Principles | S.04, S.10, S.11, M1.06, M1.10, M2.60, M0.21 |
| §3.2 Non-goals | S.05, S.06, M4.13 |
| §4.1 Pipeline | M0.22, M1.01–M1.14 |
| §4.2 Architectural style | M0.22, M1.14, M2.01–M2.03, M5.02 |
| §4.3 Components | M0.02 |
| §4.4 Packs | M0.21, M2.18, M2.26–M2.32, M4.06, M5.08, M5.25 |
| §5.1 Inputs | M2.04, M2.05, M2.06 |
| §5.2 Handling | M1.01, M2.07, M2.08, M5.01, M5.02, M5.13 |
| §5.3 Live collection | X.04 |
| §6.1 Shape families | M1.02, M2.10–M2.17 |
| §6.2 Statements, pattern keys | M1.02, M1.03 |
| §7 Identity | M1.04, M2.05, M2.18–M2.22, X.04 |
| §8.1 Entities | M0.13 |
| §8.2 Facts, four states | M0.14, M1.06, M1.07 |
| §8.3 Derivations | M0.17, M1.08 |
| §8.4 OpenConfig | M0.15, M0.16, M2.25, X.09 |
| §9.1 Primitives, ref, transforms | M0.18, M1.05, M2.23 |
| §9.2 Worked example | M0.19 |
| §9.3 Stored form | M0.18 |
| §9.4 Version scoping | M0.18, M1.07, M2.24 |
| §9.5 Beyond parsing | M2.65, M4.03 |
| §10.1 Why not just an LLM | M3.22, X.02 |
| §10.2 Signals S1–S8 | M2.59, M2.60, M2.61, M3.01–M3.16, X.01, X.02 |
| §10.3 Fusion, confidence, trust | M3.17–M3.21, M6.05 |
| §10.4 Manual grounding | M3.01–M3.08 |
| §10.5 Two-speed learning | M3.13–M3.16 |
| §10.6 Degradation ladder | M3.22, M3.29 |
| §11.1 Studio flow | M2.62–M2.67, M3.08 |
| §11.2 After approval | M2.68 |
| §11.3 Ergonomics | M2.69 |
| §11.4 Governance | M3.23–M3.27, M5.13 |
| §12.1 Rule language | M0.20, M1.10, M1.11 |
| §12.2 Rule quality gate | M2.46, M2.57, S.06 |
| §12.3 Scope, 10 domains | M2.36–M2.45, M6.12 |
| §12.4 Crosswalk hub | M2.50–M2.58, M3.31, C.02 |
| §12.5 Applicability | M2.47 |
| §12.6 Statuses, scoring | M1.10, M1.12, M2.48 |
| §12.7 Severity | M2.49 |
| §13 Policy analysis | M2.23, M4.17–M4.22, M4.25 |
| §14.1 Finding to fix | M4.01 |
| §14.2 Command sources | M4.02–M4.05, X.03 |
| §14.3 Fix preview | M4.07–M4.09 |
| §14.4 Syntax assurance | M4.10 |
| §14.5 Output format | M4.06, M4.11, M4.13 |
| §14.6 Honesty | M4.14, M0.11, X.06 |
| §15.1 PDF anatomy | M1.13, M2.70, M4.16, M4.22, M5.15 |
| §15.2 Model/version customisation | M2.71, M4.15 |
| §15.3 Signatures, DSC | M5.12 |
| §15.4 Exports | M2.73, M6.08 |
| §16 Trust layer | M5.13–M5.18, X.07 |
| §17 Platform security | M0.06, M0.11, M5.01–M5.24 |
| §18.1 Screens | M2.06, M2.21, M2.75–M2.83, M4.16, M4.22, M5.19 |
| §18.2 Design principles | M6.09, M6.10 |
| §19.1 Backend stack | M0.04, M1.03, M1.13, M2.01–M2.03, M2.14, M2.19, M2.74, M4.07, M4.12, M5.01, M5.03, M5.06, M5.07, M5.12, X.04 |
| §19.2 AI/ML stack | M2.61, M3.11, M3.13, M3.15, M3.18, M3.26, M6.05, X.02 |
| §19.3 Frontend stack | M2.75, M6.11 |
| §19.4 Engineering and CI | M0.01, M0.03, M0.05, M0.06, M7.06 |
| §19.5 Rejected | M0.07, S.03, M5.04 |
| §20.1 Framework content, licences | M2.50–M2.55, C.02–C.04, S.06 |
| §20.2 Configurations | M0.10, M0.23, M2.26–M2.33, M4.23, C.06, X.05, S.07 |
| §20.3 Manuals | M3.01, M3.07 |
| §20.4 Seeds and unseen demo | M2.26–M2.32, M2.35, M3.28, M3.29 |
| §20.5 NCIIPC | C.01, C.02, DEC.3 |
| §21.1 Datasets E1–E5 | M1.16, M2.34, M3.10, M4.23–M4.25, M6.01 |
| §21.2 Protocols (LOVO, ablations, model selection) | M3.11, M3.30, M6.03, M6.04 |
| §21.3 Metrics and targets | M1.17, M6.02 |
| §22 Budgets | M3.12, M6.06, M6.07 |
| §23 Practice and layout | M0.02, M0.05, M0.08, M0.09, S.01, S.02 |
| §24 Team | Owner table, M0.25, DEC.2 |
| §25 Milestones | Gates M0.G–M7.G, M3.33 |
| §26 Competition | S.08, M7.09, M7.11 |
| §27.1 Video | M7.01, M7.02 |
| §27.2 Slides | M7.03 |
| §27.3 Architecture doc | M7.04 |
| §27.4 README | M7.05, M7.07 |
| §28 Risks | Risk watch table |
| §29 Open decisions | DEC.1–DEC.5 |
| Appendix A References | C.05 |
| Appendix B Environment | M0.12, S.12 |
| Appendix C Changelog | S.09, M7.12 |
