# Kasauti: Master Plan

**SIH 2026 · PS 26155 · AI-Driven Multi-Vendor Network Security Compliance Auditor**
National Technical Research Organisation (NTRO) · Software · Blockchain & Cybersecurity

> **Kasauti**: AI-Driven Multi-Vendor Network Security Compliance Auditor
> *Every device, held to every standard.*
>
> A *kasauti* is the touchstone used to test whether gold is pure. "कसौटी पर खरा उतरना" means "to pass the test, to meet the standard", which is exactly the question compliance asks of every device: does it meet CIS, NIST, STIG and ISO? The name was chosen by the team on 2026-09-25. No existing software product by that name was found.

| | |
|---|---|
| Version | **v5 (frozen)**, 2026-09-25. A complete rewrite that consolidates v1–v4 into one coherent design (v4 archived at `docs/archive/PLAN-v4.md`). v5.1 adds references and object resolution (§9.1) |
| Change control | From here on, the plan changes only on **evidence**: a milestone result, a failed assumption, or a new official requirement. Log every change in Appendix C |
| Source of truth | The official PS text. Every section traces back to it (§2) |
| How to read | Executive summary → Part A (the problem) → Part B (the design) → Part C (the build) → Part D (how we win) |

---

## Executive summary

**The problem.** Enterprise and critical-infrastructure networks run devices from dozens of vendors. Each speaks its own configuration dialect, and each must meet CIS, NIST SP 800-53, DISA STIG and ISO/IEC 27001. Today that means manual checklists or expensive, vendor-locked tools that go blind the moment a new vendor, OS version or platform (SONiC, cloud security groups) shows up.

**Our answer, in three sentences.**
1. We read configurations by their **shape**, not their vendor: seven structural families cover practically every network OS, so a new vendor almost never needs new code.
2. We turn every line into **facts with proof** in a vendor-neutral Security Baseline Model, using a small, precise *mapping language*. An AI engine of independent signals proposes the mappings; for an unseen vendor it can **read the vendor's own command manual**; humans approve.
3. We judge those facts against all four frameworks at once, and every finding carries its evidence, a **fix that has been verified by re-auditing it**, and a **digital signature and transparency-log proof** that nobody altered it.

**Four pillars that set us apart:**

| Pillar | One-line promise | What the evaluator sees |
|---|---|---|
| **P1 Learns any vendor** | Unseen vendor → useful audit in minutes, not a code release | A Huawei config at 22% understood; the Studio already quotes Huawei's manual; 6 approvals later the coverage bar reads 85% (target for M3, not yet met: v5.4.0 measured 8 of 23 checks judged after 13 approvals, with no manual grounding yet) |
| **P2 Proves its fixes** | Every remediation is applied to a copy of the config and re-audited before we recommend it; firewall rulesets analysed for shadowed and redundant rules | "Preview fix": FAIL → PASS, zero regressions; "Rule 14 never fires, rule 3 shadows it" |
| **P3 Trustworthy by design** | The auditor itself is hardened, its learning loop can't be quietly poisoned, and its reports are signed and logged | A PDF with a valid signature (optionally an Indian DSC); one edited byte → "signature invalid" |
| **P4 Measured, not claimed** | Published accuracy on public data, including a leave-one-vendor-out test that *proves* unseen-vendor learning | One slide of honest numbers and a learning curve |

**Deliberate restraint.** No cloud AI, no LLM ever deciding a verdict, no auto-pushing changes to devices, no bolt-on blockchain network, no per-vendor hand-written parsers, no copied CIS/ISO text. Each is a conscious choice, explained in §3.

---

# Part A: Understanding the problem

## 1. What the PS really tests

### 1.1 The explicit asks
Normalise to a vendor-neutral schema; compare against the chosen framework; learn unrecognised syntax through an interactive, low-code training GUI without redeploying; single and bulk upload; multi-framework evaluation; one PDF per device with identity (including serial and hardware), Pass/Fail with severity, and step-by-step device-specific CLI remediation; a modular design that absorbs new vendors, standards and OS versions without code changes. The full checklist is in §2.

### 1.2 The implicit tests (what an NTRO evaluator will actually probe)
1. **Does it really handle a vendor it has never seen?** This is the heart of the PS ("traditional parsers fail because they cannot predict … newly acquired or proprietary hardware"). A demo that only shows pre-built vendors misses the point.
2. **Are its verdicts correct, and can it prove them?** A single false PASS in a security audit is worse than no audit. Absence of a line is not evidence of safety.
3. **Can an engineer actually run the remediation?** Generic advice ("disable telnet") isn't a remediation path. The PS asks for device-specific, step-by-step command sequences.
4. **Is the tool itself secure?** It will hold every configuration in the organisation. NTRO will notice if the auditor is the weakest link.
5. **Can it live in Indian critical infrastructure?** Air-gapped sites, open-source preference (MeitY OSS policy), Indian digital-signature practice, vendors common in India (Huawei, Ruijie, Sangfor, Hillstone appear in the PS for a reason).

### 1.3 The genuinely hard parts, ranked
1. **Semantics, not syntax.** One security property is often spread over several lines and blocks (telnet can be enabled per vty range, per interface, or globally), expressed with negations, lists and units, or *not expressed at all* (a vendor default that differs by OS version).
2. **Unseen vendors.** No examples, no parser, maybe a manual.
3. **Correct remediation** without real devices to test on.
4. **Trust:** in the AI (hallucination, manipulation), in the training loop (a bad mapping silently flips verdicts), and in the reports (tampering).

The design in Part B is built around these four, in this order.

---

## 2. Requirements traceability

Every requirement has a design home, a demo moment, and a **testable acceptance criterion**.

| ID | Official requirement | Design | Acceptance criterion (testable) |
|---|---|---|---|
| R-01 | Normalise to a vendor-neutral schema ("Security Baseline Model") | §8 SBM, §9 mapping language | Same security posture expressed in 7 vendor syntaxes yields identical SBM facts (golden tests) |
| R-02 | Deviation analysis vs chosen framework (e.g. ssh_version = 2) | §12 rule engine | Each rule has a passing and a failing fixture per seed vendor; all green in CI |
| R-03 | Unrecognised structure → interactive training GUI with raw lines, low-code mapping, heuristics update, **no redeploy** | §10 semantic engine, §11 Training Studio | An approved mapping changes the next audit's result with the server process never restarted |
| R-04 | Unified ingestion: single **and bulk**, any device | §5 ingestion | 100 mixed files (incl. zip) ingested; malformed files reported, never crash |
| R-05 | Dedicated, intuitive AI training GUI | §11 | A new user maps a Huawei pattern unaided in < 60 s (hallway test) |
| R-06 | Multi-framework, user-selected (CIS, NIST, STIG, ISO) | §12.4 crosswalk hub | Toggling frameworks changes the report's control matrix; every control ID traceable to an official source |
| R-07 | **One PDF per device** | §15 | Bulk audit of N devices → N signed PDFs |
| R-07a | Identity incl. **serial numbers, hardware** | §7 identity resolver | Serial/model shown with its source; "not present in supplied artefacts" when absent, never blank |
| R-07b | Pass/Fail + **risk severity** | §12.6–12.7 | Severity shown with its derivation (base + exposure) |
| R-07c | **Device-specific, step-by-step CLI** remediation | §14 | Every FAIL on a seed vendor has pre-check → change → verify → save → rollback, re-audit verified |
| R-08 | New vendors / standards / OS versions **without code changes** | §4.4 packs, §9.4 version scoping | Import a vendor pack, a framework pack and a version-scoped mapping at runtime; zero code diff |
| R-09 | User-friendly, robust | §18 UX, §22 budgets, §17 hardening | Fuzzed inputs never crash; WCAG 2.1 AA target; performance budgets met |
| Hint | Netmiko/NAPALM data collection | §5.3 optional live collection | Read-only collection from one lab device (stretch-tier) |
| Hint | NLP / pattern matching for unseen keywords | §10 signals S1, S3, S4, S5 | LOVO evaluation (§21) |
| Hint | Dynamic PDF per model and software version | §15.2 | Two IOS versions of the same config produce version-specific remediation |
| D-1 | Source code link | GitHub, Apache-2.0 (private until submission) | Public at submission |
| D-2 | README with setup | §27.4 | Clean-machine setup in ≤ 3 commands, verified by a teammate who didn't build it |
| D-3 | Architecture doc **≤ 2 pages** | §27.3 | Two pages, printed, readable |
| D-4 | Demo video **≤ 2 min** | §27.1 | ≤ 2:00, every pillar visible |
| D-5 | Presentation **≤ 5 slides** | §27.2 | Five slides |

---

## 3. Principles and deliberate non-goals

### 3.1 Principles
1. **Proof-carrying verdicts.** Every PASS/FAIL links to exact file, line, raw text, the mapping that interpreted it, and who approved that mapping.
2. **Absence is not safety.** Missing information resolves through version-aware vendor defaults, or becomes REVIEW. It is never a silent PASS.
3. **AI proposes, humans dispose, and the rules decide.** Only approved mappings feed verdicts. Verdicts come from a deterministic rule engine.
4. **Content is data.** Vendors, mappings, defaults, rules, frameworks and remediation recipes are signed, versioned packs loaded at runtime.
5. **Deterministic core, reproducible audits.** Same input + same knowledge-base version + same rule-set version produce byte-identical results.
6. **Offline and open.** Runs air-gapped on a laptop; every dependency is permissively licensed (MeitY OSS policy aligned).
7. **The auditor passes its own audit.** Hardened like the crown-jewel store it is.

### 3.2 What we deliberately don't do, and why
| We don't… | Because… |
|---|---|
| Write a parser per vendor | That's exactly the "hard-coded library" the PS says goes obsolete. We parse shapes (§6) |
| Send configs to cloud AI | Configs are a full map of critical infrastructure |
| Let an LLM decide anything | Hallucination and prompt injection are unsolved. An LLM is at most one optional voter (§10) |
| Auto-push fixes to devices | An auditor that changes production is a new attack path. We generate, verify and sign; humans apply |
| Run a blockchain network | The PS doesn't ask for one; it would add attack surface and break air-gapped use. We use the right primitive, a transparency log (§16) |
| Show a compliance % without a coverage % | 100% compliant on 10% of controls understood is a lie. We always show both (§12.6) |
| Invent control IDs or copy CIS/ISO text | IDs only from official sources; licences respected (§20.1) |
| Build microservices / Kubernetes | Single operator, air-gapped, minimal attack surface → modular monolith (§4) |

---

# Part B: The design

## 4. Architecture at a glance

### 4.1 Pipeline

```
            ┌──────────── INPUTS ─────────────┐
            │ upload (file/zip/folder)  ·  companion show-outputs  ·  optional read-only live collection │
            └──────────────────┬──────────────┘
                               ▼
 ① INGEST & EVIDENCE VAULT   validate · sandboxed parse worker · SHA-256 · AES-GCM at rest · secret masking
                               ▼
 ② SHAPE PARSING             7 structural families → Universal Config Tree (statements with path, tokens, lines)
                               ▼
 ③ IDENTITY                  vendor/OS fingerprint · hostname · model · serial · hardware (source per field)
                               ▼
 ④ MAPPING                   approved mappings (the mapping language, §9) → facts with evidence
        │ unmapped, security-relevant patterns
        ▼
 ⑤ SEMANTIC ENGINE           S1 structure · S3 vendor manual · S4 lexicon · S5 embeddings · S6 few-shot memory (+ stretch S7, S8)
        │ ranked, explained suggestions
        ▼
 ⑥ TRAINING STUDIO  ─ approve (four-eyes if verdict-flipping) → regression gate → knowledge base vN+1 → hot reload
                               ▼
 ⑦ SECURITY BASELINE MODEL   entities + facts (explicit / vendor_default / absent / unknown) + derived device facts
                               ▼
 ⑧ COMPLIANCE ENGINE         rules × entities → PASS / FAIL / REVIEW / N/A · crosswalk hub → CIS · NIST · STIG · ISO
        │                    firewall & cloud policy analysis (shadowing, redundancy, exposure)
                               ▼
 ⑨ RISK & REMEDIATION        severity = base × exposure · fix intent → vendor commands → FIX PREVIEW (re-audit) → rollback
                               ▼
 ⑩ OUTPUTS                   signed per-device PDF · JSON / CSV / OSCAL · dashboard · transparency-log proof
```

### 4.2 Architectural style
- **Modular monolith.** One FastAPI application plus a pool of worker processes. Parsing and evaluation run in workers with CPU, memory and time limits, so a hostile file can't take down the server.
- **Deterministic core, ports and adapters.** The pipeline core (text → tree → facts → findings → fixes) is pure functions with no I/O. The same core powers the web API and a CLI (`kasauti audit router.cfg --framework nist`), which also opens a future CI/CD use (checking configs before deployment).
- **Storage.** SQLite in WAL mode by default (zero setup, single file, easy to back up air-gapped); PostgreSQL for multi-user servers. The evidence vault is an encrypted, content-addressed store on disk. Packs and models are signed files on disk.

### 4.3 Components
| Module | Responsibility |
|---|---|
| `ingest` | Upload API, archive handling, validation, hashing, vault encryption, secret masking |
| `shape` | Family detection, 7 family parsers + flat fallback → Universal Config Tree |
| `identity` | Vendor/OS fingerprinting, identity resolver |
| `mapping` | Mapping-language compiler and matcher, fact emission, derivations |
| `semantic` | Signals S1–S8, fusion, manual ingestion, few-shot memory, background training, eval gate |
| `studio` | Training queue, template induction, impact preview, governance workflow |
| `sbm` | Schema, entity store, defaults resolver, derivation engine |
| `rules` | Rule language, applicability, crosswalk hub, scoring, severity |
| `policy` | Firewall/cloud ruleset analysis |
| `remediation` | Fix intents, recipe rendering, inverse mappings, hier_config/JSON-Patch application, fix preview, rollback |
| `report` | PDF (ReportLab), exports (JSON/CSV/OSCAL), PAdES signing (pyHanko) |
| `trust` | Merkle transparency log, checkpoints, proofs, verifier CLI |
| `packs` | Pack loading, schema validation, Ed25519 signature verification, hot reload |
| `auth` | Sessions, Argon2id, TOTP MFA, RBAC |
| `jobs` | Job queue in the database, worker pool (one process per job), lease-based recovery |
| `api` / `cli` / `web` | FastAPI routes, command-line interface, React front end |

### 4.4 Packs: how "no code changes" actually works (R-08)
```
packs/
  vendors/<vendor_os>/
    pack.yaml            # shape family, negation words, comment markers, unit conventions
    detect.yaml          # fingerprint signatures
    identity.yaml        # where hostname / version / model / serial appear (config + show outputs)
    defaults.yaml        # vendor defaults, scoped by OS version range (manual-extracted or curated)
    mappings/*.yaml      # statements → facts (seeded + learned in the Studio)
    recipes/*.yaml       # fix intents → command sequences, scoped by OS version range
    verify.yaml          # pre-check / verify show-commands per domain
    manual/              # optional: ingested command-manual corpus (S3)
  frameworks/<framework>/
    catalog.json         # official control IDs + titles (licence-safe)
    crosswalk.yaml       # our rule IDs → this framework's control IDs, with source
  rules/*.yaml           # vendor-neutral rules with fixtures
```
Each pack is **data only** (schema-validated YAML/JSON; no code, no pickle) and **Ed25519-signed**. A new vendor is almost always a new pack in an existing shape family. A new standard is a framework pack. A new OS version is version-scoped entries. The only change that needs code is a genuinely new *shape* family, and the flat-line fallback covers even that in the meantime.

---

## 5. Ingestion and the evidence vault

### 5.1 Inputs
- Config files (`.txt .cfg .conf .log .xml .json .yaml`), `.zip` archives, folders; single or bulk.
- **Companion files** per device (`show version`, `show inventory`, `get system status`, `show system info`, `show chassis hardware`, `display version`, `display esn`): the reliable source of serials and hardware (§7).
- Pairing: files are grouped into devices by hostname and filename stem, with a manual correction UI.
  Since v5.1.22 each file is recognised in a worker as it arrives (configuration or command
  output, vendor, hostname); every configuration is a device, and an output joins the one whose
  host it names, or whose file or folder name it shares. A tie or no match is never guessed:
  the output is left out with the reason until someone pairs it by hand. The audit checks the
  pairing again, so another host's serial can't reach a report. A recognising job that a
  hostile file kills is split until that file fails alone (v5.1.23), so the rest are still
  grouped.

### 5.2 Handling
- Limits on size, archive entries and nesting depth; path normalisation (zip-slip); `defusedxml` (XXE, billion laughs); encoding detection; binary sniffing.
  Reviewed against a hostile corpus (M2.07): archives inside archives and LZMA-compressed
  entries are refused, parsers cap nesting at 100 levels, and every parser and search runs in
  linear time.
- **Sandboxed parsing:** each file is parsed in a worker process with CPU/memory/time limits.
- **Until the vault exists (M2.04 → M5.01):** an uploaded original waits in an owner-only
  staging directory under a random id only until its audit job's worker reads it, and is
  deleted on that read, before parsing. The database never holds it; results hold masked text.
  Since v5.1.19 it is also sealed as it arrives (AES-256-GCM in 64 KiB segments, the STREAM
  construction, each file bound to its ids) under a key made at server start and kept in
  memory only; workers get the key over the pipe that starts them, never through the database,
  and decrypt in memory. What a deleted staged file leaves on the disk is ciphertext. A restart
  makes files staged before it unreadable, and their jobs say so.
- **Evidence vault:** originals stored immutable, content-addressed by SHA-256, encrypted with AES-256-GCM under envelope keys. Only the `admin` role can decrypt originals. Everyone else sees the masked view.
- **Masking that keeps auditability:** the secret value is hidden but its *kind* is kept (`password 7 ****`, `secret 9 ****`, `snmp community ****(RO)`), so rules like "no reversible password types" still work.
- Every ingested artefact's hash is appended to the transparency log (§16).

### 5.3 Optional live collection (PS hint: Netmiko/NAPALM)
Read-only collection via NAPALM (core drivers: EOS, IOS, IOS-XR, NX-OS, Junos; community drivers: FortiOS, PAN-OS) for `get_config` and `get_facts` (which includes serial and model), or Netmiko for show commands. Credentials are held in memory only, SSH host keys are verified, and a read-only device account is recommended. Stretch-tier: we have no physical devices, so it's tested against one containerised lab NOS.

---

## 6. Structural parsing: the Universal Config Tree

### 6.1 Seven shape families
| Family | Examples | Tree rule |
|---|---|---|
| **Indent** | Cisco IOS/IOS-XE/NX-OS, Arista EOS, Aruba-CX, Dell OS10, Huawei VRP, Ruijie, Allied Telesis, H3C | Child = deeper indent; `!` / `#` separators |
| **Brace** | Juniper Junos, VyOS, PAN-OS CLI | `{ }` nesting, `;` terminators |
| **Set-path** | `set …` forms of Junos/VyOS/PAN-OS, Check Point Gaia, Extreme EXOS | Path = leading tokens |
| **Block-edit** | Fortinet FortiOS (and similar) | `config … / edit … / set … / next / end` |
| **Path-command** | MikroTik RouterOS | `/ip service` + `set … key=value` |
| **XML** | PAN-OS XML, pfSense/OPNsense, Sophos exports | Element path |
| **JSON/YAML** | SONiC `config_db.json`, AWS/Azure/GCP exports, Meraki API, Cumulus NVUE | Key path |
| *Flat fallback* | Anything else | One statement per line |

**Family detection** scores each family's structural signals (indent regularity, brace balance, `config/edit/next/end` markers, XML/JSON validity, leading `set`/`/`), and it's usually unambiguous. Vendor fingerprinting (§7) runs on top.

**A file its vendor's parser rejects** (cut off, damaged, nested past 100 levels) is read by
the flat fallback, so its lines still reach the Training Studio, but it gets no verdict: every
PASS, FAIL, or "nothing to check" becomes REVIEW, with its evidence kept, and the report says
why (v5.1.21). With the structure lost, a setting may be in the file unseen, and a line that
was seen may be undone by one that wasn't; absence must never read as a verdict (§3.1,
principle 2). A rule skipped for the device's role stays skipped: the role isn't read from
the file.

### 6.2 Statements and pattern keys
Every leaf becomes a **Statement** `{path: [parent blocks…], tokens, text, line_start, line_end, family}`. For example: `path = ["line vty 0 4"], text = "transport input ssh telnet"`.

A **pattern key** abstracts variables by type (`<INT> <IP> <IFNAME> <STR>`) while keywords stay literal, so `interface GigabitEthernet1/0/7` becomes `interface <IFNAME>`. 48 interface blocks collapse into one pattern, so the admin teaches a pattern once, not 48 times. (v5.1.3: this replaces Drain3 template mining, whose similarity merge joined different commands.)

---

## 7. Device identity (R-07a)

Serial numbers are usually **not** in configuration files, so identity is resolved from several sources in priority order, and the report shows which source each field came from:
1. **Live facts:** NAPALM `get_facts` (vendor, model, serial, OS version, hostname).
2. **Companion show outputs,** recognised and read by each vendor pack's `identity.yaml`: signatures scored like the vendor fingerprint, fields read by the mapping language or RE2, hardware components by RE2 records (v5.1.18; not TextFSM, ntc-templates or TTP, which run Python's backtracking `re` over device output). An output that names another host, or comes from another vendor, is refused with the reason, never mixed in.
3. **Config headers and markers:** FortiGate `#config-version=<model>-<version>…`, Junos `version …;`, PAN-OS XML `version` attributes, Cisco `version` / `hostname`, SONiC `DEVICE_METADATA`.
4. **Manual entry** in the UI (v5.1.27): fills only a field no file gives, marked "entered by hand"; where a file disagrees the file wins, with a warning. Typed values are shown in the device profile but are never SBM facts and never change a verdict: a typed OS version doesn't choose version-scoped defaults.

Missing fields are stated explicitly ("Serial: not present in supplied artefacts; upload `show inventory` to populate"). Identity also drives **role inference** (router / switch / firewall / cloud filter / white-box), which decides rule applicability and report sections.

---

## 8. The Security Baseline Model (R-01)

### 8.1 Entities, not a flat dictionary
Security properties live at different scopes (per device, per vty range, per interface, per user, per rule). A flat key-value schema can't say "telnet is enabled on vty 5–15 only". The SBM is a small **entity model**:

| Entity | Key attributes |
|---|---|
| `Device` | hostname, vendor, os_family, os_version, model, serial, hardware, role |
| `MgmtService` | kind (ssh/telnet/http/https/snmp/netconf/…), enabled, version, ciphers, macs, kex |
| `MgmtSession` | kind (console/vty/web/api), range, transport, access_filter, idle_timeout_s, auth_method |
| `Interface` | name, zone, role (untrusted / trusted / mgmt, inferred + overridable), admin_up, mgmt_protocols, filters_in/out |
| `LocalUser` | name, privilege, hash_type |
| `AuthServer` | kind (tacacs/radius/ldap), host, key_present |
| `LogTarget` | host, transport, severity; plus flags: timestamps, admin_logged, config_change_logged |
| `TimeSource` | host, authenticated |
| `SnmpCommunity` / `SnmpUser` | access, filter / auth, priv |
| `CryptoProfile` | purpose (ike/ipsec/ssh/tls), algorithms, dh_group, lifetimes |
| `FilterRule` | position, src, dst, service, action, log, enabled, zone_from, zone_to, name |
| `Banner`, `PasswordPolicy`, `LockoutPolicy`, `RoutingAuth`, `L2Port`, `Tunnel` | domain-specific attributes |

### 8.2 Facts with four states and evidence
Every attribute is a **Fact**: `{value, state: explicit | vendor_default | absent | unknown, evidence: [{file, lines, raw, mapping_id@version, approved_by}]}`.
- `explicit`: stated in the config.
- `vendor_default`: not stated, resolved from `defaults.yaml` **for this OS version** (defaults genuinely change between releases).
- `absent`: not stated and no default known.
- `unknown`: statements exist but weren't understood (unmapped).

Rules decide how to treat `absent` and `unknown` (normally REVIEW, §12.1).

### 8.3 Derivations: vendor mapping stays local, security meaning stays global
Device-level security facts are **derived** from entities by small, versioned formulas, for example:

```
management.telnet_reachable :=
    any(MgmtService[kind=telnet].enabled)
 or any(MgmtSession[kind=vty].transport ∋ telnet)
 or any(Interface.mgmt_protocols ∋ telnet)
```
A vendor mapping only has to say what *its* line means locally ("this vty range allows telnet"). The security meaning ("is telnet reachable at all?") is defined once, for every vendor. Derived facts carry the union of their inputs' evidence.

### 8.4 Aligned with OpenConfig
Where an equivalent exists, SBM names map to **OpenConfig** paths (the industry's vendor-neutral YANG models, Apache-2.0), e.g. `/system/ssh-server/config/protocol-version`, `/system/telnet-server/config/enable`, `/system/aaa`, `/system/logging`, `/system/ntp`. Compliance-specific extras (hash types, lockout, rule hygiene) live in an `x-sbm` extension. We extend the industry's schema instead of inventing one, and it opens a future path to gNMI/NETCONF collection. The SBM is versioned (`sbm_version`) with migrations.

---

## 9. The mapping language: how a vendor line becomes a fact

This is the core of the system. It's small enough to be edited by clicks in the Training Studio, expressive enough for very different syntaxes, and invertible so it can also produce remediation.

### 9.1 Six primitives
| Primitive | Meaning | Studio action that creates it |
|---|---|---|
| `entity` | This block/statement opens or names an entity (e.g. `line vty 0 4` → MgmtSession vty 0–4) | "This block is a **[entity type]** named **[token]**" |
| `set` | A slot's value becomes an attribute (with typed slots and transforms) | Click a token → "this is **[attribute]**" |
| `assert` | Presence of the statement means attribute = constant | "This line means **[attribute] = [value]**" |
| `members` | Each item in a list slot is added to a set attribute | "Each word here is a **[protocol/server/…]**" |
| `negation` | The vendor's negation form inverts the fact (`no`, `undo`, `unset`, `delete`, `disable`, `disabled=yes`) | "The opposite is written with **[undo]**" (usually auto-detected, or read from the manual) |
| `default` | What holds when nothing is stated, per OS version range | "If absent, the default is **[value]**" (often pre-filled from the manual) |

**References (the seventh building block).** Configs constantly point at other named things: `access-class MGMT-ACL in` on a vty line, `set srcaddr "LAN_GRP"` in a FortiOS policy, `<source><member>web-servers</member>` in PAN-OS, security-group IDs referenced by other AWS groups, `user-interface … acl 2001` on Huawei. A `ref` primitive records "this attribute points to entity X by name". After parsing, a **resolver** links references to their targets:
- It expands address/service **objects and groups** (recursively, with cycle detection) into concrete IP and port sets.
- It flags **dangling references** (a policy pointing at an object that doesn't exist) as findings of their own.

Without this, firewall analysis (§13) would be comparing object *names* instead of the addresses behind them, and "is management restricted by an ACL?" couldn't be answered. With it, derivations can follow the chain vty → ACL → permitted sources.

**Transforms** handle the messy reality: value maps (`enable/disable → true/false`), boolean inversion (`disable-telnet yes` → telnet false), **unit normalisation** (Cisco `exec-timeout 10 0` → 600 s; FortiOS `admintimeout 5` minutes → 300 s), list splitting, and case folding.

### 9.2 Worked example: one property, eight platforms, six primitives
| Platform | What the config says | Primitives | Resulting facts |
|---|---|---|---|
| Cisco IOS-XE | `line vty 0 4` → ` transport input ssh telnet` | `entity` + `members` | MgmtSession[vty 0–4].transport = {ssh, telnet} → derived: telnet reachable |
| Juniper Junos | `system { services { telnet; } }` | `assert` (presence) | MgmtService[telnet].enabled = true |
| Fortinet FortiOS | `config system interface` → `edit "wan1"` → `set allowaccess ping https telnet` | `entity` + `members` | Interface[wan1].mgmt_protocols ∋ telnet (and wan1 is untrusted → severity rises, §12.7) |
| Palo Alto PAN-OS | `<deviceconfig><system><service><disable-telnet>no</disable-telnet>` | `set` + inversion | MgmtService[telnet].enabled = true |
| Huawei VRP | `telnet server enable` / `undo telnet server enable` | `assert` + `negation(undo)` | MgmtService[telnet].enabled = true / false |
| MikroTik RouterOS | `/ip service` → `set telnet disabled=yes` | `entity` + `set` + inversion | MgmtService[telnet].enabled = false |
| SONiC | nothing about telnet in `config_db.json` | `default` | MgmtService[telnet].enabled = false (vendor_default) |
| Cisco, line absent | nothing stated | `default` scoped by OS version | resolved per release, else REVIEW |

Six primitives cover eight very different syntaxes. That's the evidence that a small language, not a per-vendor parser, is the right abstraction. (AWS security groups express a *different* property, exposure of port 23 to the internet, as `FilterRule` entities, handled by §13.)

### 9.3 Stored form (what a learned mapping looks like)
```yaml
id: fortinet_fortios/interface-allowaccess
vendor: fortinet_fortios
os_versions: ">=6.0"
context: ["config system interface", "edit <STR:ifname>"]
entity: {type: Interface, key: ifname}
match: "set allowaccess <LIST:protocols>"
effect: {members: Interface.mgmt_protocols, from: protocols,
         map: {ping: icmp, https: https, http: http, ssh: ssh, telnet: telnet, snmp: snmp}}
negation: "unset allowaccess"
provenance: {version: 3, proposed_by: trainer:asha, approved_by: [approver:ravi], signals: [S3, S5]}
```

### 9.4 Version scoping
Mappings, defaults and recipes all carry `os_versions` ranges. When a vendor changes syntax or defaults in a new release, we add a scoped entry and the old one keeps serving older devices. This is the PS's "firmware updates make hard-coded libraries obsolete" problem, solved as data.

### 9.5 Why this matters beyond parsing
- The **Training Studio** is a visual editor for exactly this language, so "low-code" has precise semantics rather than being a free-form tagging screen.
- The language is **invertible**. Given a mapping and a desired value, we can *render* the command (`set allowaccess ping https` without telnet, or `undo telnet server enable`). Teaching the system to read a vendor also teaches it to fix that vendor (§14).

---

## 10. The semantic engine: suggesting mappings without a single point of failure

### 10.1 Why not "just use an LLM"
A single LLM has four structural limits here:
1. It **hallucinates** and isn't reproducible.
2. It can be **manipulated** by text inside the config (descriptions and banners are attacker-writable; 2026 research shows this works against LLM-based security analysis).
3. It needs **hardware** we can't assume (a 4 GB laptop GPU; air-gapped sites).
4. It **doesn't know rare vendors**: Huawei, Sangfor, Hillstone and Ruijie syntax is thin in training data.

So suggestions come from **independent signals that fail differently**, fused and gated by human approval.

### 10.2 The signals
| # | Signal | What it contributes | Technology | Research basis | Tier |
|---|---|---|---|---|---|
| S1 | **Structure** | Block context, negation form, pattern key, value types | Shape parsers + typed pattern keys | Drain; Selfstarter/Diffy templates | Core |
| S2 | **Approved knowledge base** | Exact, human-approved mappings (the only signal that feeds verdicts) | Mapping language (§9) | — | Core |
| S3 | **Vendor-manual grounding** | For unseen vendors: which documented command this line is, what it does, its `undo` form and its default | Manual ingester (§10.4); seed corpus from **NAssim** (MIT: 12,406 Huawei NE40E + Nokia 7750 SR command entries) | **NAssim, ACM SIGCOMM '22**: device models from manuals, 9.1× faster onboarding | Core ★ |
| S4 | **Security lexicon** | Cross-vendor synonyms (`telnet`/`stelnet`/`admin-telnet`, `logging`/`info-center`/`syslog`, `snmp-server`/`snmp-agent`), aligned to OpenConfig names | Curated YAML + rapidfuzz | OpenConfig | Core |
| S5 | **Semantic embeddings + reranker** | Closeness of line (or its manual description) to SBM attribute descriptions and to approved examples from *other* vendors | sentence-transformers; model **chosen by benchmark** (§21) from Qwen3-Embedding-0.6B, granite-embedding-small-english-r2, SecureBERT2.0, bge-small; reranker Qwen3-Reranker-0.6B / bge-reranker-v2-m3 | NAssim's NetBERT; domain-adapted compliance mapping (arXiv 2607.06364) | Core |
| S6 | **Few-shot memory** | Learns from every approval, at two speeds (§10.5) | Prototype/kNN memory + background contrastive fine-tune (SetFit / sentence-transformers) | NAssim fine-tuned on 110–381 expert pairs | Core ★ |
| S7 | Fleet consensus | Values that differ from same-role peers; value-type inference | Template-with-holes + outlier scoring | Selfstarter (NSDI '20), Diffy (PLDI '24) | Stretch |
| S8 | LLM voter | Broad general knowledge; drafting explanations | Local Granite 4.2-3B or Qwen3.5-4B via Ollama (localhost only), or an org-hosted open model | "Verified Prompt Programming" (HotNets '23): LLMs need verifiers | Stretch |

★ Not seen in any SIH 26155 repository we reviewed (§26).

### 10.3 Fusion, confidence and trust
- Each signal returns `(candidate attribute, score)` or abstains. A **stacking model** (logistic regression over signal scores, retrained from Studio decisions) ranks the candidates.
- Confidence starts as calibrated thresholds. Once the evaluation set is large enough, **conformal prediction** (MAPIE, BSD-3) produces candidate *sets* with a stated coverage ("90% confident it's one of these two"). An empty set means "don't know", and we never guess.
- **Every suggestion explains itself:** which signals agreed, the manual excerpt, and the three nearest approved lines from other vendors.
- **Trust policy:** suggestions only pre-fill the Studio. Nothing reaches a verdict until approved (§11.4).

### 10.4 Manual grounding (S3), step by step
1. **Input:** a vendor CLI reference (HTML/PDF) uploaded by the admin, or a pre-parsed corpus (NAssim).
2. **Segment** into command entries using a vendor-agnostic section lexicon ("Format/Syntax", "Function/Description", "Parameters", "Views/Modes", "Default").
3. **Compile** each syntax line (`{a | b}` alternatives, `[optional]`, `<param>`) into a matcher (RE2, linear-time).
4. **Extract** the description, the `undo`/`no` form, parameter types and ranges, and "*By default, …*" sentences.
5. **Ground** an unknown config line by syntax match against the compiled commands (high precision). If nothing matches, fall back to embedding search over descriptions.
6. **Map** the command description to SBM attribute descriptions (S5).

By-products:
- auto-filled `defaults.yaml` entries (default states come from the vendor's own manual)
- negation forms
- **syntax checking of generated remediation commands** against the manual grammar (§14.4)

### 10.5 Learning at two speeds
- **Instant (seconds):** every approval is added to a prototype/kNN memory over frozen embeddings, and patterns still pending in the queue are re-ranked immediately. This is what the live demo shows.
- **Background (minutes, optional GPU):** once enough new labels accumulate, a contrastive fine-tune (SetFit / sentence-transformers trainer) produces a candidate model. It's **promoted only if it beats the current model** on the evaluation gate (§21), including the leave-one-vendor-out split. Model files are safetensors with pinned hashes.

### 10.6 Degradation ladder
| What's available | Behaviour |
|---|---|
| All core signals | Best suggestions |
| No GPU | Identical results; background training slower |
| No manual for this vendor | S1 + S4 + S5 + S6 still suggest; the admin teaches a few lines; S6 learns |
| Completely novel vendor, novel shape | Flat-line fallback + lexicon + embeddings → Studio; coverage climbs with each approval |
| LLM absent (the default) | No loss of core function; S8 is additive only |

---

## 11. The Training Studio (R-03, R-05)

### 11.1 Flow
1. **Queue of patterns, not lines**, ranked by security relevance × number of devices affected. It shows the per-vendor coverage bar.
2. **Card:** the raw line(s) with block context, vendor/OS, the top suggestions with their explanation, and the manual excerpt if S3 matched.
3. **Teach by example:** the admin clicks tokens to make them slots (value, name, list) or literals. The system proposes the generalisation by **anti-unification** (the least general pattern covering the examples) and lists the other lines it would match. The admin can tighten or loosen it by clicking.
4. **Pick meaning:** a searchable SBM attribute tree plus one of the six primitives, with transform and unit pickers.
5. **Impact preview:** "matches 37 lines on 4 devices; Interface.mgmt_protocols changes on 4 devices; **2 findings flip FAIL → PASS**, 1 PASS → FAIL."
6. Approve / Ignore (not security-relevant; this trains the relevance filter) / Defer.

### 11.2 After approval
Knowledge base v(n+1) → regression gate (§11.4) → hot reload → affected audits re-run → coverage bar moves. The server process is never restarted.

### 11.3 Ergonomics
Keyboard-first (approve/next/skip), bulk-approve for high-confidence clusters, and undo. Every decision is recorded with author, time, signals and knowledge-base version.

### 11.4 Governance: a learning loop that can't be quietly poisoned
Training data is a security boundary. A wrong mapping (`telnet enable` taught as "disabled") would silently turn every device green.
- **Roles:** `trainer` proposes, `approver` approves. They're separate RBAC roles.
- **Four-eyes on verdict flips:** if the impact preview shows *any* finding moving FAIL → PASS, a second approver (≠ trainer) is required.
- **Regression gate:** before activation, every vendor's golden configs must reproduce their expected SBM snapshots and verdicts, apart from the intended changes.
- **Label audit:** cleanlab flags approvals that disagree strongly with the other signals and the fleet, for re-review.
- **Versioning and rollback:** every knowledge-base version is kept, diffable, one-click revertible, and logged in the transparency log.

---

## 12. Compliance engine (R-02, R-06, R-07b)

### 12.1 Rule language
Rules are vendor-neutral, quantified over SBM entities, and ship with their own tests:
```yaml
id: MGMT-TELNET-01
title: Clear-text Telnet management is not reachable
intent: Credentials must never cross the network in clear text.
for_each: Device
assert: not management.telnet_reachable
on_absent: resolve_default          # vendor+version default, else REVIEW
on_unknown: review
severity: {base: high}
exposure: [telnet_on_untrusted_interface]        # raises to critical (§12.7)
fix_intent: {make: management.telnet_reachable, equal: false}
refs:
  nist_800_53r5: [CM-7, AC-17(2), SC-8]
  disa_stig: auto        # matched from imported vendor STIGs, human-confirmed (§12.4)
  cis: {cisco_ios_xe_17: "<rec id>", fortios_7: "<rec id>"}
  iso_27001_2022: derived    # via NIST OLIR #155 (§12.4)
fixtures:
  pass: [cisco_ios_xe/telnet_off.cfg, junos/no_telnet.conf]
  fail: [cisco_ios_xe/telnet_vty.cfg, fortios/wan_telnet.conf]
```
```yaml
id: MGMT-SESSION-TIMEOUT-01
for_each: MgmtSession where kind in [console, vty, web]
assert: idle_timeout_s > 0 and idle_timeout_s <= 600
```
Per-entity rules give per-entity findings ("vty 5–15: `exec-timeout 0 0` means sessions never time out", with exact lines). The operators are declarative (`== != < <= in ∋ any all none count matches exists`), and there's no `eval`.

### 12.2 Rule quality gate
Every rule ships with: its intent, official references, `on_absent`/`on_unknown` semantics, at least one passing and one failing fixture per seed vendor it applies to, and a fix intent. CI fails if any is missing. **No rule may cite a control ID that isn't in an imported official catalog.** Pure hardening checks without a benchmark are labelled "hardening best practice", never given invented numbers.

### 12.3 Scope: about 50 rules in 10 domains
Management plane, AAA, logging, time, SNMP, services, crypto, filtering, L2, routing authentication. Depth beats breadth: the top 25 rules get curated remediation recipes on every seed vendor. The rest rely on inverse mappings (§14).

### 12.4 Crosswalk hub: every framework ID traceable to an official source
NIST SP 800-53 r5 is the **hub**. Every rule is anchored to NIST controls. Every other framework hangs off the hub through an *official* bridge wherever one exists:

| Framework | Source of IDs (licence) | Bridge to our rules |
|---|---|---|
| **NIST SP 800-53 r5** | Official OSCAL catalog (public domain / CC0) | Authored per rule, peer-reviewed |
| **DISA STIG** | Imported XCCDF for the vendor's STIG (US Gov, public domain) | Matched by reading each requirement's check and fix text; a human confirms. **Consistency check:** the STIG rule's CCIs → NIST (DISA CCI list) must share a base control with our NIST anchors, or the mapping says why. (CCIs that still cite only 800-53 **Rev 4** follow NIST's own "moved to / incorporated into" links in the Rev 5 OSCAL catalog; every translation is reported) |
| **ISO/IEC 27001:2022** | Annex A control numbers only (copyrighted standard) | **Derived from NIST via NIST OLIR #155**, the official SP 800-53 r5 → ISO/IEC 27001:2022 informative reference, then reviewed |
| **CIS Benchmarks** | Recommendation IDs from the free benchmark PDFs, per vendor/version (CC BY-NC-SA: IDs + our own wording, with attribution) | Authored per rule and vendor |
| **NCIIPC** (if obtained) | NCIIPC guidelines | A framework pack like any other |

A CI "crosswalk lint" rejects unknown IDs, missing anchors and inconsistent STIG↔NIST pairs.
Each mapping also says how much of the control the rule decides (`full`, `part`, `stricter`), so a
check that covers part of a STIG requirement can fail it but never mark it met (v5.3.0).

### 12.5 Applicability
Rules declare the roles and features they apply to, so a switch isn't failed on VPN rules and a cloud security group isn't failed on console timeouts. Non-applicable rules are N/A and listed, not hidden.

### 12.6 Statuses and scoring: always two numbers
- Status per rule and entity: **PASS / FAIL / REVIEW** (absent or unknown evidence, or an unapproved mapping) **/ N/A**.
- **Compliance %** = PASS / (PASS + FAIL) over applicable rules, per framework.
- **Coverage %** = (PASS + FAIL) / applicable rules: how much we could actually judge.
- Both are shown everywhere, so nobody mistakes "100% compliant" on 10% coverage for safety.
- NIST control status rolls up from its rules: all pass → satisfied; some fail → partially satisfied.

### 12.7 Severity: base × exposure, explained
- **Base** comes from the STIG category where mapped (CAT I → High, CAT II → Medium, CAT III → Low), otherwise from our reviewed rating.
- **Exposure modifiers**, each bounded and explainable, give the final Critical / High / Medium / Low:
  - raised when the weakness is reachable from an **untrusted interface/zone** (inferred from zone names like untrust/outside/wan, public addressing, default-route egress; the admin can override). Public means globally reachable by IANA's IPv4 special-purpose registry (IPv4 only: inside networks use global IPv6 addresses too); default-route egress doesn't count on a switch (v5.1.28)
  - raised for perimeter-firewall roles
  - lowered when a compensating control exists (management restricted to a management subnet)
- Every finding shows "High (base) → **Critical**: telnet allowed on `wan1` (untrusted)".

---

## 13. Firewall and cloud policy analysis (P2)

The PS names "granular ACLs" among its hardening protocols. Checking only for "any-any" is shallow, so we analyse the **whole ordered ruleset** of every firewall and cloud filter, using the classic taxonomy of **Al-Shaer & Hamed (Firewall Policy Advisor, IEEE INFOCOM 2004)**:

| Anomaly | Meaning | Why it matters |
|---|---|---|
| **Shadowing** | An earlier rule matches everything a later rule matches, with a different action | The later rule never fires. The admin believes something is blocked/allowed that isn't |
| **Redundancy** | A rule is fully covered by another with the same action | Dead rules hide intent and slow review |
| **Generalisation** | A broader later rule covers an earlier exception | Often intended; flagged for review |
| **Correlation** | Partial overlap with different actions | Order-dependent behaviour, a classic source of mistakes |

Plus hygiene checks:
- any-any allows
- allow rules without logging
- clear-text or legacy services (Telnet/FTP/SMBv1) from untrusted zones
- disabled or stale rules
- management ports exposed to the internet

For **AWS**, the analysis spans both layers: stateless NACLs and stateful security groups. This two-layer case was formalised in a 2026 *Future Internet* paper. Implementation uses interval arithmetic on address and port ranges (Python `ipaddress`, no extra dependency), **after** the reference resolver (§9.1) has expanded every address/service object and group into concrete sets. That step is what makes shadowing detection correct on real firewalls, where rules almost never contain raw IPs. It runs on SBM `FilterRule` entities, so every firewall vendor we can parse gets it for free.

---

## 14. Remediation engine (R-07c, P2)

### 14.1 From finding to fix
Each rule declares a **fix intent** (e.g. make `telnet_reachable` false). The engine turns it into concrete changes for *the specific entities in evidence*. That means this device's actual vty ranges, interfaces and policy IDs, not a generic snippet.

### 14.2 Command sources (in priority order)
1. **Curated recipes** in the vendor pack, scoped by OS version and templated with entity context (Jinja2 sandboxed).
2. **Inverse mappings:** render the approved mapping with the desired value, using the vendor's negation form. This covers every vendor taught in the Studio.
3. **STIG fix text** for the imported vendor STIGs (reference and wording).
4. **AI draft** (only if S8 is enabled), labelled "AI-drafted: verify before use", and never shown as verified.

### 14.3 Fix preview: every recommended fix is proven by re-auditing it
- **Indent / brace / set-path families:** build the intended config (running + fix lines), then **hier_config** (MIT) computes the minimal, correctly ordered command sequence, predicts the **future config** and generates the **rollback**.
- **XML / JSON families (PAN-OS, SONiC, AWS):** express the fix as an exact patch (RFC 6902 JSON Patch / XML edit) and apply it to a copy.
- Then **re-parse and re-audit the predicted config.** A fix is marked **Verified** only if its target finding flips FAIL → PASS and **no other finding regresses**.

This is the "verifier in the loop" idea from HotNets '23 and the 2026 configuration-repair benchmarks, done fully offline.

### 14.4 Syntax assurance
Generated commands are checked against the vendor's manual grammar where a manual has been ingested (S3), and against hier_config's platform rules otherwise. The badges shown are:
- ✓ Re-audit verified
- ✓ Syntax checked (manual / platform)
- Source: curated / inverse mapping / STIG / AI draft

### 14.5 Output format (every FAIL on a seed vendor)
```
! Pre-check        show running-config | section line vty
! Change           configure terminal
                    line vty 0 4
                     transport input ssh
                    end
! Verify           show running-config | section line vty   → expect "transport input ssh"
! Save             copy running-config startup-config
! Rollback         configure terminal / line vty 0 4 / transport input ssh telnet / end
Badges: ✓ Re-audit verified (FAIL→PASS, 0 regressions)  ✓ Syntax: cisco_ios platform rules  · Source: curated recipe
```
Non-CLI platforms get their native form: AWS CLI (`aws ec2 revoke-security-group-ingress …`), PAN-OS `set` commands, SONiC `config` commands or JSON patches.

**Never auto-applied.** We generate, verify and sign. People apply.

### 14.6 Honesty about verification without devices
"Verified" means *verified against our own model of the device* (re-parse + re-audit), plus syntax checks. It does **not** mean tested on hardware. The report says so. Where a containerised NOS is available (e.g. Arista cEOS, Nokia SR Linux, SONiC-VS), recipes can additionally earn a "lab-tested" badge (stretch).

---

## 15. Reporting (R-07)

### 15.1 Per-device PDF anatomy (ReportLab)
1. **Cover and device profile:** hostname, vendor, model, **serial**, hardware, OS version, role, the source of each identity field, config SHA-256, audit ID, date, knowledge-base and rule-set versions, frameworks selected.
2. **Executive summary:** per framework, Compliance % *and* Coverage %; severity distribution; top 5 risks in plain language.
3. **Control matrix:** rule → framework control IDs → status → severity, per selected framework.
4. **Detailed findings** (FAIL first, by severity): what and why; expected vs actual; **evidence lines with line numbers**; severity derivation; **step-by-step remediation with badges**.
5. **Firewall policy analysis** (firewalls and cloud filters only): anomalies with the rule pairs involved.
6. **Assurance and transparency:** lines understood, unmapped patterns, REVIEW items, which mappings were human-taught (and by whom).
7. **Appendix:** methodology, framework attributions (CIS attribution required), glossary, provenance (versions, transparency-log inclusion proof, signature details).

### 15.2 Customised by model and software version (PS hint)
Remediation is selected by OS-version range, sections by role, and version-specific notes are included (e.g. defaults that changed in this release).

### 15.3 Signatures, including Indian DSC
Every PDF carries a **PAdES digital signature** (pyHanko, MIT). It uses a key generated at install by default. It can also be an **organisational certificate, or an officer's Class-3 DSC on a USB token via PKCS#11**, the digital-signature practice recognised under India's IT Act. Any PDF reader shows whether the report has been altered since signing.

### 15.4 Exports
Machine-readable JSON (full SBM, findings, evidence), CSV (findings), a fleet summary PDF, and **OSCAL assessment-results** (NIST's machine-readable format) so results can flow into GRC tools. OSCAL comes after the spine is done.

---

## 16. Trust layer: the blockchain decision

**Is blockchain required?** No. The PS text never mentions it. "Blockchain & Cybersecurity" is the theme bucket, and the PS itself is about cybersecurity. A blockchain network would add servers, consensus, keys and attack surface, and it would break air-gapped deployment.

**What we take from blockchain is tamper-evident history, via the primitive that secures the web's certificates.** Certificate Transparency (RFC 9162) and Sigstore's Rekor use this design:
- Every evidence hash, mapping approval, knowledge-base version and report hash is appended to a **Merkle-tree transparency log** (RFC 9162-style hashing).
- The log issues **signed checkpoints**: Ed25519-signed tree roots.
- **Inclusion proofs:** anyone holding a report can check it was logged at audit time. The proof is embedded in the PDF appendix.
- **Consistency proofs:** anyone can check the log only ever grew and was never rewritten.
- An offline **verifier CLI** (`kasauti verify report.pdf`) checks the signature, the inclusion proof and the checkpoint without trusting our server. An external auditor (or NCIIPC) can run it.
- **Optional anchoring:** checkpoints can be exported to an external ledger or witness if an organisation wants one. That's a documented adapter, not built by default.

**Why this beats a SHA-256 hash chain** (what other teams did): a chain proves order but gives no compact proof for one record, and a quietly truncated tail isn't detectable without an outside reference. Merkle proofs plus signed checkpoints fix both.

---

## 17. Platform security: the auditor passes its own audit (P3)

The platform holds topology, ACLs, password hashes, SNMP communities and VPN peers for an entire organisation. It's hardened accordingly. We self-assess against **OWASP ASVS Level 2** as a checklist.

| Asset / threat | Attack | Control |
|---|---|---|
| Stored configs | Disk theft, backup leak, curious insider | AES-256-GCM vault (envelope keys; key from OS keystore or passphrase); masked views; only admins decrypt originals; retention policy |
| Accounts | Guessing, stolen sessions | Argon2id; **TOTP MFA** (enforced at first admin login); lockout + rate limits; server-side sessions in HttpOnly/SameSite/Secure cookies; CSRF tokens; idle timeout |
| Authorisation | Viewer approves mappings; auditor edits rules | RBAC (`viewer`, `auditor`, `trainer`, `approver`, `admin`), least privilege, all actions logged |
| **Learning loop** | Poisoned or careless mapping flips verdicts | Four-eyes on verdict flips, regression gate, cleanlab label audit, rollback (§11.4) |
| Uploads | Zip bomb, zip-slip, XXE, billion laughs, giant or binary files | Limits, path normalisation, defusedxml, sniffing, **sandboxed worker processes** with resource limits |
| Patterns | ReDoS from admin- or pack-supplied regex | **RE2** (linear time) everywhere |
| Templates | Server-side template injection | Jinja2 **SandboxedEnvironment**, whitelisted filters |
| Packs | Poisoned or code-carrying pack imports | Data-only packs, schema validation, **Ed25519 signatures**, quarantine for unsigned packs |
| Models | Swapped or malicious weights | **safetensors** only, SHA-256-pinned manifest checked at start-up |
| LLM (if enabled) | Prompt injection via config text | Free text stripped, delimited input, schema-constrained output, the LLM never decides |
| Reports and history | Forgery, deletion | PAdES signatures; transparency log (§16) |
| Live collection | Credential theft, MITM | Read-only accounts, host-key verification, in-memory credentials |
| Supply chain | Compromised dependency | Hash-locked lockfile (uv), CycloneDX SBOM, pip-audit / npm audit, bandit, gitleaks, trivy in CI |
| Exposure | Tool reachable on the LAN | Localhost binding by default; TLS, CSP, HSTS and other security headers when exposed; Ollama bound to 127.0.0.1 |
| Air gap | No internet at site | Offline installer, bundled models, **signed offline updates** for packs and catalogs |

**Secure development:** `SECURITY.md` (threat model, reporting), security test suite (authentication, upload abuse, ReDoS, SSTI, poisoning gate, signature tampering), SBOM per release.

**We practise what we audit:** MFA, lockout, admin-action logging, encrypted management and least privilege are exactly the controls we check on devices.

---

## 18. User experience (R-09)

### 18.1 Screens
| Screen | Purpose |
|---|---|
| **Dashboard** | Fleet Compliance % and Coverage % per framework and vendor; top failing controls; riskiest devices; coverage per vendor |
| **New audit** | Name → frameworks → scope domains → drop files (single/bulk/zip + companions) → start |
| **Audit results** | Device list with scores, identity completeness, signed-PDF download (single or bulk zip) |
| **Device view** | Findings table (filter by framework/severity); Monaco config viewer with evidence highlighted; entity/SBM explorer; policy-analysis tab; **fix preview** |
| **Provenance drawer** | Click any finding: raw line → mapping (who approved, when, which signals) → fact → rule → framework controls → fix → verification |
| **Training Studio** | Pattern queue, suggestions with explanations, token-click teaching, impact preview, approvals, coverage bars |
| **Knowledge base** | Mappings per vendor, versions and diffs, rollback, pack import/export with signature status |
| **Frameworks and rules** | Enable frameworks, browse rules with crosswalks and fixtures |
| **Admin and trust** | Users and roles, MFA, transparency-log checkpoint, integrity verification |

### 18.2 Design principles
Evidence first (every number clickable down to a config line); two numbers, never one; plain-language findings with technical detail one click away; keyboard-first Studio; honest empty states and error messages; WCAG 2.1 AA target; light and dark themes.

---

# Part C: Building it

## 19. Technology stack (final; every licence verified 2026-09-25 against PyPI / npm / Hugging Face / GitHub)

### 19.1 Backend (Python 3.12)
| Purpose | Choice | Licence |
|---|---|---|
| API / server | FastAPI, Uvicorn, python-multipart | MIT, BSD-3, Apache-2.0 |
| Schema | Pydantic v2 | MIT |
| Persistence | SQLAlchemy 2 + Alembic; SQLite (default) / PostgreSQL | MIT; public domain; PostgreSQL licence |
| PG driver | psycopg 3 | LGPL-3.0 (unmodified library use) |
| Workers | multiprocessing pool + DB job table (no broker) | PSF |
| Pattern keys | in-house, keyword-literal (Drain3 dropped in v5.1.3) | Apache-2.0 (ours) |
| Remediation | hier_config; Aerleon (ACL rendering) | MIT; Apache-2.0 |
| Show-output parsing | the mapping language and RE2, in each pack's `identity.yaml` (TextFSM, ntc-templates and TTP dropped in v5.1.18) | Apache-2.0 (ours) |
| Live collection (stretch) | NAPALM, Netmiko (Paramiko underneath) | Apache-2.0, MIT (Paramiko LGPL-2.1, unmodified) |
| XML / YAML | defusedxml (SAX, DTDs forbidden), PyYAML (safe loader, aliases refused) | PSF, MIT |
| Safe regex | google-re2 | BSD-3 |
| Templates | Jinja2 (sandboxed) | BSD-3 |
| PDF + signing | ReportLab, matplotlib, **pyHanko** | BSD, PSF-style, MIT |
| Crypto | cryptography (AES-GCM, Ed25519); in use since v5.1.19 (staging) | Apache-2.0 OR BSD-3 (+ cffi MIT-0, pycparser BSD-3) |
| Auth | argon2-cffi, pyotp | MIT, MIT |
| Logging | structlog | MIT / Apache-2.0 |

### 19.2 AI / ML
| Purpose | Choice | Licence |
|---|---|---|
| Embedding runtime | sentence-transformers 6 | Apache-2.0 |
| Embedding models (benchmark shortlist) | Qwen3-Embedding-0.6B; granite-embedding-small-english-r2 (47M); SecureBERT2.0-biencoder; bge-small-en-v1.5 | Apache-2.0 ×3, MIT |
| Rerankers (benchmark) | Qwen3-Reranker-0.6B; bge-reranker-v2-m3 | Apache-2.0 |
| Classical ML, stacking | scikit-learn, numpy | BSD-3 |
| Few-shot fine-tune | SetFit 1.2 / sentence-transformers trainer | Apache-2.0 |
| Calibration | MAPIE (conformal) | BSD-3 |
| Label audit | cleanlab | Apache-2.0 |
| Fuzzy matching | rapidfuzz | MIT |
| Model files | safetensors | Apache-2.0 |
| LLM (stretch) | Ollama / llama.cpp; Granite 4.2-3B or Qwen3.5-4B | MIT runtimes; Apache-2.0 models |

### 19.3 Frontend (TypeScript)
React 19, Vite, TypeScript, Tailwind 4, Radix primitives with shadcn/ui patterns, TanStack Query and Table, Zustand, Recharts, Monaco editor, react-dropzone, lucide icons (all MIT except TypeScript Apache-2.0 and lucide ISC). Tests: Vitest, Playwright.

### 19.4 Engineering and CI
uv (hash-locked), ruff, mypy, pytest, Hypothesis (property tests), eslint, prettier, pre-commit; CycloneDX SBOM, pip-audit, npm audit, bandit, gitleaks, trivy; Docker Compose for packaging. **Our licence:** Apache-2.0 (includes a patent grant, which suits government adoption).

### 19.5 Considered and rejected
| Candidate | Why not |
|---|---|
| ciscoconfparse2 | GPL-3.0; also a per-vendor-parser approach |
| PyMuPDF | AGPL-3.0 |
| Redis 8 | RSALv2 / SSPLv1 / AGPLv3; not needed |
| Llama 3.x, Gemma (incl. EmbeddingGemma) | Custom, non-OSI licences |
| Qwen2.5-3B (currently installed locally) | Research licence; use `qwen2.5:1.5b` (Apache-2.0) or the choices above |
| Cloud LLM APIs | Data sovereignty |
| Batfish (as the core parser) | Hand-written per-vendor grammars plus a heavy Java service; we reuse its Apache-licensed example configs as data only |
| WeasyPrint | Heavy GTK dependencies on Windows |
| pgvector / FAISS | Unnecessary at our scale (plain numpy) |
| JWT in browser storage | Can be stolen through XSS |
| Microservices | Attack surface and operational weight without benefit |

---

## 20. Content and data

### 20.1 Framework content and licences
| Source | Status | What we ship |
|---|---|---|
| NIST SP 800-53 r5 (OSCAL) | Public domain / CC0 | Full catalog |
| NIST OLIR #155 (800-53 r5 → ISO 27001:2022) | Public NIST informative reference | Mapping rows |
| DISA STIGs (XCCDF) + CCI list | US Government works, public domain | Titles, severity, check/fix text, CCIs |
| CIS Benchmarks | CC BY-NC-SA 4.0 | IDs + our own wording + attribution; no copied text |
| ISO/IEC 27001:2022 | Copyrighted | Control numbers + our own short descriptions |
| NCIIPC guidelines | To be obtained | A framework pack if permitted |

### 20.2 Configurations
1. **Authored corpus:** hardened and weak variants for each seed vendor, written from vendor documentation and peer-reviewed. These are the golden fixtures.
2. **Batfish repository** (Apache-2.0): example networks and grammar test configs (Cisco, Juniper, Arista, Palo Alto, …).
3. **Mutation generator:** injects catalogued violations into hardened configs to produce labelled test sets (§21).
4. **Containerised NOS labs** (stretch; disk-permitting): SONiC-VS, Nokia SR Linux, Arista cEOS, for authentic configs, show outputs and lab-tested recipes.
5. `datasets/SOURCES.md` records source, licence and hash for every file.

### 20.3 Manuals
NAssim corpus (MIT; Huawei NE40E + Nokia 7750 SR), downloaded at setup rather than vendored, since the content derives from vendor manuals. Admins can ingest their own vendor manuals at runtime.

### 20.4 Seed vendors and the unseen-vendor demo
- **Seeds (7):** Cisco IOS-XE, Arista EOS, Juniper Junos/SRX, Fortinet FortiOS, Palo Alto PAN-OS (XML), AWS security groups + NACLs (JSON), SONiC (`config_db.json`). That's routers, switches, firewalls, cloud and white-box, over 5 of the 7 shape families. SONiC and cloud security groups are the PS's own examples of where traditional parsers fail.
- **Unseen demo vendor:** **Huawei VRP**. Its manual is available through NAssim, so the demo exercises S3. It's also highly relevant to Indian networks, and it's never in the seed packs.
- **Second unseen:** MikroTik (a new shape family, no manual), showing the no-manual path of the degradation ladder.

### 20.5 NCIIPC outreach
nciipc.gov.in refused connections from our research environment (2026-09-25) and also didn't open from the developer's own browser and laptop (2026-09-26). The developer therefore writes to helpdesk1@nciipc.gov.in asking for published guidelines, sanctioned samples or a hardening baseline. Nothing in the build depends on a reply; if material arrives and its use is permitted, it becomes a framework pack. An NCIIPC-aligned framework pack would be highly relevant to NTRO.

---

## 21. Evaluation methodology (P4: measured, not claimed)

### 21.1 Datasets
| ID | Contents | Purpose |
|---|---|---|
| E1 Golden set | Authored + Batfish configs with hand-verified SBM snapshots and verdicts | Correctness, regression gate |
| E2 Mapping set | 400–600 labelled (statement → attribute) pairs across seeds + Huawei (NAssim-assisted) | Suggestion quality; model selection |
| E3 Mutation set | Hardened configs × catalogued violation operators (per vendor) | Detection precision/recall; *mutation testing for compliance* |
| E4 Fix set | Every E3 violation | Fix success rate (re-audit verified) |
| E5 Policy set | Synthetic rulesets with planted shadowing/redundancy/correlation + real examples | Policy-analysis precision/recall |

### 21.2 Protocols
- **Leave-one-vendor-out (LOVO).** For each vendor V, remove all of V's mappings. Then measure the zero-shot suggestion quality for V (with and without V's manual), and the **learning curve** after 0 / 5 / 10 / 20 approvals. This is the scientific version of "handles unseen vendors", and the core of our P4 slide.
- **Ablations.** Remove each signal in turn (S3, S4, S5, S6, S8) and report the change. This shows there's no single point of failure and quantifies what each signal is worth (including "no LLM").
- **Model selection.** The embedding models and rerankers in §19.2 compete on E2 under LOVO. The winner is chosen by Recall@1 and Recall@5, with speed as a tie-breaker.

### 21.3 Metrics and initial targets (to be confirmed by measurement, and reported honestly)
| Metric | Target |
|---|---|
| **False-PASS rate** on E1/E3 (the metric that matters most in security) | **0** |
| Detection recall / precision on E3, seed vendors | ≥ 95% / ≥ 95% |
| Coverage of security-relevant lines, seed vendors | ≥ 95% |
| LOVO zero-shot Recall@5 (with manual / without) | ≥ 60% / ≥ 40% (for reference: NAssim reported ~73% Recall@30 in 2022) |
| Huawei coverage after ≤ 20 approvals | ≥ 80% |
| Fix success (FAIL→PASS, no regressions) on E4, seed vendors | ≥ 95% |
| Policy anomalies on E5 | 100% on planted cases (it's an exact algorithm) |

---

## 22. Performance and robustness budgets (laptop: i5-12500H, 16 GB, no LLM)
| Budget | Target |
|---|---|
| Parse + map + evaluate a 5,000-line config | < 2 s |
| Per-device signed PDF | < 3 s |
| Bulk: 100 mixed configs end-to-end | < 3 min |
| Studio suggestion latency per pattern | < 300 ms (cached embeddings) |
| Memory, full stack | < 2.5 GB |
| Cold start (models loaded) | < 20 s |
| Hostile inputs (fuzz corpus) | 0 crashes, 0 hangs beyond limits |

**Large files (measured 2026-09-27, v5.1.17).** An audit costs about 14 s and 200 MiB of memory per MiB of a
dense configuration (the densest input found, a bare `interface` line after line: 44 s and
470 MiB). The limits are set from these numbers, so none of them fails a file the upload has
accepted without saying why: the job's time limit grows with the file (2 min + 1 min per MiB),
the result is stored gzip-compressed (at most about 2.2 times the file, against a 64 MiB limit
for a 20 MiB file), and each worker has a memory ceiling (2 GiB by default, about 10 MiB of
dense configuration; `kasauti serve --worker-memory`). A file that needs more fails its own
job with that message.

**Measured 2026-09-27, v5.1.21 (M2.09).** Bulk: 100 mixed files (all five vendors from 1 to
150 KiB, a zip with folders, and files that must be refused or fail) take 40 s end to end
on the default 2 workers and 74 s on 1 (a machine with fewer than 4 CPUs), against the
3-minute budget; `tests/ingest/test_bulk.py` checks it on every run. A job's fixed cost fell
from about 2 s to 0.65 s: a worker no longer imports the database layer it never uses, and
pack YAML is read by libyaml, not pure Python (0.44 → 0.09 s). The audit itself is 0.03 s for
a small file and at most 1.3 s at 5,000 lines. Memory per MiB of configuration, peak
committed: 115 MiB for a realistic dense Cisco file (was 142), 40 for the same line repeated
(was 125); the parsed tree is a sixth of what it was. The worst case is a file where every
line is its own entity (`interface Gi0/1`, `interface Gi0/2`, …): about 440 MiB per MiB,
since each entity carries its facts, evidence and findings into the result. A 2 GiB worker
still audits about 4 MiB of that, and 15 MiB of realistic configuration. Going further would
change the stored result's data model (a compact SBM), which is its own task.

**Measured 2026-09-27, v5.1.22 (M2.06).** Recognising the 100 files before the upload starts
is one worker job of 2 s, since files join the job still waiting; the whole bulk test, now
with a `show version` audited with its device, takes 43 s on 2 workers.

---

## 23. Engineering practice and repository layout
```
kasauti/
  backend/kasauti/{ingest,shape,identity,mapping,semantic,studio,sbm,rules,policy,remediation,report,trust,packs,auth,api,cli}
  frontend/
  packs/{vendors,frameworks,rules}
  datasets/{authored,batfish,mutations,SOURCES.md}
  eval/{harness,reports}
  tools/{import_oscal,import_stig,import_cci,import_olir,ingest_manual,mutate,sign_pack}
  docs/{PLAN.md,ARCHITECTURE.md,SECURITY.md,archive/}
  README.md  LICENSE  docker-compose.yml
```
- **Definition of done:** tests (unit + fixtures), types, docs, security checks green, reviewed by one teammate.
- **Branching:** short-lived feature branches → PR → review → `main`. `main` is always demo-able from Milestone 1 on.
- **CI:** lint, types, tests, rule quality gate, crosswalk lint, golden regression, SBOM and security scans.

---

## 24. Team and ownership

**Actual team (2026-09-26): one developer + Claude.** The six roles below remain as *work areas* for organising tasks. Review steps that assumed a second human (code review, config peer review, clean-machine setup) are adapted in `docs/TODO.md` (S.01, C.06, M7.07). The hallway test (R-05) still uses someone outside the project.
| # | Role | Owns | Pillar |
|---|---|---|---|
| 1 | Lead / architect | SBM, mapping language, rule language, integration, final demo | All |
| 2 | Parsing & identity | Ingestion, shape families, identity, manual ingester (S3) | P1 |
| 3 | AI/ML | Signals S4–S6, fusion, evaluation harness, LOVO, ablations | P1, P4 |
| 4 | Compliance & network content | Rules, fixtures, crosswalks, STIG/OSCAL/CCI/OLIR import, recipes | P2 |
| 5 | Frontend & UX | All screens, Training Studio, provenance drawer | P1 |
| 6 | Security, reporting & DevOps | Platform hardening, signing, transparency log, PDF, CI, packaging, video | P3 |

---

## 25. Milestones (gated by exit criteria, not dates; there's no fixed deadline)
| Milestone | Exit criteria | Fallback if blocked |
|---|---|---|
| **M0 Foundations** | Private repo + CI + security scanners; SBM v0, mapping and rule languages v0; pack format frozen; 3 authored configs; eval harness skeleton; `SECURITY.md` draft | — |
| **M1 Walking skeleton** | One Cisco config → tree → mappings → SBM → 10 rules → unsigned PDF, end to end | Simplify the entity model before adding breadth |
| **M2 Spine** | 7 seed vendors, ~50 rules with fixtures, 4 frameworks via the crosswalk hub, identity resolver, PDF v1, Studio v1 (teach, approve, hot reload), dashboard | Cut to 5 seed vendors (keep SONiC and AWS: they're the PS's own examples) |
| **M3 P1 Learns any vendor** | S3 manual grounding, S5 benchmarked, S6 two-speed learning, governance (four-eyes, regression gate), LOVO results | If S3 Recall@5 on Huawei stays < 40%: present S3 as supporting evidence and lead the demo with teach-by-example + instant learning |
| **M4 P2 Proves its fixes** | Fix intents, recipes for the top 25 rules × seed vendors, inverse mappings, fix preview with hier_config / JSON Patch, rollback, policy analysis | Keep fix preview for indent/brace families; plain recipes elsewhere |
| **M5 P3 Trustworthy** | Vault encryption, MFA/RBAC, sandboxed workers, RE2 and sandboxed templates, signed packs, PAdES signing, transparency log + verifier CLI, security test suite | Transparency log without consistency proofs (inclusion only) |
| **M6 P4 + polish** | Full evaluation report, performance budgets met, UX polish, accessibility pass | — |
| **M7 Deliverables** | Video, slides, 2-page architecture doc, README; clean-machine setup test; three full dry runs; repo made public | — |

---

# Part D: Winning

## 26. Competitive position

**Commercial and open-source landscape.**
- **Titania Nipper:** CIS-accredited, evidence-rich, step-by-step CLI remediation, even an air-gapped edition, but a closed, fixed device library.
- **Tufin / AlgoSec:** firewall-policy management suites.
- **Batfish:** deep open-source analysis with hand-written per-vendor grammars.
- **Firewall Orchestrator:** firewall documentation.

**None of them lets an administrator teach it a new vendor.**

**Other SIH 26155 teams (5 public repositories reviewed on 2026-09-25).** The common baseline across them: a vendor-neutral model, "AI proposes, rules decide", a training page, SHA-256 chained reports, offline operation, UNKNOWN for missing data. The strongest had multi-signal matching with BGE embeddings and template induction. Several used per-vendor parsers, and one used a GPL library.

**What we have that we didn't see anywhere:**
1. Manual-grounded learning of unseen vendors, including auto-extracted defaults.
2. A precise, invertible mapping language, so learning to read a vendor also gives remediation for it.
3. A learning loop treated as a security boundary (four-eyes on verdict flips, regression gate).
4. Re-audit-verified fixes with rollback.
5. Full ruleset anomaly analysis.
6. A Merkle transparency log with signed checkpoints and DSC-signable PDFs.
7. Leave-one-vendor-out evaluation with ablations.
8. Every framework ID traceable to an official source (OSCAL, STIG/CCI, OLIR).

**Caveat:** we saw 5 of roughly 500 teams. These pillars were chosen because they're hard to reproduce quickly, not because nobody else could think of them. Execution will decide.

**Operational:** keep the repository private until submission.

## 27. Deliverables

### 27.1 Demo video (≤ 2:00)
| Time | Beat |
|---|---|
| 0:00–0:10 | Hook: seven vendors, seven dialects, one question: "Is this network compliant, and can you *prove* it?" |
| 0:10–0:30 | Bulk upload of 7 configs incl. SONiC and AWS; CIS + NIST + STIG selected; fleet dashboard with Compliance % and Coverage % |
| 0:30–0:55 | **P2:** Palo Alto: rule 14 is shadowed by rule 3; telnet allowed on the untrusted zone raises it to Critical. "Preview fix" → re-audit → FAIL→PASS, zero regressions, rollback ready |
| 0:55–1:30 | **P1:** Unseen Huawei config at 22% coverage. The Studio quotes Huawei's own manual ("`undo telnet server enable` … default: disabled"). 6 approvals; the bar climbs to 85% live; re-audit; Huawei-syntax fixes appear (the M3 target; until it is met, record from `docs/DEMO.md`, which uses measured numbers) |
| 1:30–1:48 | **P3:** The signed PDF opens with a valid signature; one edited byte → invalid. Trying to approve a verdict-flipping mapping alone → "second approver required" |
| 1:48–2:00 | **P4:** Numbers: false-PASS 0, LOVO learning curve, ablation "no LLM needed". Close: offline, open source, NTRO-ready |

### 27.2 Slides (5)
1. **The problem and the gap:** multi-vendor reality; checklists vs vendor lock-in; why parsers fail.
2. **Kasauti:** the pipeline on one diagram; shape families + mapping language + SBM.
3. **P1 Learns any vendor:** signals, manual grounding, Training Studio, governance, the LOVO learning curve.
4. **P2 + P3 Proves and protects:** verified fixes, policy analysis, signed reports, transparency log, platform threat model.
5. **P4 + deployment:** metrics table, stack and licences (MeitY OSS aligned), air-gapped deployment, roadmap.

### 27.3 Architecture document (2 pages)
- Page 1: the pipeline diagram, the component table, and the mapping-language worked example (§9.2).
- Page 2: SBM entities, semantic engine and governance, crosswalk hub, remediation verification, security and trust.

### 27.4 README
- Top: 60-second pitch, demo GIF, links to video, slides and architecture doc.
- Quick start in three commands (Docker) plus native setup.
- Sample data, "teach a new vendor" walkthrough, "add a framework" walkthrough.
- Evaluation results table, security model summary, licences and attributions.
- Verified by a teammate on a clean machine.

## 28. Risks
| Risk | Mitigation |
|---|---|
| Scope explosion | Spine → pillars → stretch, gated milestones |
| A wrong security statement in the demo (bad ID or command) | Rule quality gate, official-ID lint, peer review of recipes, re-audit verification |
| False PASS | Four-state facts, version-scoped defaults, REVIEW semantics, zero-false-PASS gate |
| Manual grounding underperforms | Kill criterion at M3; teach-by-example + instant learning carry the demo |
| No real devices | Authored + Batfish + mutation corpora; honest "verified against model" labelling; optional container labs |
| Laptop limits (≈3 GB free RAM, 30 GB disk) | No LLM in the core; small embedding models; native dev over Docker; prune images |
| Licence mistakes | Verified licence table; CI licence check on the lockfile |
| Live demo failure | Pre-recorded video, seeded demo database, fully offline |
| Other teams converge on similar ideas | Depth (evaluation, governance, verification, trust) is hard to copy; keep the repo private until submission |

## 29. Open decisions
1. ~~Product name~~: decided, **Kasauti**; since 2026-09-28 the product shows the English name only (no Devanagari in the UI, reports or titles).
2. ~~Team size and names~~: decided, **one developer + Claude** (§24).
3. ~~NCIIPC outreach owner~~: decided, the developer, by email (§20.5).
4. Whether live collection makes the demo (depends on lab availability and disk).
5. What evaluators get to run: Docker image vs native installer.

---

## Appendix A: research and references
- NAssim: Chen et al., *Software-Defined Network Assimilation*, ACM SIGCOMM 2022. [paper](https://libinliu0189.github.io/papers/NAssim-sigcomm22.pdf), [data (MIT)](https://github.com/AmyWorkspace/nassim)
- Selfstarter: Kakarla et al., *Finding Network Misconfigurations by Automatic Template Inference*, NSDI 2020. [link](https://www.usenix.org/conference/nsdi20/presentation/kakarla)
- Diffy: *Data-Driven Bug Finding for Configurations*, PLDI 2024. [code (MIT)](https://github.com/microsoft/DiffyConfigAnalyzer)
- Mondal et al., *What do LLMs need to Synthesize Correct Router Configurations?*, HotNets 2023. [arXiv](https://arxiv.org/abs/2307.04945)
- Cornetto: *Benchmarking LLM-Driven Network Configuration Repair* (2026). [arXiv](https://arxiv.org/abs/2604.22513); *Evaluating Agentic Configuration Repair* (2026). [arXiv](https://arxiv.org/html/2606.06212)
- Astragalus: *Automatic Configuration Repair for Production Networks* (2026). [arXiv](https://arxiv.org/html/2605.22092)
- *Automated Compliance Mapping with Domain-Adapted Sentence Transformers* (2026). [arXiv](https://arxiv.org/pdf/2607.06364)
- Prompt injection via log content (2026). [arXiv 2605.24421](https://arxiv.org/html/2605.24421), [arXiv 2607.14493](https://arxiv.org/html/2607.14493)
- Al-Shaer & Hamed, *Firewall Policy Advisor*, IEEE INFOCOM 2004. [link](https://www.researchgate.net/publication/4011766_Firewall_Policy_Advisor_for_Anomaly_Discovery_and_Rule_Editing); two-layer cloud filtering algebra (2026). [doi](https://doi.org/10.3390/fi18080426)
- Certificate Transparency, RFC 9162; Sigstore Rekor
- NIST SP 800-53 r5 and OSCAL content: [CSRC](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final), [OSCAL content](https://github.com/usnistgov/oscal-content); NIST OLIR #155 (800-53 r5 → ISO 27001:2022). [catalog](https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155)
- DISA STIG library and CCI. [cyber.mil](https://www.cyber.mil/stigs/downloads), [STIG browser](https://cyber.trackr.live/stig)
- CIS Benchmarks terms. [link](https://www.cisecurity.org/terms-of-use-for-non-member-cis-products)
- OpenConfig models. [repo](https://github.com/openconfig/public)
- hier_config. [repo](https://github.com/netdevops/hier_config), [docs](https://hier-config.readthedocs.io/en/latest/)
- MeitY Policy on Adoption of Open Source Software. [pdf](https://www.meity.gov.in/static/uploads/2024/02/policy_on_adoption_of_oss.pdf)
- Titania Nipper. [product](https://titania.com/products/nipper)

## Appendix B: development environment (measured 2026-09-25)
i5-12500H (12C/16T), 15.7 GB RAM with ~3 GB typically free, RTX 3050 Laptop 4 GB, **30.6 GB free disk**. Python 3.12.8, Node 20, Git, Ollama (qwen2.5:1.5b ✓ Apache-2.0; qwen2.5:3b ✗ research licence), Docker installed with the engine not running, WSL available. Native development day to day; Docker only for packaging.

## Appendix C: changelog
- **v1:** first architecture, stack, traceability.
- **v2:** research on LLM risk, hardware, framework availability; milestone-based phases.
- **v3:** multi-signal semantic engine; OpenConfig; verified remediation libraries; competitor and research review.
- **v4:** self-review: priorities (spine → pillars → stretch), platform security, blockchain decision, firewall analysis, tool corrections.
- **v5.1.33 (2026-09-28, M2.31 AWS security groups and network ACLs):**
  - **The pack.** A sixth seed pack, `aws_vpc`, reads a VPC's `describe-security-groups` and
    `describe-network-acls` output as JSON or YAML: 55 mappings and six quoted defaults
    (docs/reviews/aws_vpc.md).
  - **Records.** A pack can read list items as records: one statement per item, fields in key
    order (`@ FromPort 22 IpProtocol tcp ToPort 22`). A key given twice is refused, and a file
    without one of the export's sections is partial.
  - **First-match evaluation.**
    - Security groups are permit-only rulesets that deny the rest.
    - Network ACL entries are evaluated by rule number, IPv4 and IPv6 apart, with the quoted
      asterisk deny.
    - An entry that can't be placed in a ruleset (an unread network ACL entry) counts as an
      unknown entry everywhere, never as missing.
  - **References between security groups** (moved from M2.23):
    - A group in the file resolves to it.
    - A group AWS returns with its account exists (`ref` gains `exists`).
    - One returned without an account was deleted (a stale rule): dangling.
    - A named group is the instances in it, never every address.
    - A referenced prefix list exists, but its entries aren't in the export: REVIEW.
  - **Identity.** Identity reads a record's field (`field: VpcId`), and `all_agree` refuses a
    hostname when an export names several VPCs.
  - **Rules.** Every rule names the roles it covers. Only FILTER-PERMIT-ANY-01 and
    REF-DANGLING-01 judge cloud filters.
  - **Fixed on the way:**
    - The "understood" count counted a line twice when both a mapping and identity read it
      (49 of 48). It now counts statements once. Golden counts moved; verdicts didn't.
    - A partial file's FAIL was downgraded because an attribute the vendor never has (a PAN-OS
      rule's `applications`) was "missing". Now only attributes something could set count.
    - A permit whose source is already every address stayed REVIEW when it also named an object
      of unknown extent. It is now a permit-any.
    - The `network` transform reads `10.1.2.3/0` as every address.
    - JSON and YAML are now built from the parser's events, with libyaml's parser where PyYAML
      has it, and nesting is bounded as it arrives. New AWS-shaped hostile files took 11 s per
      MiB. PyYAML's composer took 5 of those, and it recurses once per nesting level; libyaml's
      composer has no recursion limit at all. They now take about 4 s. A record's repeated-key
      check was quadratic; it now uses a set.
- **v5.1.34 (2026-09-28, M2.75–M2.83 the web UI, first cut):**
  - **Screens.** Dashboard, New audit (with pairing by hand and details typed by hand), audit
    results, device view with the provenance drawer, knowledge base, frameworks and rules
    (`frontend/`). The Training Studio waits for its engine (M2.62–M2.69).
  - **Dependencies, fewer than §19.3 listed.** The runtime is React, React DOM, React Router,
    TanStack Query and lucide. Charts are plain SVG, the drop area is our own, and the
    configuration viewer is built from the result's evidence instead of Monaco: less code to
    trust, and a CSP with no inline script or style. `npm run licences` applies the §19.5 policy;
    CI gains a `web` job.
  - **Served by `kasauti serve`**, same origin as the API, from `frontend/dist`, under its own
    policy; only known file types inside the build folder are served.
  - **API.** `GET /api/uploads`, `GET /api/audits` (each audit with a summary), each device's
    PDF and an upload's zip of PDFs (M2.72), and the knowledge base (`/api/kb`).
  - **Closed on the way:**
    - `load_kb` accepted a folder with no packs: a server started outside the repository root
      ran with an empty knowledge base and would have failed every audit. It now refuses to
      start and says why.
    - A summary counted a failing rule at its base severity while its findings, raised by
      exposure, said critical: the dashboard now counts what the findings say.
- **v5.1.35 (2026-09-28, the web UI redesigned, brand and logo):**
  - **Identity.** "Basalt and brass", after the touchstone: basalt frames the product, and brass
    marks the brand and the single primary action on a screen, nothing else. The logo is a basalt
    slab with a brass streak drawn as a tick and two fainter earlier streaks
    (`frontend/src/components/Brand.tsx`, the favicon and the PDF header share its geometry).
    The product is named in English only: no Devanagari in the UI, reports or titles.
  - **Colour does one job.** Verdicts get their own hues (jade PASS, vermilion FAIL, indigo
    REVIEW, slate N/A). Amber is gone, because it read like the brand gold. Severity is a single
    ramp shown as a four-bar glyph. Every verdict also has a shape, so no reading depends on
    colour. A firewall's permit and deny are neutral, since an action is not a verdict. The PDF
    uses the same palette.
  - **Type.** IBM Plex Sans and Plex Mono (SIL OFL-1.1, from IBM's repository), bundled with the
    build, so the air-gapped rule still holds. The npm licence gate accepts OFL-1.1 for
    `@fontsource` font packages only.
  - **Layout.** A top bar replaces the sidebar. One "posture" panel replaces the rows of equal
    stat cards: compliance, every check by verdict, coverage, the share of each file understood,
    and failed checks by severity. The overview, an upload's results and the device view all use
    it. The device view has breadcrumbs, identity with readable sources and a basalt
    configuration viewer. The provenance drawer is a numbered chain with one code panel per file.
    New audit shows a step indicator. The knowledge-base table no longer overflows.
  - **Closed on the way:**
    - The PDF's top risks ranked failed rules by their base severity, while the findings
      (raised by exposure) and the dashboard said critical. The PDF now ranks and counts by
      effective severity (`effective_severity`), with failed checks and failed findings shown
      apart. A test holds the PDF and the web summary to the same counts on every weak sample.
    - Vendor-pack descriptions and one rule intent showed plan and TODO references to users.
      Those now live in YAML comments. Only the KB and ruleset hashes (and the audit ids derived
      from them) changed in the golden snapshots; no verdict changed.
    - The file-shape and identity-source labels were raw ids and markup ("Json Yaml",
      `` `show version` (dir/…) ``); they now read as words.
- **v5.1.36 (2026-09-29, theme switch and CLI severity):**
  - **Light, dark or the system's.** A three-way switch in the top bar. The choice is kept in the
    browser (`kasauti-theme`) and applied before the first paint by `public/theme.js`, a file
    because the CSP allows no inline script. Dark tokens now hang on `:root[data-theme="dark"]`
    instead of the media query alone, so the viewer's choice can override the system.
  - **The CLI summary said "high" where the audit found critical.** It printed each failed rule's
    base severity. It now prints the effective one (`effective_severity`, moved from the PDF into
    `kasauti/audit.py` so the CLI needn't load ReportLab), like the PDF and the web UI; a test
    holds Telnet on the weak sample's WAN uplink to "critical".
  - **The flaky hostile-file test.** It failed once, under a full suite run alongside slide
    rendering. Not reproduced in 6 × 350 ingest tests run in parallel, nor in 4 parallel runs of
    the test alone; its assertions already name the file and the job's error, so a recurrence
    will say why.
- **v5.5.0 (2026-09-29, team accounts: M5.03-M5.05 in part):**
  - **Sign in, sign up, sign out.** One team, one workspace: every account sees the same fleet,
    and its role says what it may change (`viewer` < `auditor` < `trainer` < `approver` <
    `admin`). Every route under `/api` but health and sign-in needs a session (401), and a change
    needs a role that may make it (403): the server decides, not the screen. A sign-up joins as
    an auditor; `kasauti account add` makes the first administrator and `kasauti account role`
    changes a role; `kasauti serve --no-signup` closes sign-up.
  - **Passwords and sessions.** Argon2id (argon2-cffi, MIT; RFC 9106's second recommended
    profile); at least 15 characters and no composition rules, as NIST SP 800-63B-4 asks of a
    password used alone. Five wrong passwords in a row lock an account for five minutes; an
    unknown name costs a hash too. Sessions are server-side rows keyed by the SHA-256 of a
    random token in an HttpOnly, SameSite=Strict cookie (Secure over HTTPS), ended after 30
    minutes idle, 12 hours after sign-in, or on sign-out. The cross-site checks still apply to
    every change, signing in included.
  - **Four-eyes by real people.** The Studio's "acting as" switch is gone: who proposes and who
    approves is whoever is signed in. A lesson that makes a check pass needs an approver other
    than its proposer; it waits under "Waiting for approval" until one signs in.
  - **Demo accounts.** `kasauti serve --demo-accounts` makes Asha (trainer) and Ravi (approver)
    and shows their passwords on the sign-in page; without the flag nothing is shown.
  - **Still open:** TOTP MFA (M5.03), per-client rate limits beyond the lockout, the admin screen
    for accounts (M5.19), logging every action per account (M5.05).
- **v5.2.0 (2026-09-29, remediation: R-07c, M4 §14):**
  - **Every failed check gets a fix, proven before it is shown.** One fix per failed check,
    covering every entity it fails for, in five steps: pre-check, change, verify, save,
    rollback. The change is the vendor's own commands, filled in from this device's entities
    by curated recipes in each vendor pack (98 across six vendors); `<VALUES>` only the site
    knows (its syslog server, a new password) are left, each described.
  - **Proof.** The commands are applied to a copy of the configuration by an editor for its
    shape family (indent, set-path, block-edit, PAN-OS `set` → XML, AWS CLI → export edits) and
    the copy is re-audited. A fix whose findings clear, with no check worse anywhere, is
    *re-audit verified*. All fixes go on one copy first (one extra audit per device); one that
    doesn't settle there is re-audited alone, within a work limit counted in statements, not
    time, so results stay deterministic. On every weak sample every failed check is fixed and
    verified, and together they take the device to no failed check (PAN-OS: lockout then waits
    for review, because which lockout governs TACACS+ logins isn't documented; the summary says
    so). "Verified" means against Kasauti's model of the device, not on hardware; the JSON, PDF
    and UI all say so, and nothing in the code can reach a device (a test guards it).
  - **Not hier_config.** §14.3 named hier_config for text families; our own editors (no new
    dependency) also cover EOS, Junos `set` and FortiOS, and derive the rollback from what the
    change altered (Junos uses `rollback 1`). Pre-check and verify show what the change touched.
  - **Where it shows.** A Fixes tab on the device view (before → after, the basis, one card per
    check with copyable steps), the finding drawer's link to its fix, PDF section 5, and a CLI
    summary line. The "remediation in a later release" notes are gone.
  - **Safety.** Secrets copied from a configuration stay masked in every step (context-aware:
    a FortiGate community is its `set name`), with a note where one must be typed; `<VALUE>`
    stand-ins stay readable. Examples used for proof are documentation values that never occur
    in real configurations. The loader refuses a recipe for an unknown rule or with an
    undescribed value.
  - **Cost.** 100 mixed files uploaded, recognised, audited and every fix proven in 52 s on the
    development laptop (was about 40 s for the audit alone).
  - **Still open:** syntax checks against vendor manuals (M4.10), fixes for Studio-taught vendors
    by inverse mapping (M4.03), STIG fix text (M4.04), version-specific recipes (M4.15).
- **v5.4.0 (2026-09-29, Training Studio: R-03, R-05, M2.59-M2.69, M2.81, M3.23-M3.24):**
  - **Teach a vendor without code.** The Studio reads configurations of an untaught vendor
    (Huawei VRP) in memory only, and queues the patterns its pack doesn't read, lines inside an
    untaught block after the block. A trainer marks which words are values, picks one of 18
    curated meanings (`packs/studio/meanings.yaml`) and previews what approving it changes:
    lines read, statements understood, and every check that moves (Telnet REVIEW → FAIL). An
    approval is stored in the data folder with who proposed and who approved it; the knowledge
    base reloads in place and the next audit reads it, the server never restarted.
  - **Four-eyes on anything that passes.** A change that makes any check PASS can't be approved
    by whoever proposed it, and the server refuses it, not only the screen. Each person is
    recorded in their own role (`trainer:asha`, `approver:ravi`).
  - **Suggestions that don't mislead.** Measured on the Huawei samples: a meaning was suggested
    whenever a line shared any word with it, so `snmp-agent sys-info version v3` came first as
    "SSH version 1" (one careless approval would fail SSH on a router running only version 2),
    `undo telnet server enable` as "service on", and a TACACS+ line as NTP authentication. A
    meaning now lists the words that name its subject (`requires`, groups that must all
    match), those words weigh more than common ones, and a faint likeness (score < 0.2) is "No
    suggestion". Suggestions still only pre-fill the card.
  - **Measured learning curve** (weak Huawei sample, 13 approvals): 1 → 16 of 37 statements
    understood, 0 → 8 of 23 checks judged (7 FAIL, 1 PASS); the 15 left rest on lines not yet
    taught and stay REVIEW. The earlier target "22 % → 85 % after 6 approvals" was never
    measured and is withdrawn; `docs/DEMO.md` uses measured numbers only.
  - **Found while preparing the demo video:** a finding raised by exposure listed the WAN
    interface line first, so the findings list showed `interface GigabitEthernet1` as the
    evidence for SNMP, SSH and Telnet; a finding's own lines now come first, then the lines that
    located it (goldens: order only, verified across all 14 cases). The PDF showed raw
    backticks around command names. The Studio set a rest-of-line value's other words apart
    from it. `tools/demo_seed.py --export` writes the demo fleet as one folder per device, so a
    folder drop pairs every command output with no pairing by hand.
  - **Still open:** fixes for a taught vendor (M4.03); the manual excerpt and manual grounding
    (M3); anti-unification over several lines, the free attribute tree, keyboard and bulk
    approval, re-running stored audits (see M2.61-M2.69).
- **v5.3.0 (2026-09-29, multi-framework: R-06, M2.51-M2.58):**
  - **Three frameworks, each from its official source.** NIST SP 800-53 Rev. 5 stays the hub.
    DISA STIGs are imported from DISA's published XCCDF (`tools/import_stig.py`): ten benchmarks
    for the five seed platforms that have one (IOS XE Router NDM + RTR, Arista EOS NDM + Router,
    Juniper SRX NDM + ALG, FortiGate NDM + Firewall, Palo Alto NDM + ALG, the last sunset by
    DISA on 2026-07-10 with no successor and marked so), 501 requirements with category, CCIs
    and fix text, every source zip's SHA-256 recorded. ISO/IEC 27001:2022 comes from NIST OLIR
    #155 (`tools/import_olir.py`, hash checked against NIST's): Annex A numbers only, our own
    wording for the 14 controls in use, no ISO text. AWS security groups have no STIG, and the
    report says so instead of scoring zero.
  - **Every mapping checked against the official bridge.** A STIG requirement reaches NIST
    through DISA's CCI list, which now carries Rev. 5 references directly; the 22 CCIs that
    still cite only Rev. 4 follow NIST's own "moved to / incorporated into" links from the
    OSCAL catalog (now kept in `withdrawn`), so every one reaches an active Rev. 5 control. The
    crosswalk lint rejects a mapping that shares no NIST base control with its rule unless a
    `bridge_note` says why (DISA files remote-session encryption under MA-4(6), for instance),
    and a note that isn't needed. 88 STIG mappings, matched by reading each requirement's check
    and fix text; 22 ISO mappings, each within what OLIR #155 relates to the rule's anchors.
    TIME-NTP-AUTH-01 has no ISO control because OLIR #155 relates none to SC-45 or IA-3.
  - **No overclaiming.** A mapping says how much of the control the rule decides: `full`,
    `part` (a FAIL fails the control; a PASS leaves it undetermined) or `stricter` (a PASS meets
    it; a FAIL doesn't break it). A STIG requirement is open or not, never "partially
    satisfied". The framework's two numbers count the same way, so a hardened Cisco router is
    100 % STIG-compliant on 31.6 % coverage: most STIG requirements ask more than a
    configuration can show (DoD banner text, two AAA servers, FIPS ciphers).
  - **Selectable end to end.** New Audit selects every installed framework by default; the CLI
    takes `--framework nist|stig|iso`; NIST always leads. The device view shows each framework's
    two numbers and a Controls tab per framework (STIG with CAT and DISA's wording); the fleet
    dashboard pools each; the PDF has a matrix per framework and its attribution; the Rules page
    shows each rule's ISO controls and STIG requirements per platform. Goldens now score all
    three.
  - **Decided:** a rule's base severity stays our reviewed, vendor-neutral rating rather than the
    STIG category (§12.7): one rule maps to requirements of different categories on different
    platforms. The category is shown beside each STIG requirement.
  - **Groundwork for a vendor taught in the Studio.** A Huawei VRP pack added as data only
    (fingerprint and identity, no mappings) and two authored VRP samples. Two things this
    exposed are fixed: masking now hides VRP's secrets (`community read cipher S`,
    `irreversible-cipher`, `shared-key cipher`, NTP and SNMPv3 `authentication-mode … cipher`),
    where before it masked the kind word and showed the secret; and a verdict that rests only on
    something absent that the vendor's pack can't read yet (no banner seen, because nothing reads
    banners) is now REVIEW, naming what the pack doesn't read. An untaught Huawei router reads
    0 pass, 0 fail, 23 review, instead of five FAILs it had no evidence for. Seed packs read
    every area their rules judge, so their verdicts are unchanged (goldens).
  - **Still open:** CIS Benchmarks (M2.54): recommendation numbers exist only in CIS's benchmark
    PDFs, handed out after registration, so they wait for the team to download them (C.04).
    DISA's fix text is imported but not yet shown with our fixes (M4.04).
- **v5.1.32 (2026-09-27, M2.28 limits closed):** Every Junos file form the CLI writes is now
  replayed as the CLI would (`kasauti/mapping/commands.py`): `[edit …]` banners, prompts and
  command output in terminal captures, `edit`/`up`/`top`/`exit`, `insert`, `rename`, `copy`,
  `delete` of everything, `display set relative` and `explicit`, and braces shown from a level.
  A file that holds only part of a configuration (shown from a level, filtered, `ACCESS-DENIED`,
  a change script) is read at its level and marked partial: every entity type may have more
  members elsewhere, so a witness in the file still fails a rule but nothing passes. Relative
  lines without a banner are placed at the one level the pack's mappings allow. `insert`
  order reaches first-match evaluation (`ConfigTree.order`). `[ … ]` sets of values are one
  statement per value in both forms (brace `application [ a b ]` had been unknown); only ordered
  lists stay joined. Interface next hops and `qualified-next-hop` are read (90 mappings). Two
  Junos-only fingerprint signatures (`root-login`, `authentication-order`) let a system
  fragment be recognised. Fixed on the way: the masker hid `];` after the word `password`, and
  a 20,000-unit export took 12 s (the splitter now keys its cache by path shape). Golden
  verdicts unchanged.
- **v5.1.31 (2026-09-27, M2.28 Junos `display set` exports):** A Junos configuration exported
  as `set` commands is rebuilt into the brace tree it stands for, and read by the same 84
  mappings. Each line is split where the pack's mappings expect blocks, `deactivate`/`delete`
  drop paths, and ordered lists given one value per line are joined back. Before, such a file
  was read line by line with every rule left for review, and it wasn't recognised as Junos
  (score 0); it now scores what the brace file does. The display-set twins of the authored
  configurations give the same facts and verdicts as their brace files, and so does every
  mapping. One false PASS was caught while building it (`web-management http` with settings
  read as unknown). The `{@}` entity key now keys a block's header and its lines alike; before,
  a Junos community and its `authorization` were two entities.
- **v5.1.30 (2026-09-27, M2.26 NX-OS and classic IOS kept out of IOS XE):** No seed pack
  reads NX-OS or classic IOS (§20.4), so the separation M2.26 waited on can't come from their
  packs. A vendor pack's `detect.yaml` can now list `excludes`: patterns that name another OS
  it isn't written for. A match rules the pack out whatever it scores, so the operator is
  asked, with the reason; an operator who chooses the pack anyway is warned. The IOS XE pack
  excludes an NX-OS version line (`version 9.3(1)`) or header (`!Command: show
  running-config`), and a version line of release 15 or earlier. A classic IOS 15
  configuration was claimed as IOS XE with full score (1.2); none of the pack's defaults
  covers that release. Verdicts on all samples unchanged.
- **v5.1.29 (2026-09-27, M2.23 references in firewall policies):** §9.1's FortiOS and
  PAN-OS examples are live: every address or service a policy names is a `Reference`,
  resolved or dangling, and the policy is judged by what the object covers. A name the
  file doesn't define now makes the policy unknown (REVIEW) instead of passing as narrow.
  What a name may be comes from each vendor's documentation; where it may be something
  the pack can't see (a PAN-OS country), it is unknown, not dangling. The AWS case moves to
  M2.31 and the Huawei case to M3.28, with their packs. One golden label corrected. Two
  FortiOS false PASSes closed on the way: IPv6 policy addresses and negated fields.
- **v5.1.28 (2026-09-27, M2.22 role inference from addressing and routes):** The two
  signals §12.7 names besides zone names. SBM 0.10 adds `Interface.addresses` and a `Route`
  entity, read by all five seed packs. An interface is untrusted when it has a public IPv4
  address (IANA's special-purpose registry decides; IPv4 only) or when the default route
  leaves by it (named, or next hop on its subnet), except on a switch. Routes whose exit
  isn't read (blackhole, SD-WAN zone, object destinations) never count. Switch ports are
  now read, so the switch role works on real configs. Verdicts on all samples unchanged.
- **v5.1.27 (2026-09-27, M2.19 manual identity entry):** Identity source 4. A device's
  hostname, OS version, model, serial and hardware can be typed before its audit (upload
  API, or `kasauti audit --identity`). A typed value fills only a field no file gives and is
  marked as entered by hand; a file that disagrees wins, with a warning. Typed values never
  enter the SBM or change a verdict. They are checked as untrusted input: known fields,
  128 characters, printable on one line.
- **v5.1.26 (2026-09-27, M2.18 fingerprinting across all packs):** Every sample is scored
  against all five packs, as an upload is: whole configurations go to their own vendor (1.1 to
  1.5 against 0.7), command outputs to none, fragments to their own vendor or to the operator,
  and no file ever to a wrong vendor. The Junos `set` export gap stays with M2.28.
- **v5.1.25 (2026-09-27, M2.17 family detection on every corpus):** A test walks
  `datasets/` and checks every configuration against its vendor pack's family, with a clear
  margin; a file outside a vendor's folder fails it, so corpora can't grow untested. It
  showed FortiOS winning by 0.01 over indentation: block-edit and brace now score by their
  own balanced pairs, and every sample wins by at least 0.10. M2.28 was reopened: its
  Junos `set` form is still pending though the item was marked done.
- **v5.1.24 (2026-09-27, M2.08 masking reviewed per vendor):** 129 statements across the
  five vendors, syntax checked against each vendor's reference; the M1 masker leaked 29 of
  them (among them Junos NTP and SNMPv3 privacy keys, Cisco trap-host communities after
  `vrf`, IKEv2 asymmetric keys, the type 6 master key, and FortiGate SNMP communities, which
  are only known by their block, so masking now takes the statement's path) and hid 9 words
  that weren't secrets, such as NTP key numbers. Three leaks had reached sample output. Every
  vendor's samples are now scanned for planted secrets after an audit.
- **v5.1.23 (2026-09-27, M2.06 follow-up):** One hostile file no longer costs the other
  files of its recognising job their grouping. An error on one file makes only that file
  unrecognised; a job whose worker is killed or crashes is split into up to 16 smaller jobs,
  and so on, until the file that caused it fails alone (1,000 files: three more rounds, 36
  jobs at most). Tested with a real worker process that dies on one file of three.
- **v5.1.22 (2026-09-27, M2.06 devices, server side):** Uploaded files are grouped into
  devices before the upload starts. A `sort_files` job recognises each file in a worker
  (files added while it waits join it: one job for 100 files, 2 s) and leaves it sealed for
  the audit; the server groups by hostname, then file or folder name, and leaves ties and
  misses for a person, with the reason. The API lets a client pair an output by hand, leave it
  out, or go back to automatic; starting queues one audit per device with its outputs. The
  screen waits for the frontend (M2.77). Migration 0005 adds the pairing columns.
- **v5.1.21 (2026-09-27, M2.09 bulk acceptance):** R-04's acceptance test runs on every
  build: 100 mixed files, a zip among them, each ends audited, refused with a reason, or
  failed with a sentence, in 40 s on 2 workers (74 s on 1) against §22's 3 minutes. Per-job
  start-up fell from about 2 s to 0.65 s without giving up a fresh process per job: the
  worker's side of the pool moved to `kasauti.jobs.child`, which never imports SQLAlchemy or
  Alembic, and packs are read with libyaml after a check of the event stream (no aliases, at
  most 64 levels: libyaml's composer recurses in C, and 5,000 levels ended the process). The
  parsed tree's statements are slotted dataclasses, not pydantic models: a sixth of the
  memory. Found by the test: a PAN-OS file cut off half way was read line by line and still
  failed rules it configures; a file its parser rejects now gets no verdict, only REVIEW
  (§6.1). Worst-case memory (one entity per line) is unchanged and recorded in §22.
- **v5.1.20 (2026-09-27, M2.07 hostile inputs):** The limits reviewed against a generated
  corpus of 7 hostile archives and 28 hostile files, through the intake, every parser and real
  worker processes (§22: 0 crashes, 0 hangs). Found and fixed: an LZMA zip entry declares its
  own dictionary size, allocated before a byte is read (a 1 KB zip committed 1.5 GiB), so
  LZMA entries are refused; nesting was unbounded (256 KiB of nested XML took three minutes),
  so every parser caps it at 100 levels and reads deeper input line by line with a warning;
  unclosed block comments and banners rescanned the rest of the file, and line-by-line regex
  loops in detection and identity cost seconds on a file of empty lines. All now linear:
  whole-text RE2 searches (a million empty lines, 23.7 → 0.23 s). Nested archives stay
  refused (§5.2): opening them would add a second expansion budget for a case device exports
  don't produce.
- **v5.1.19 (2026-09-27, sealed staging):** Closes the open staging risk from v5.1.16:
  a deleted staged configuration could be recovered from the disk. Brought forward from
  M5.01: an upload is sealed as it streams in (AES-256-GCM in 64 KiB segments with the STREAM
  nonce construction, so segments can't be reordered, dropped or cut off; every tag covers the
  file's upload and file ids, so one file can't be passed off as another), under a key made
  at server start and held in memory only. Worker processes get the key from the pool over
  the pipe that starts them (a general, database-free channel for worker secrets); the job
  payload names only the key's id, so a worker holding another key fails the job with a clear
  message and deletes the file. `zipfile` reads a sealed archive through a seekable reader
  that decrypts only the segments it touches. New dependency: `cryptography` 50.0.1 (Apache-2.0
  OR BSD-3-Clause; cffi MIT-0, pycparser BSD-3-Clause), checked on PyPI. The rest of M5.01
  (a key from the OS keystore or a passphrase, content-addressed originals kept for review,
  admin-only decryption, retention) is unchanged.
- **v5.1.18 (2026-09-27, M2.05 companion files):** Serials and hardware (R-07a) come from the
  device's command outputs: `show version`, `show inventory`, `get system status`, `show
  system info`, `show chassis hardware` (and `display version` / `display esn` for a pack that
  declares them). Everything vendor-specific is pack data (R-08): `identity.yaml` gains
  `companions` (signatures that recognise each output, scored like the vendor fingerprint)
  and `inventory` (RE2 records, one hardware component per match), and a pack can't read an
  output it can't recognise. §7's order is now enforced: a companion before the configuration.
  An output from another host or vendor, or a second copy of one command, is refused with the
  reason and listed in the result, never mixed in. The audit result gains `companions` and
  `inventory`; the audit id covers the companions; the PDF device profile gains a hardware
  inventory table. TextFSM, ntc-templates and TTP are dropped from the stack: all three
  compile their templates with Python's backtracking `re` and run them over device output,
  while every expression that meets untrusted text here is RE2 (checked in their sources,
  2026-09-27). Seed packs' output formats were checked against each vendor's documentation;
  two packs named a command their OS doesn't have (FortiOS and PAN-OS `show version`), and
  Arista's model pattern could never match; all fixed.
- **v5.1.17 (2026-09-27, large files):** Closes the result-size limit raised in v5.1.16, and the
  limits behind it. The 32 MiB result limit had in fact capped a configuration at about 1 MiB
  (an audit's JSON is 31 times its configuration). Results are now written by the worker as
  gzip-compressed canonical JSON, checked by the server without being parsed, stored
  compressed (migration 0004, which converts stored results) and served as stored with
  `Content-Encoding: gzip` at `GET /api/jobs/{id}/result`; 64 MiB compressed, 2 GiB expanded.
  An audit's time limit grows with the file's size. Each worker caps its own memory (Windows
  job object, POSIX `RLIMIT_AS`; the memory part of M5.02). Vendor detection no longer parses
  the file once per shape family when no signature needs a tree: a 2.65 MB audit went from 55
  to 37 s and from 1.17 GB to 0.54 GB peak. §22 gains the large-file measurements.
- **v5.1.16 (2026-09-27, M2.04 uploads):** Upload API: an upload is opened, filled one file per
  request (raw bytes, name in `X-File-Name`; a folder is its files, a `.zip` is expanded entry
  by entry), then started as one audit job per accepted file. Every refused file keeps a row
  with its reason (R-04). Names are display labels only; files are staged under random ids, so
  zip-slip has nothing to act on. §5.2 gains the interim rule until the vault (M5.01): an
  original waits on disk only until its audit's worker reads it, and is deleted on that read;
  housekeeping deletes anything no queued job needs. Every state-changing request needs the
  `X-Kasauti-Request` header and a same-origin `Sec-Fetch-Site`/`Origin` (cross-site request
  forgery), ahead of M5's sessions. The job result limit rises from 8 to 32 MiB after
  measuring audit results (about 550 bytes per configuration line). Migration 0003.
- **v5.1.15 (2026-09-27, M2.03 jobs):** §4.3 gains the `jobs` module. The queue is a database
  table (migration 0002); pools claim with `FOR UPDATE SKIP LOCKED` on PostgreSQL and
  `BEGIN IMMEDIATE` on SQLite, hold jobs on a renewed lease, and recover a lost pool's jobs.
  Each job runs in its own spawned process that never sees the database and answers in JSON,
  never pickle. A crash or timeout fails the job without retrying it, since the same input
  would fail again; only lost workers are retried. §17 gains the background-jobs row.
  M5.02 adds OS-level CPU and memory limits to these same processes.
- **v5.1.14 (2026-09-26, M2.02 storage):** SQLAlchemy 2.1 + Alembic; SQLite (WAL) by default,
  PostgreSQL through the optional `postgresql` extra. §17 gains the database row: owner-only
  file, `secure_delete` for the retention policy, verified TLS to any PostgreSQL off the machine,
  URL from the environment only. Migrations are the operator's call on PostgreSQL (`kasauti db
  upgrade`); for single-user SQLite `serve` applies them. CI gains a PostgreSQL job.
- **v5.1.13 (2026-09-26, M2.01 web API shell):** `kasauti serve` runs FastAPI on 127.0.0.1
  only. Serving to the LAN is refused, not merely off by default, until accounts, MFA and TLS
  exist (M5): §17's "localhost by default" tightened, because an unauthenticated API would
  hand configurations to anyone on the network. A Host allow-list stops DNS rebinding; security
  headers on every response; Swagger UI off (it loads from a CDN; §17 air gap).
- **v5.1.12 (2026-09-26, first-match filter evaluation; named login lists):**
  - **Ordered first-match evaluator** (`kasauti/policy/firstmatch.py`), built ahead of M2.31
    because FortiOS local-in policies needed it: can a source no entry names get this traffic
    through? Entries are tried in order; each is asked whether it matches *some* of the
    traffic (a permit then lets it in) and *all* of it (only then does a deny block it); what
    isn't read is MAYBE and turns a decision it could have pre-empted into UNKNOWN. What
    unmatched traffic gets is a quoted vendor fact on the new SBM 0.9 `Ruleset` entity, never
    assumed. It replaces the order-blind "any permit-any entry" check behind
    `Reference.permits_any`.
  - **FortiOS local-in policies read** (IPv4 and IPv6 tables, file order, no implicit deny):
    per interface and management protocol, over IPv4 and, where offered, IPv6, into
    `Interface.mgmt_restricted`; inference `mgmt_service.access_filter.device_filter.*`.
    Management ports (`admin-sport` …) are read and defaulted, port ranges carry their
    protocol (`prepend` transform).
  - **False PASS closed:** FortiOS `ip6-allowaccess` wasn't read, so Telnet/HTTP offered only
    over IPv6 was invisible; Cisco read an *empty* vty ACL as "permits no one", but Cisco
    documents that an empty access list permits all traffic.
  - **Cisco named login lists read:** vty lines take their own list; remote logins are judged
    by what every vty line's list shares, so a TACACS+ default doesn't pass lines whose list is
    local (`MgmtSession.login_methods`, `ref … unless`, objects expanded before lines).
  - **Engine:** unread lines are tracked for blocks opened under a context (a FortiOS `edit`)
    and attributed to the nearest enclosing entity; container headers aren't counted.
    Cisco/Arista extended ACL entries read their destination for every protocol; Junos term
    ports narrow a term.
- **v5.1.11 (2026-09-26, central login in use; PAN-OS and FortiOS gaps):**
  - **False PASS closed on every vendor:** AAA-CENTRAL-AUTH-01 passed when a TACACS+/RADIUS/LDAP
    server was merely configured. It now asks which methods administrator logins use (SBM 0.8
    `AuthPolicy.login_methods`, derivation `aaa.central_login_in_use` replacing
    `aaa.central_server_configured`): Cisco/EOS `aaa authentication login default`, Junos
    `authentication-order`, FortiOS remote administrators and user groups, PAN-OS
    authentication profiles. The FortiOS and PAN-OS hardened twins had this false PASS and were
    fixed.
  - **PAN-OS:** interface management profiles' `permitted-ip` read (an empty list is "no IP
    address restrictions"); proxy ARP off before 12.2.2 by the quoted release gate; lockout
    through an authentication profile is REVIEW (which lockout governs isn't documented);
    Panorama exports and Panorama-managed firewalls get a warning pointing at `show config
    merged`.
  - **FortiOS:** services limited by `iprange`/`fqdn` aren't all traffic (SBM 0.8
    `ObjectDef.destinations`); remote administrators store no password (`hash_type: remote`).
    Local-in policies wait for the ordered first-match evaluator that AWS NACLs (M2.31) need.
  - **Mapping language:** expanding references take any list attribute (`take`) and fill empty
    targets (`if_empty`), keep items from other lines, and resolve user groups to their servers'
    kinds; a new `unknown` effect (with `from`/`unless`) marks a fact the pack can't read.
    Vendor packs can declare input `warnings` in `detect.yaml`.
- **v5.1.10 (2026-09-26, fifth seed vendor: PAN-OS, first XML pack):**
  - **PAN-OS pack** (67 mappings over the XML shape family; 10 defaults quoted from Palo Alto's
    web interface help and admin guide, element names checked against pan-os-python), a weak
    twin with 14 catalogued weaknesses (all caught), golden cases, fixtures for five vendors.
  - **SBM 0.7:** `MgmtService.permitted_sources` (PAN-OS `permitted-ip`; an empty list means
    any) and `FilterRule.applications` (a rule naming applications isn't a permit-all).
  - **Mapping language:** `combine: any` (a service turned on at the MGT port or in any profile
    stays on, whatever the file order) and `ref … expand` (an interface inherits its management
    profile's protocols; unknown if the profile is missing).
  - **Content:** permit-all derivation v3 skips disabled rules and respects applications;
    AAA-LOCKOUT-01 doesn't count a zero lockout duration (PAN-OS documents 0 two ways); a
    per-service permitted-sources inference; PAN-OS secret elements masked.
- **v5.1.9 (2026-09-26, FortiOS gaps closed):**
  - **Administrator trusted hosts** are read per account (SBM 0.6 `LocalUser.permitted_sources`,
    `permitted_sources_v6`); a vendor-neutral inference treats management services as
    source-restricted only when every account is, for IPv4 and IPv6. HTTPS administration on
    FortiOS is now judged.
  - **FortiGuard NTP** is a time source of its own (`TimeSource.enabled`, `TimePolicy.sync_enabled`):
    FAIL with authentication at its documented default, REVIEW where Fortinet's docs are silent.
    Defaults gain `except_keys`; rules no longer list absent scope switches as findings.
  - **Service objects seen through** like addresses (resolver families); `set` with a template
    can narrow a set (`protocol-number 47` makes an all-IP service GRE only).
  - FortiOS pack: 96 mappings, 22 quoted defaults. Remaining limits give FAIL or REVIEW, never
    PASS (local-in policies, service destinations).
- **v5.1.8 (2026-09-26, fourth seed vendor: FortiOS):**
  - **FortiOS pack** (63 mappings; 18 defaults read from the "Default" column of Fortinet's CLI
    reference), a weak twin with 16 catalogued weaknesses (all caught), golden cases, fixtures
    for four vendors.
  - **`on_no_default: fail`:** a rule where absence is the violation now accepts a documented
    protective default (FortiOS locks out after 3 failures) and fails only when there is none.
  - **SBM 0.5:** `PasswordPolicy.enforced` and `LogTarget.enabled`, so a value configured while
    its feature is off (a FortiOS syslog server with `status` disabled) is never a PASS.
  - **Address objects seen through:** the resolver widens policy sources and destinations that
    name catch-all objects or groups, and gives REVIEW where an object's extent wasn't read.
  - **Zone-aware exposures:** "management reachable from untrusted" now asks for management
    protocols on the interface (or no filter and no zone), not only a missing ACL.
- **v5.1.7 (2026-09-26, third seed vendor: Arista EOS):**
  - **Arista EOS pack** (56 mappings, 9 defaults quoted from Arista's documentation, 7 model defaults), a weak
    twin with 20 catalogued weaknesses (19 caught, 1 honestly REVIEW), golden cases, fixtures
    for three vendors on every applicable rule.
  - **Identity from comment headers:** identity sources can be RE2 regexes over raw lines
    (EOS `! device:`; FortiGate `#config-version` next).
  - **EOS `EOF` banners** are parsed as one statement, so banner text is never configuration.
  - **Rule generalised by the third vendor:** FILTER-UNTRUSTED-INGRESS-01 applies to switches
    with untrusted interfaces (a routed ISP uplink), not only to routers and firewalls.
- **v5.1.6 (2026-09-26, second seed vendor: Junos):**
  - **Juniper Junos pack** (67 mappings, defaults quoted from Juniper's documentation), a weak
    twin with 17 catalogued weaknesses, golden cases, and fixtures across two vendors on every
    applicable rule.
  - **Language additions:** a `prefix` transform (hash type from a crypt string) and a `{@}` key
    token (the line of the entity's block).
  - **Rules generalised by the second vendor:**
    - sessions of kind `cli` (Junos login classes) are covered by the timeout rule;
    - zone membership satisfies untrusted-ingress filtering on zone-based firewalls.
  - **A false-PASS path found and closed:** host-inbound services granted to a whole SRX zone
    were ignored.
- **v5.1.5 (2026-09-26, M2 engine completion):**
  - **Inferences and exposures are pack data**, in the same expression language, not hidden
    code (`packs/inferences/`, `packs/exposures/`):
    - Interface and device roles are inferred only where the config is silent, and the
      evidence shows the inference.
    - Severity is base × exposure, and the plan's own §12.7 example is now literal output:
      "High (base) → Critical: telnet is reachable and an untrusted interface lets it through".
  - **The reference resolver (§9.1) creates `Reference` entities (SBM 0.4)**, so these are
    ordinary facts rules judge:
    - dangling references;
    - the chain vty → ACL → permitted sources;
    - recursive group expansion, with cycle detection.
  - **Two new rules:** REF-DANGLING-01 and MGMT-VTY-ACL-02.
  - **A false-PASS path, caught by a test and closed:** an ACL entry line no mapping could read
    was invisible, so "the ACL doesn't permit everyone" could come out *false* instead of
    *unknown*. Lines inside an object's block that nothing understood are now recorded against
    that object.
  - **Also caught by the new validation:** an exposure cited by MGMT-TELNET-01 since M1 had
    never been defined. The loader now rejects unknown exposures and scope mismatches.
- **v5.1.4 (2026-09-26, M1 hardening):** both M1 limits removed.
  - **Every Cisco default is now sourced from Cisco's documentation** (TODO C.06), with the
    sentence quoted in `docs/reviews/cisco_ios_xe.md`. A default the docs don't state has no
    entry, so the rule says REVIEW. Two findings: the SSH default depends on the release
    (compatibility mode 1.99 before IOS XE 17.10, v2 only from 17.10), which is exactly what
    version-scoped defaults are for; and a `username` privilege default that came from memory
    was removed.
  - **Every planted weakness W1–W20 is judged:** 11 new rules, 21 in total (services, password
    policy, web-management ACL, SSH v2, banner, proxy ARP, permit-any entries, untrusted-ingress
    filtering, timestamps, configuration-change logging).
    - The minimum password length follows NIST SP 800-63B-4: 15 characters for single-factor
      passwords.
    - The hardened twin changed to match (`min-length 15`, proxy ARP off everywhere).
  - **Mapping language:** optional groups in patterns (`[log]`, `[vrf <STR>]`; the `[optional]`
    syntax §10.4 already anticipates) and value templates (`"{net} {wildcard}"`).
  - **SBM 0.3**, with its migration: `MgmtService.access_filter`, `Interface.description`,
    `Interface.proxy_arp`, `PasswordPolicy.cleartext_passwords_encrypted`.
  - **Cisco ACL entries are read into `FilterRule`s.** Address forms the mappings don't read
    leave facts absent (REVIEW), never assumed harmless.
  - **Review of the pack** found two real gaps, both fixed with regression tests:
    - `ntp server vrf …` was silently dropped (N/A instead of a verdict);
    - password type 4 gave REVIEW instead of FAIL.
- **v5.1.3 (2026-09-26, M1 build evidence):** the walking skeleton works end to end; refinements it forced (details in `docs/spec/`):
  - **Pattern keys without Drain3.** Drain3 has had no release since 2022, pulls jsonpickle into the runtime, and its similarity merge joins `ip ssh version 2` with `ip ssh time-out 60`. Keys now abstract values by type and keep keywords literal: deterministic, order-independent, still 48 interfaces → 1 pattern (§6.2).
  - **SBM 0.2**, with the first real migration (TODO M2.25). Entities record the lines that named them. `TimePolicy` holds device-wide NTP authentication enforcement (OpenConfig `enable-ntp-auth`), because a key on one server isn't enforcement. The document gains `known_empty` and `unread`.
  - **Closed-world defaults.** `none_of: <EntityType>` in `defaults.yaml` says a vendor ships none of a type (no SNMP communities until one is configured). It is the only way "none seen" can become "none exist". Statements about a type that couldn't be read block any "all/none" conclusion about it.
  - **Near misses.** A line whose keywords match a mapping but whose values don't makes those facts *unknown* (REVIEW), never absent, so a default can't paper over a misread line.
  - **Mapping language:** `otherwise` for value maps; `{#}` ordinal keys, so a secret (an SNMP community) is never an entity key; an empty `context` means top level only.
  - **Two views of defaults.** Vendor defaults decide a rule only when it says `on_absent: resolve_default`; everywhere else a defaulted fact reads as absent. A PASS or FAIL that rests on an unapproved mapping becomes REVIEW (§12.6).
  - **All seven shape families were built in M1**, not M2, because the §9.2 worked example spans them. XML uses defusedxml's SAX parser for line numbers, so lxml isn't needed.
  - **NIST SP 800-53 r5** comes from the official OSCAL release 5.2.0 at a pinned commit: IDs and titles only, with the source SHA-256 recorded.
  - **Security issues found and fixed in M1:**
    - Pattern keys were built from unmasked text, so a short secret could reach a report. They are now built from masked text.
    - Config text is escaped before ReportLab sees it. A crafted line would otherwise crash the report or plant a link.
    - Pack YAML refuses aliases (billion laughs).
  - **Approval of seed mappings.** Seed-pack mappings are approved through repository review (`approved_by: [maintainer]`). Mappings a trainer teaches go through Studio four-eyes approval (M3.24).
- **v5.1.2 (2026-09-26, M0 build evidence):** refinements found while freezing the specs (details in `docs/spec/`):
  - The SBM gains `LoggingPolicy`, for the device-wide logging flags §8.1 put beside `LogTarget`, and `ObjectDef`, the targets of `ref`. `CryptoProfile` gets `dh_groups` (a set) and `lifetime_s`.
  - Derivations live in `packs/derivations/` (content is data), an addition to the §4.4 layout.
  - Entity keys use braces for slots (`key: "{ifname}"`). §9.3's `key: ifname` shorthand is rejected with a hint, because stored literally it would merge all interfaces.
  - Evaluation is four-valued (TRUE/FALSE/ABSENT/UNKNOWN), and a quantifier over zero entities is ABSENT rather than FALSE. This closes a false-PASS path where "nothing parsed" would read as "nothing wrong".
  - Licence policy is strict for runtime dependencies. Unmodified LGPL/MPL is allowed only for dev-only tools.
  - Encoding detection uses charset-normalizer (MIT), not chardet (LGPL).
- **v5.1.1 (2026-09-26):** evidence-based updates. Team is solo + Claude (§24), with review steps adapted in TODO.md. NCIIPC site unreachable from the developer's own machine too, so outreach is email-only (§20.5). Open decisions 2 and 3 closed (§29). Task breakdown created in `docs/TODO.md`.
- **v5.1:** added the `ref` primitive and reference resolver (object/group expansion, dangling-reference findings); plan frozen under evidence-based change control.
- **v5:** full rewrite into one coherent design. New: the **mapping language** (six primitives, worked example, invertibility); the **entity-based SBM** with derivations; a **rule language** with quantifiers and mandatory fixtures; the **crosswalk hub** with official bridges (OLIR #155, CCI with Rev4→Rev5 handling); **verdict-flip four-eyes** governance; **fix preview** via hier_config future/rollback and JSON Patch; manual-grounded syntax checking of fixes; **Compliance % + Coverage %**; exposure-based severity; **DSC-signable PDFs**; RFC 9162-style transparency log; **LOVO evaluation, ablations, mutation testing**; performance budgets; acceptance criteria per requirement; milestone fallbacks; deliberate non-goals.
