# Security

Kasauti holds the configuration of every network device in an organisation: topology, ACLs,
password hashes, SNMP communities, VPN peers. It is built to pass its own audit (PLAN §17).

> **Status:** draft (Milestone 1). Controls are listed with the milestone that delivers them;
> nothing below is claimed as done until its tests exist (**bold** = in place and tested). The
> final version, including the OWASP ASVS Level 2 self-assessment, lands in Milestone 5
> (TODO M5.21, M5.24).

## Reporting a vulnerability

Please report privately through a GitHub security advisory on this repository ("Report a
vulnerability"), not a public issue. Include what you found, how to reproduce it, and the
impact you expect. We'll acknowledge within 7 days.

## Threat model

Assets, the attacks we design against, and the controls, from PLAN §17.

| Asset / surface | Attack | Control | Milestone |
|---|---|---|---|
| Stored configurations | Disk theft, backup leak, curious insider | AES-256-GCM evidence vault with envelope keys (key from OS keystore or passphrase); masked views; only `admin` decrypts originals; retention policy | M5.01 |
| Accounts | Password guessing, stolen sessions | Argon2id; TOTP MFA enforced at first admin login; lockout and rate limits; server-side sessions in HttpOnly/SameSite/Secure cookies; CSRF tokens; idle timeout | M5.03–M5.04 |
| Authorisation | Viewer approves mappings; auditor edits rules | RBAC: `viewer`, `auditor`, `trainer`, `approver`, `admin`; least privilege; every action logged | M5.05 |
| **Learning loop** | A poisoned or careless mapping silently flips verdicts to PASS | Four-eyes approval on any FAIL→PASS flip; regression gate on golden configs; cleanlab label audit; versioned knowledge base with rollback | M3.23–M3.27 |
| Uploads | Zip bomb, zip-slip, XXE, billion laughs, giant or binary files; a name that climbs out of a folder or disguises its type | **Size limit checked before reading, binary sniffing, `defusedxml` SAX with DTDs forbidden, YAML aliases refused (M1)**; **bodies streamed and cut off at their limit; zip entries counted by what really decompresses (20 MiB a file, 1,000 entries, 512 MiB expanded), nested archives, encrypted and symlink entries refused; names are display labels only (`..`, drive letters, control and bidi-override characters removed) and files are stored under random ids, so zip-slip has nothing to act on (M2.04)**; a memory ceiling on each audit's worker process (2 GiB by default), so a file too dense to audit fails its own job instead of exhausting the machine, and a time limit that grows with the file's size (M2.04 follow-up)**; **reviewed against a generated corpus of 7 hostile archives and 28 hostile files through the intake, every parser and real workers: LZMA zip entries refused (they allocate a dictionary of the entry's choosing, up to 4 GiB), nesting capped at 100 levels in every parser, every parser and search linear in the file's size (M2.07)**; **the job that recognises files before an upload starts gets the same corpus in one job, and its result is checked like input: entries only for files it was given, known kinds, hostnames cleaned and capped, so a worker a hostile file took over can't name other files or inject text; a job such a file kills is split until that file fails alone, so it can't deny the others their grouping (M2.06)**; CPU limits and confinement of the worker processes (M5.02) | M1, M2.04, M2.07, M5.02 |
| Staged uploads | A configuration left on disk in the clear | **Until the vault exists: an owner-only staging directory; a worker recognises the file (configuration or command output, vendor, hostname) and leaves it sealed (M2.06); the audit's worker deletes it as soon as it has read it, before parsing; housekeeping deletes anything no queued job needs and expires unstarted uploads after an hour; the database never holds the file, and a test finds none of a config's planted secrets in the database, its WAL or staging after an audit (M2.04)**; **sealed as it arrives with AES-256-GCM under a key made at server start and kept in memory only, so a deleted staged file leaves only ciphertext on the disk; workers get the key over the pipe that starts them, never through the database; tampering, truncation, reordering or a file passed off as another fails its check (M5.01 first part, v5.1.19)**. The key can reach the disk through the page file or hibernation file; full-disk encryption (BitLocker, LUKS) covers that, and the keystore-backed vault is the rest of M5.01 | M2.04, M5.01 |
| Cross-site requests | A web page the user visits makes the browser POST to the local API (CSRF) | **Every state-changing request needs `X-Kasauti-Request: 1`, which another site can't add without a CORS preflight this server never grants; `Sec-Fetch-Site` must be same-origin and `Origin`, when sent, this server (M2.04)**; session CSRF tokens with sign-in | M2.04, M5.04 |
| Secrets in outputs | Passwords, keys and SNMP communities copied into evidence, pattern keys, JSON or PDF | **Kind-preserving masking (`password 7 ****`) of every displayed line and pattern key; secrets never become entity keys (`community-{#}`); a test scans every audit output for the planted secrets (M1)** | M1, M2.08 |
| Reports | A crafted config line (`<a href=…>`, `<font>`) injects markup into the PDF or breaks it | **All config-derived text is escaped before ReportLab; tested with a crafted line (M1)** | M1 |
| Patterns | ReDoS from admin- or pack-supplied regular expressions | **RE2 (linear time) for the rule `matches` operator and fingerprint regexes (M1)**; for every other untrusted pattern, with a lint | M1, M3.03, M5.06 |
| Templates | Server-side template injection in remediation recipes | Jinja2 `SandboxedEnvironment` with whitelisted filters | M5.07 |
| Packs | Poisoned or code-carrying content imports | Data-only packs (the loader refuses any non-data file; **in place since M0**), schema validation (**M0**), **YAML aliases refused (M1)**; **read with libyaml only after its event stream is checked for aliases and nesting past 64 levels, since libyaml's composer recurses in C and deep nesting would end the process (M2.09)**, Ed25519 signatures, quarantine for unsigned packs | M0, M1, M5.08 |
| Verdicts | A misread, missing or unapproved fact reported as PASS | **Four-valued evaluation; unread lines become *unknown*, never *absent*; vendor defaults only where a rule opts in; unapproved mappings give REVIEW; zero-false-PASS gate in CI (M1)** | M1 |
| Models | Swapped or malicious weights | safetensors only; SHA-256-pinned manifest checked at start-up | M3.13, M5.09 |
| Optional LLM | Prompt injection through config text (descriptions and banners are attacker-writable) | Free text stripped, delimited input, schema-constrained output; the LLM is one optional voter and never decides a verdict; bound to 127.0.0.1 | X.02 |
| Reports and history | Forgery, silent deletion | PAdES signatures (optionally an Indian Class-3 DSC via PKCS#11); Merkle transparency log with signed checkpoints, inclusion and consistency proofs; offline verifier | M5.12–M5.17 |
| Live collection | Credential theft, man-in-the-middle | Read-only device accounts; SSH host-key verification; credentials held in memory only | X.04 |
| Supply chain | Compromised or badly licensed dependency | Hash-locked `uv.lock`; licence gate (**M0**); pip-audit, bandit, gitleaks, trivy; CycloneDX SBOM (**M0 in CI**) | M0.06–M0.07 |
| Network exposure | Tool reachable from the LAN; a web page reaching the localhost API through DNS rebinding | `kasauti serve` binds 127.0.0.1 and refuses any other address until accounts, MFA and TLS exist (M5); requests must name `127.0.0.1` or `localhost` as their host (others get 400); every response carries CSP `default-src 'none'`, `nosniff`, `DENY` framing, `no-referrer`, `no-store`; no server banner; no CDN-loaded API docs. HSTS arrives with TLS | M2.01 (done), M5.10 |
| Background jobs | A hostile file crashing, hanging or exhausting the server; a compromised worker attacking the server; a job row choosing what code runs; configuration text stored in the queue | One fresh process per job (`spawn`), so a crash or hang ends only that job, and nothing carries over to the next; a wall-clock limit per job; **a memory ceiling each worker sets on itself before running anything (Windows job object, POSIX `RLIMIT_AS`) (M2.04 follow-up)**; workers never get a database connection, and send back one size-limited message: a failure as JSON, or a result as gzip that the server checks (one member, intact, expands within 2 GiB, a JSON object) and stores without parsing, never unpickled; a job row names a kind, and only the code's own registry maps kinds to functions; payloads capped at 64 KiB so they carry references, not configurations; errors other than a handler's own message are recorded by exception type only; job ids are random UUIDs; OS-level CPU limits and confinement per worker still to come (a worker a hostile file has taken over could lift its own memory ceiling) | M2.03, M2.04 (done), M5.02 |
| Database | Stolen or tampered database file; a remote database reached in clear text or through an impostor; configuration text echoed in errors | SQLite file and directory created owner-only (0600/0700 on POSIX); WAL with `synchronous=FULL`, `secure_delete=ON` (deleted rows are overwritten), `trusted_schema=OFF`, foreign keys on; only the `sqlite3` and psycopg 3 drivers accepted; a PostgreSQL server off this machine must use `sslmode=verify-full` or `verify-ca`; the URL comes from `KASAUTI_DATABASE_URL`, never argv (visible to every local user), and every message shows it with the password hidden; statement parameters never appear in errors; `/api/health` names the database kind, never its path or host | M2.02 (done) |
| Logs | Secrets leaking into logs | Structured logging with a redaction processor for secret-looking fields (**M0**) | M0.04 |
| Air-gapped sites | No internet at the deployment site | Offline installer, bundled models, signed offline updates for packs and catalogs | M5.11 |

## What "verified" means in a report

A remediation marked **Verified** was applied to a copy of the configuration, re-parsed and
re-audited: its target finding flipped FAIL → PASS and no other finding regressed. That is
verification against Kasauti's model of the device, plus syntax checks. It is **not** a test
on real hardware, and reports say so (PLAN §14.6). Kasauti never pushes changes to devices.

## Secure development

- Every change passes lint, strict typing, tests, the licence gate and security scanners in CI.
- Every dependency's licence is verified at the source before it's added.
- A security test suite (authentication, upload abuse, ReDoS, SSTI, the poisoning gate,
  signature tampering) lands with Milestone 5 (TODO M5.20).
- An SBOM is published with every release (TODO M5.22).
