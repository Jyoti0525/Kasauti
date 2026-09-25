# Security

Kasauti holds the configuration of every network device in an organisation: topology, ACLs,
password hashes, SNMP communities, VPN peers. It is built to pass its own audit (PLAN §17).

> **Status:** draft (Milestone 0). Controls are listed with the milestone that delivers them;
> nothing below is claimed as done until its tests exist. The final version, including the
> OWASP ASVS Level 2 self-assessment, lands in Milestone 5 (TODO M5.21, M5.24).

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
| Uploads | Zip bomb, zip-slip, XXE, billion laughs, giant or binary files | Size/entry/depth limits; path normalisation; `defusedxml`; binary sniffing; parsing in sandboxed worker processes with CPU, memory and time limits | M2.07, M5.02 |
| Patterns | ReDoS from admin- or pack-supplied regular expressions | RE2 (linear time) for every untrusted pattern | M3.03, M5.06 |
| Templates | Server-side template injection in remediation recipes | Jinja2 `SandboxedEnvironment` with whitelisted filters | M5.07 |
| Packs | Poisoned or code-carrying content imports | Data-only packs (the loader refuses any non-data file; **in place since M0**), schema validation (**M0**), Ed25519 signatures, quarantine for unsigned packs | M0, M5.08 |
| Models | Swapped or malicious weights | safetensors only; SHA-256-pinned manifest checked at start-up | M3.13, M5.09 |
| Optional LLM | Prompt injection through config text (descriptions and banners are attacker-writable) | Free text stripped, delimited input, schema-constrained output; the LLM is one optional voter and never decides a verdict; bound to 127.0.0.1 | X.02 |
| Reports and history | Forgery, silent deletion | PAdES signatures (optionally an Indian Class-3 DSC via PKCS#11); Merkle transparency log with signed checkpoints, inclusion and consistency proofs; offline verifier | M5.12–M5.17 |
| Live collection | Credential theft, man-in-the-middle | Read-only device accounts; SSH host-key verification; credentials held in memory only | X.04 |
| Supply chain | Compromised or badly licensed dependency | Hash-locked `uv.lock`; licence gate (**M0**); pip-audit, bandit, gitleaks, trivy; CycloneDX SBOM (**M0 in CI**) | M0.06–M0.07 |
| Network exposure | Tool reachable from the LAN | Binds to localhost by default; TLS, CSP, HSTS and other security headers when exposed | M2.01, M5.10 |
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
