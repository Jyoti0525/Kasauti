# Dataset sources

Every file under `datasets/` is listed here with its origin, licence and SHA-256
(PLAN §20.2, docs/TODO.md S.07). Files are stored byte-for-byte (see `.gitattributes`), so
hashes and line numbers in findings always match. A file that isn't listed here doesn't belong
in the repository.

**Review status** follows TODO C.06: every authored file is cross-checked line by line
against the vendor's official documentation, then reviewed in a separate pass.

## Authored corpus (`datasets/authored/`)

Written by the Kasauti team from vendor documentation and released under this repository's
Apache-2.0 licence. No real device configuration was used. All secrets are placeholders.

| File | Platform | Lines | SHA-256 | Review |
|---|---|---|---|---|
| `cisco_ios_xe/hardened.cfg` | Cisco IOS-XE 17.9, edge router | 121 | `aa42cfc9a1aadbb8803740d5f9a37df8a021c2ae23245d3e86255508c1f461b2` | commands cross-checked against Cisco docs (C.06, see `docs/reviews/cisco_ios_xe.md`) |
| `cisco_ios_xe/weak.cfg` | Cisco IOS-XE 17.9, weak twin | 59 | `11686e9d46d70ef7a8983b168ceecc8f86fa1112d40a098dd6e67abd6d891946` | commands cross-checked against Cisco docs (C.06) |
| `cisco_ios_xe/fixtures/web_mgmt_restricted.cfg` | Cisco IOS-XE 17.9, HTTPS management behind an ACL (pass fixture for MGMT-WEB-ACL-01) | 16 | `b7a21e0d5106bdd3c0e5eb6d6eff77a1d41f0ed3b3719a5ad3530de5d3bc257d` | commands cross-checked against Cisco docs (C.06) |
| `juniper_junos/hardened.conf` | Junos OS 23.4, branch SRX | 158 | `fd6dbf78b9086b337fdf5b3f9e31e4e5b1c469a5ad7d52a738b82fcc3aaa1fda` | written; doc cross-check pending (C.06) |

References used: Cisco IOS XE 17 configuration guides (security, SSH, AAA, SNMP, NTP, system
management); Juniper Junos OS user guides (system basics, login classes, SSH, syslog, NTP,
firewall filters, security zones).

### Planted weaknesses in `cisco_ios_xe/weak.cfg`

This is the ground truth the M1 walking skeleton must find. Each item names the lines (or
"absent" when the weakness is a missing statement, which must resolve to FAIL or REVIEW, never
PASS) and what the hardened twin does instead.

| # | Lines | Weakness | Hardened twin |
|---|---|---|---|
| W1 | 7 | `service pad` enabled | `no service pad` |
| W2 | 8 | Reversible password storage not blocked (`no service password-encryption`) | `service password-encryption` |
| W3 | 15 | `enable password 0`: clear-text enable password | `enable secret 9` |
| W4 | 17 | Local user with a reversible type-7 password | `secret 9` |
| W5 | absent | No `aaa new-model`: no central AAA, no command accounting | TACACS+ AAA with accounting |
| W6 | absent | No login lockout (`login block-for` absent) | `login block-for 120 attempts 3 within 60` |
| W7 | absent | No minimum password length | `security passwords min-length 12` |
| W8 | 21 | HTTP management server enabled | `no ip http server` |
| W9 | 22 | HTTPS management server enabled without a restricting ACL | disabled |
| W10 | 27 | Proxy ARP on the WAN interface | `no ip proxy-arp` |
| W11 | 37–38, 24–27 | Edge ACL permits everything (`permit ip any any`) and isn't applied to the WAN interface | explicit allow list, final `deny ip any any log` |
| W12 | 40 | No remote syslog host; no timestamps; no config-change logging | `logging host … transport tcp`, `archive log config` |
| W13 | 42 | SNMP community `public` (RO), well-known string | SNMPv3 `priv` only |
| W14 | 43 | SNMP community `private` with **RW** access | none |
| W15 | 45 | NTP without authentication | `ntp authenticate` + trusted key |
| W16 | absent | No `ip ssh version 2` (version left to default) | `ip ssh version 2` |
| W17 | 47–48 | Console never times out (`exec-timeout 0 0`) | `exec-timeout 5 0` |
| W18 | 49–53 | vty 0–4: never times out, type-7 line password, **Telnet allowed**, no access-class | SSH only, `access-class MGMT-ACL in`, 10-minute timeout |
| W19 | 54–57 | vty 5–15: **Telnet only**, 30-minute timeout, no access-class | `transport input none` |
| W20 | absent | No login banner | `banner login` |

## Golden cases (`datasets/golden/`, E1)

Each case holds a `case.yaml` (the input path and SHA-256, and hand-labelled verdicts for every
rule) and an `expected.json` snapshot of the full audit result, reviewed by hand whenever it
changes (PLAN §21.1; `eval/harness/golden.py`). The labels come from the weakness catalogue
above, never from the engine's output.

| Case | Input | Labels |
|---|---|---|
| `cisco_ios_xe_weak` | `authored/cisco_ios_xe/weak.cfg` | all 21 rules FAIL; every weakness W1–W20 is judged by at least one rule |
| `cisco_ios_xe_hardened` | `authored/cisco_ios_xe/hardened.cfg` | 20 rules PASS; MGMT-WEB-ACL-01 N/A (no web server runs) |

History: on 2026-09-26 the hardened twin changed to `security passwords min-length 15` (NIST SP
800-63B-4's minimum for single-factor passwords) and `no ip proxy-arp` on GigabitEthernet3, so
that it is hardened under the full rule set.

## Third-party data

None yet. Batfish example configs (Apache-2.0, TODO M2.33) and the NAssim manual corpus
(MIT, downloaded at setup and not vendored, TODO M3.01) will be listed here when added.
