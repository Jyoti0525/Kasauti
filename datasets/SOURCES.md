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
| `cisco_ios_xe/fixtures/vty_acl_permits_any.cfg` | Cisco IOS-XE 17.9, vty lines behind an ACL that permits any source (fail fixture for MGMT-VTY-ACL-02) | 16 | `aebeb3dd78ca32ab8971c7d8263e994d678d9811a625a00d212bbd752b08b2ba` | commands cross-checked against Cisco docs (C.06) |
| `cisco_ios_xe/fixtures/vty_acl_dangling.cfg` | Cisco IOS-XE 17.9, vty lines naming an ACL that doesn't exist (fail fixture for REF-DANGLING-01, MGMT-VTY-ACL-02) | 12 | `be369df0c87e40094137d0abaa4f0a106313089b524a71b6ea0605e593488b1e` | commands cross-checked against Cisco docs (C.06) |
| `juniper_junos/hardened.conf` | Junos OS 23.4, branch SRX | 162 | `b6a504c35d9066a1b0da376dc94e82b7878c9f502fee8b7c0f159f08cdcc7cc9` | commands cross-checked against Juniper docs (C.06, `docs/reviews/juniper_junos.md`) |
| `juniper_junos/weak.conf` | Junos OS 23.4, weak twin | 90 | `f48beafafa88a1d91043583e0a4acad920cb676aa4e51b50eb55685b49248d37` | commands cross-checked against Juniper docs (C.06, `docs/reviews/juniper_junos.md`) |

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

### Planted weaknesses in `juniper_junos/weak.conf`

| # | Weakness | Hardened twin |
|---|---|---|
| J1 | `system services telnet` | not configured |
| J2 | `web-management http` on the WAN unit, unrestricted | not configured |
| J3 | `system services finger` | not configured |
| J4 | `netadmin` in `super-user`: predefined classes never time out | class `NETADMIN` with `idle-timeout 10` |
| J5 | root password `$1$` (MD5-crypt) | `$6$` (SHA-512) |
| J6 | no TACACS+/RADIUS server | `tacplus-server` |
| J7 | no `retry-options` (no lockout) | `tries-before-disconnect 3`, `lockout-period 10` |
| J8 | `minimum-length 6` | `minimum-length 15` |
| J9 | SNMP `community public` with `authorization read-write` | SNMPv3 USM only |
| J10 | `ntp server` without `key`, no `trusted-key` | `key 1` + `trusted-key 1` |
| J11 | no syslog `host` | `host 10.20.10.50` |
| J12 | no `interactive-commands`/`change-log` logging (`any notice` may still include commits: REVIEW) | `interactive-commands any` to host and file |
| J13 | no login `message` | `message "Authorised access only…"` |
| J14 | lo0 input filter `PROTECT-RE` doesn't exist | filter defined |
| J15 | filter `ALLOW-ALL`, term with no `from` and `then accept` | explicit terms ending in discard |
| J16 | WAN unit in no security zone and without an input filter | `ge-0/0/0.0` in zone `untrust` |
| J17 | `proxy-arp unrestricted` on the WAN unit | not configured |

## Golden cases (`datasets/golden/`, E1)

Each case holds a `case.yaml` (the input path and SHA-256, and hand-labelled verdicts for every
rule) and an `expected.json` snapshot of the full audit result, reviewed by hand whenever it
changes (PLAN §21.1; `eval/harness/golden.py`). The labels come from the weakness catalogue
above, never from the engine's output.

| Case | Input | Labels |
|---|---|---|
| `cisco_ios_xe_weak` | `authored/cisco_ios_xe/weak.cfg` | 21 rules FAIL, covering every weakness W1–W20; REF-DANGLING-01 and MGMT-VTY-ACL-02 N/A (no references) |
| `cisco_ios_xe_hardened` | `authored/cisco_ios_xe/hardened.cfg` | 22 rules PASS; MGMT-WEB-ACL-01 N/A (no web server runs) |
| `juniper_junos_weak` | `authored/juniper_junos/weak.conf` | 17 rules FAIL (J1–J17), LOG-CONFIG-CHANGE-01 REVIEW, 3 PASS by documented Junos defaults, 2 N/A (no vty lines) |
| `juniper_junos_hardened` | `authored/juniper_junos/hardened.conf` | 20 rules PASS, 3 N/A (no vty lines, no web management) |

History: on 2026-09-26 the Junos hardened config gained a login class with `idle-timeout 10` and `minimum-length 15`, and the Cisco hardened twin changed to `security passwords min-length 15` (NIST SP
800-63B-4's minimum for single-factor passwords) and `no ip proxy-arp` on GigabitEthernet3, so
that it is hardened under the full rule set.

## Third-party data

None yet. Batfish example configs (Apache-2.0, TODO M2.33) and the NAssim manual corpus
(MIT, downloaded at setup and not vendored, TODO M3.01) will be listed here when added.
