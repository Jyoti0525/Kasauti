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
| `arista_eos/hardened.cfg` | Arista EOS 4.30, routed leaf with an ISP uplink | 70 | `d6372eb5f4730eabf7b084a54cb1601d99d9eca857b6e04137c515ad021f8cd1` | commands cross-checked against Arista docs (C.06, `docs/reviews/arista_eos.md`) |
| `arista_eos/weak.cfg` | Arista EOS 4.30, weak twin | 53 | `05ec52c6ed8ac684a84da3c78620d89d6c883f8b153257f50adf1436aeacbe48` | commands cross-checked against Arista docs (C.06, `docs/reviews/arista_eos.md`) |
| `fortinet_fortios/hardened.conf` | FortiOS 7.4.8, edge FortiGate 60F | 140 | `1b302a15d8eebb323a1a28212f6c5822f8f5de76d2e89f62d7cc9471d0d71d4d` | commands cross-checked against Fortinet docs (C.06, `docs/reviews/fortinet_fortios.md`) |
| `fortinet_fortios/weak.conf` | FortiOS 7.4.8, weak twin | 82 | `3f9c81f20f880e52f6bf60e45ed2260c1f7dc4bdd1076fbb9dcefd5225c1f97a` | commands cross-checked against Fortinet docs (C.06, `docs/reviews/fortinet_fortios.md`) |
| `paloalto_panos/hardened.xml` | PAN-OS 11.1.2, edge firewall (XML running config) | 311 | `37927308ce4b29ba19ad2edbcd17e2904bf06a6e0a5bdeefa85aa73f62b475f2` | elements cross-checked against Palo Alto Networks docs and pan-os-python (C.06, `docs/reviews/paloalto_panos.md`) |
| `paloalto_panos/weak.xml` | PAN-OS 11.1.2, weak twin | 164 | `d7aad8397621ac42c0c313c3d53c939b85a04f89b41d7bd11b13bd092b1699eb` | elements cross-checked against Palo Alto Networks docs and pan-os-python (C.06, `docs/reviews/paloalto_panos.md`) |

References used: Cisco IOS XE 17 configuration guides (security, SSH, AAA, SNMP, NTP, system
management); Juniper Junos OS user guides (system basics, login classes, SSH, syslog, NTP,
firewall filters, security zones); Arista EOS user manual (connection management, user
security, system clock and time protocols, system event logging, ACLs); Fortinet FortiOS 7.4 CLI reference,
administration guide and log message reference; Palo Alto Networks PAN-OS 11.1 web interface
help and administrator's guide, and element names from pan-os-python (ISC).

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

### Planted weaknesses in `arista_eos/weak.cfg`

| # | Weakness | Hardened twin |
|---|---|---|
| E1 | `username admin … nopassword` | no such user |
| E2 | `netadmin` with `secret 5 $1$…` (MD5-crypt) | `secret sha512 $6$…` |
| E3 | no TACACS+/RADIUS server | `tacacs-server host` + AAA group |
| E4 | no `aaa authentication policy lockout` | `lockout failure 3 duration 900` |
| E5 | no `password minimum length` | `management security` / `password minimum length 15` |
| E6 | no `logging host` | `logging host 10.30.10.50 514 protocol tcp` |
| E7 | no command accounting (whether EOS syslogs config changes by default isn't documented in the pages checked: REVIEW) | `aaa accounting commands all default start-stop group … logging` |
| E8 | `ntp server` without `key`, no `ntp authenticate` | key, trusted-key, `ntp authenticate` |
| E9 | SNMP community `public ro` | none |
| E10 | SNMP community `private rw` | none |
| E11 | Ethernet1 (WAN uplink) without an inbound access-group | `ip access-group EDGE-IN in` |
| E12 | `EDGE-IN 10 permit ip any any` | SSH to the device only, then `deny ip any any log` |
| E13 | eAPI with `protocol http` | eAPI not enabled |
| E14 | eAPI with no access-group | eAPI not enabled |
| E15 | `management console` / `idle-timeout 0` | `idle-timeout 5` |
| E16 | `management ssh` / `idle-timeout 0` | `idle-timeout 10` |
| E17 | `management ssh` / `ip access-group MGMT-ACL in`, ACL never defined | `MGMT-ACL` defined |
| E18 | `management telnet` / `no shutdown` | Telnet left at its default (off) |
| E19 | no login banner | `banner login` … `EOF` |
| E20 | `ip proxy-arp` on the WAN uplink | not configured |

`logging format timestamp traditional` is deliberately present and is **not** a weakness under
LOG-TIMESTAMPS-01: traditional messages are still timestamped.

### Planted weaknesses in `fortinet_fortios/weak.conf`

FortiGate backups print only non-default settings, so several weaknesses are a setting left at
a weak default (F7, F14) or a value set without its on switch (F10).

| # | Weakness | Hardened twin |
|---|---|---|
| F1 | `set admintimeout 480` (8 hours) | `set admintimeout 10` |
| F2 | `set admin-https-redirect disable`: clear-text HTTP administration | redirect left on (default) |
| F3 | HTTP and HTTPS administration accept logins from anywhere: `admin` has no trusted hosts | `trusthost1` and `ip6-trusthost1` on the only administrator |
| F4 | `set admin-ssh-v1 enable` | left disabled (default) |
| F5 | `telnet` (and `http`) in `wan1` `allowaccess` | `wan1` allows `ping` only |
| F6 | `set admin-lockout-threshold 10` | `3`, `admin-lockout-duration 900` |
| F7 | no password policy (status disabled by default, minimum 8) | `status enable`, `minimum-length 15` |
| F8 | admin password `ENC SH2…` (SHA-256) | `ENC PB2…` (PBKDF2) |
| F9 | no TACACS+/RADIUS/LDAP server | `config user tacacs+` |
| F10 | `config log syslogd setting` with a server but `status` left disabled | `status enable`, `mode reliable` |
| F11 | `config log eventfilter` / `set system disable` | event logging left on (default) |
| F12 | SNMP community `public` | none |
| F13 | custom NTP server without `authentication` | `authentication enable`, SHA256 key |
| F14 | no pre-login banner | `set pre-login-banner enable` |
| F15 | `config system proxy-arp` entry on `wan1` | none |
| F16 | policy 1 `wan1 -> internal`, `srcaddr "all"`, `dstaddr "ANY-NET"` (0.0.0.0/0), `service "ALL"`, accept | explicit sources and services only |

### Planted weaknesses in `paloalto_panos/weak.xml`

| # | Weakness | Hardened twin |
|---|---|---|
| P1 | `idle-timeout 0`: administrators are never logged out | `idle-timeout 10` |
| P2 | no `admin-lockout`: Failed Attempts defaults to 0 (unlimited) | `failed-attempts 5`, `lockout-time 30` |
| P3 | `password-complexity` with `minimum-length 8` | `minimum-length 15` |
| P4 | admin `phash` `$1$…` (MD5-crypt) | `$5$…` (SHA-256-crypt) |
| P5 | no TACACS+/RADIUS/LDAP server profile | `server-profile/tacplus` |
| P6 | `disable-telnet no` on the MGT port | `yes` |
| P7 | `disable-http no` on the MGT port | `yes` |
| P8 | no `permitted-ip` on the MGT port (any address) | `permitted-ip 10.30.10.0/24` |
| P9 | interface management profile `ALLOW-MGMT` (HTTPS, SSH) on the WAN interface | profile `PING-ONLY` |
| P10 | no login banner | `login-banner` |
| P11 | syslog profile `SIEM` defined but no System/Config log setting sends to it | `send-syslog SIEM` for System and Config logs, over SSL |
| P12 | SNMP v2c community `public` | a site-specific community |
| P13 | primary NTP server with `authentication-type none` | `symmetric-key` (SHA-1, key id 1) |
| P14 | security rule `allow-all`: untrust → trust, any source, destination, application and service | rules naming sources, applications and `application-default`; an explicit deny-and-log |

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
| `arista_eos_weak` | `authored/arista_eos/weak.cfg` | 17 rules FAIL, covering E1–E20 except E7; LOG-CONFIG-CHANGE-01 and MGMT-SSH-V2-01 REVIEW (no documented default); 4 PASS (3 by documented or model defaults, and MGMT-VTY-ACL-01 because SSH names an ACL: that it dangles is E17, judged by MGMT-VTY-ACL-02) |
| `arista_eos_hardened` | `authored/arista_eos/hardened.cfg` | 21 rules PASS; MGMT-SSH-V2-01 REVIEW (EOS has no SSH version setting and the version isn't documented in the pages checked); MGMT-WEB-ACL-01 N/A (eAPI off) |
| `fortinet_fortios_weak` | `authored/fortinet_fortios/weak.conf` | 16 rules FAIL (F1–F16), 4 PASS by documented or model defaults (and zone-style filtering), 3 N/A (no vty lines, no references) |
| `fortinet_fortios_hardened` | `authored/fortinet_fortios/hardened.conf` | 21 rules PASS (the remote administrator's user group resolves), 2 N/A (no vty lines) |
| `paloalto_panos_weak` | `authored/paloalto_panos/weak.xml` | 13 rules FAIL (P1–P14; P8 and P9 both under MGMT-WEB-ACL-01), 7 PASS by documented or model defaults (proxy ARP: none before 12.2.2), zones and a resolved reference, 1 REVIEW (SSH version), 2 N/A (no vty lines) |
| `paloalto_panos_hardened` | `authored/paloalto_panos/hardened.xml` | 19 rules PASS, 2 REVIEW (SSH version; lockout, since administrators log in through an authentication profile whose lockout Palo Alto doesn't rank against the management one), 2 N/A (no vty lines) |
| `juniper_junos_hardened` | `authored/juniper_junos/hardened.conf` | 20 rules PASS, 3 N/A (no vty lines, no web management) |

History: on 2026-09-26 the Junos hardened config gained a login class with `idle-timeout 10` and `minimum-length 15`, and the Cisco hardened twin changed to `security passwords min-length 15` (NIST SP
800-63B-4's minimum for single-factor passwords) and `no ip proxy-arp` on GigabitEthernet3, so
that it is hardened under the full rule set.

Later the same day, AAA-CENTRAL-AUTH-01 started asking whether logins *use* a central server,
not only whether one is configured. The FortiOS and PAN-OS hardened configs had a TACACS+ server
that no administrator used, so they passed wrongly; they gained a remote administrator
(FortiOS `remote-auth` with a user group) and an authentication profile (PAN-OS
`authentication-profile TACACS-AUTH`). The PAN-OS twin also gained an in-band management
interface whose profile accepts HTTPS and SSH only from the NOC subnet.

## Third-party data

None yet. Batfish example configs (Apache-2.0, TODO M2.33) and the NAssim manual corpus
(MIT, downloaded at setup and not vendored, TODO M3.01) will be listed here when added.
