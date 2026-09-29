# Demo video script (D-4, ≤ 2:00)

Every number below was measured on the build of 2026-09-29 with the authored samples in
`datasets/authored` (illustrative configurations written from vendor documentation, no real
device). If a number on screen differs when you record, say the number on screen, not this one.

## Before recording

```
uv run --project backend kasauti serve --data-dir var/video --demo-accounts   # terminal 1, repo root
uv run --project backend python tools/demo_seed.py               # terminal 2: the demo fleet
uv run --project backend python tools/demo_seed.py --export var/demo-fleet   # the folder to drop
```

Open http://127.0.0.1:8000/ in a 1440 × 900 window, light theme, browser zoom 100 %. The sign-in
page lists the two demo accounts with their passwords (`--demo-accounts` does that):

| Account | Password | Role |
|---|---|---|
| `asha` | `Kasauti-Demo-Trainer` | trainer: audits, and teaches the Studio |
| `ravi` | `Kasauti-Demo-Approver` | approver: also approves a lesson that makes a check pass |

The seeded fleet belongs to the team, so either account sees it.
To start again from nothing, stop the server and delete `var/video`. Taught Huawei lines live
in `var/video/learned`, so deleting the folder also forgets them.

Have two folders ready in the file picker: `var/demo-fleet` (the bulk upload: one folder per
device, so each device's `show version` and `show inventory` pair with it on their own) and
`datasets/authored/huawei_vrp` (for the Studio).

## Shot list

| Time | Screen | Do | Say (or caption) |
|---|---|---|---|
| 0:00–0:05 | Sign in | **Sign in** on Asha's demo row. | "Kasauti runs on your own machine, for your team." |
| 0:05–0:12 | Overview | Hold on the fleet overview. | "Every brand writes its configuration its own way. One question: is each device secure?" |
| 0:12–0:25 | New audit | **Choose a folder** → `var/demo-fleet`: 12 files, 6 devices. Then **Start audit of 6 devices**. | "Drop a folder. Kasauti recognises each brand from the file itself, six brands here, and pairs each device's `show version` output with it." |
| 0:25–0:35 | Overview | Back to the overview: NIST, DISA STIG and ISO 27001 cards. | "Three standards at once, each with two numbers: how compliant, and how much we could judge." |
| 0:35–0:55 | EDGE-R1 → Findings | Click **Clear-text Telnet management is not reachable**. Point at the lines, then the last line of the Rule step. | "Every finding goes back to the exact lines. Telnet on the WAN port: base severity High, raised to Critical because it faces the internet." |
| 0:55–1:05 | EDGE-R1 → Fixes | Show **21 → 0** and open one fix. | "A five-step fix for every failure: pre-check, change, verify, save, rollback. All 21 applied to a copy and re-audited: 21 failed checks before, 0 after." |
| 1:05–1:30 | Training Studio | Add `huawei_vrp/weak.cfg`. Show **0 fail, 23 review**. As **Asha**: teach `interface`, then `description WAN uplink to ISP` (the value is the rest of the line), then `telnet server enable` → **Preview**: Telnet **Review → Fail** → Approve. | "A brand Kasauti has never seen. It doesn't guess: every check stays in review. A trainer teaches it line by line, and sees what each lesson changes before approving." |
| 1:30–1:45 | Training Studio | Add `hardened.cfg`, teach `http server enable`: preview shows a check turning **Pass**; **Approve as Asha** is greyed out. **Leave it for an approver** → sign out (top right) → **Sign in** on Ravi's row: back in the Studio, **Waiting for approval** → **Approve as Ravi**. | "A lesson that makes a check pass needs a second person, an approver. No single account can talk a device into passing." |
| 1:45–1:55 | Audit of the Huawei file | **Audit** → Start → open BR-HW-AR1 → Telnet finding. | "No restart, no code: the next audit reads Huawei, and Telnet on its WAN port is Critical too." |
| 1:55–2:00 | PDF report | Open EDGE-R1's **PDF report**. | "One report per device. Runs offline; passwords are masked the moment a file arrives." |

## Numbers you can say (measured 2026-09-29)

- Demo fleet: 6 devices, 6 brands (Cisco, Juniper, Arista, Fortinet, Palo Alto, AWS); 10 critical
  failed checks; NIST 49.5 % compliant on 97.2 % coverage. Huawei, taught in the Studio, is the
  seventh brand.
- EDGE-R1 (Cisco IOS XE, weak sample): 21 of 21 judged checks fail; 21 fixes, all re-audit
  verified; 21 failed checks before, 0 after.
- Huawei VRP, untaught: 23 checks, all in review. After 13 approvals from the weak sample:
  16 of 37 lines understood, 8 checks judged (7 fail, 1 pass), 15 still in review because they
  rest on lines not yet taught (AAA, ACLs, the banner). Kasauti says so; it never guesses.
- 100 configurations uploaded, recognised, audited and every fix proven in 52 s on the
  development laptop.
- The Studio's AI suggestions (measured 2026-09-30, `eval/reports/lovo.md`): on a vendor it
  has never seen, the first suggestion is right 74 % of the time (the word lists alone: 57 %);
  when it makes one, it is right 96 %; unsure, it says "No suggestion". On Huawei, which is in
  no seed pack, 27 of 27 lines got the right meaning first.
- Huawei taught with every line the Studio can express (`eval/reports/huawei_teach.md`):
  23 approvals, each the top suggestion, then 11 of 21 checks judged, 10 failing. The model is
  local (30 MB, no GPU, no internet at run time).

## Don't say

- "MFA" or "single sign-on": accounts have passwords (Argon2id) and lockout; MFA is TODO M5.03.

- "Shadowed / redundant rule analysis": the Filtering policy tab lists every rule in one form,
  but the analysis isn't built yet.
- "Signed PDF" or "transparency log": the report says "not digitally signed".
- "CIS scores": CIS Benchmarks aren't installed (their PDFs need a CIS sign-up).
- "AI suggests": Studio suggestions come from word lists and the line's surroundings, not a model.
- "22 % → 85 % after 6 approvals": an early plan target, not a measurement (see above).
- Fixes for Huawei: a Studio-taught brand gets findings, not fix commands yet (TODO M4.03).
