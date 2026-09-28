import { describe, expect, it } from "vitest";
import type { AuditOut, AuditResult, Finding, ScoreOut, Summary } from "../api/types";
import {
  byVendor,
  failedBySeverity,
  latestPerDevice,
  pool,
  riskiest,
  severityTotals,
  topFailing,
} from "./fleet";

function score(passed: number, failed: number, review = 0, na = 0): ScoreOut {
  return {
    framework: "nist_800_53r5",
    title: "NIST SP 800-53 Rev. 5",
    compliance_pct: null,
    coverage_pct: null,
    passed,
    failed,
    review,
    not_applicable: na,
  };
}

function audit(
  id: string,
  pack: string,
  hostname: string | null,
  s: ScoreOut,
  fails: [string, Summary["failed_by_severity"]] = ["", {}],
  state: AuditOut["state"] = "succeeded",
): AuditOut {
  const [rule, bySeverity] = fails;
  return {
    job_id: id,
    upload_id: "u",
    label: null,
    name: `${id}.cfg`,
    state,
    error: null,
    created_at: "2026-09-28T10:00:00Z",
    finished_at: null,
    summary:
      state === "succeeded"
        ? {
            audit_id: id,
            hostname,
            vendor: null,
            pack,
            os_version: null,
            model: null,
            identity_found: 1,
            identity_total: 6,
            scores: [s],
            statuses: {},
            failed_by_severity: bySeverity,
            rules: rule
              ? [{ rule_id: rule, title: rule, domain: "aaa", severity: "high", status: "FAIL" }]
              : [],
            understood_pct: 90,
            statements: 10,
            warnings: 0,
          }
        : null,
  };
}

describe("fleet scores", () => {
  it("pool rule counts, never average percentages", () => {
    // 1/2 and 18/20: averaging the percentages would say 70 %; the pooled figure is 19/22.
    const pooled = pool([score(1, 1), score(18, 2)]);
    expect(pooled.compliance_pct).toBe(86.4);
    expect(pooled.coverage_pct).toBe(100);
  });

  it("leave compliance unknown when nothing could be judged", () => {
    const pooled = pool([score(0, 0, 3)]);
    expect(pooled.compliance_pct).toBeNull();
    expect(pooled.coverage_pct).toBe(0);
    expect(pool([]).coverage_pct).toBeNull();
  });

  it("count each device once, at its latest audit", () => {
    const audits = [
      audit("new", "cisco_ios_xe", "R1", score(9, 1)),
      audit("old", "cisco_ios_xe", "R1", score(1, 9)),
      audit("fw", "fortinet_fortios", "R1", score(5, 5)), // same name, another vendor: another device
      audit("anon", "aws_vpc", null, score(1, 1)),
      audit("queued", "aws_vpc", null, score(0, 0), undefined, "queued"),
    ];
    const devices = latestPerDevice(audits);
    expect(devices.map((d) => d.audit.job_id)).toEqual(["new", "fw", "anon"]);
    expect(byVendor(devices, "nist_800_53r5").get("cisco_ios_xe")?.compliance_pct).toBe(90);
  });

  it("rank devices by weighted failures and rules by how many devices fail them", () => {
    const devices = latestPerDevice([
      audit("a", "cisco_ios_xe", "A", score(1, 3), ["R-1", { high: 1, low: 2 }]),
      audit("b", "cisco_ios_xe", "B", score(1, 1), ["R-1", { critical: 1 }]),
      audit("c", "cisco_ios_xe", "C", score(4, 0)),
    ]);
    expect(riskiest(devices).map((d) => d.summary.hostname)).toEqual(["B", "A"]);
    expect(topFailing(devices)).toEqual([
      { rule: expect.objectContaining({ rule_id: "R-1" }), devices: 2 },
    ]);
    expect(severityTotals(devices.map((d) => d.summary))).toEqual({ critical: 1, high: 1, low: 2 });
  });
});

describe("the most common failures", () => {
  it("show a check at its worst severity on any device", () => {
    const high = audit("a", "cisco_ios_xe", "A", score(0, 1), ["TELNET", { high: 1 }]);
    const critical = audit("b", "cisco_ios_xe", "B", score(0, 1), ["TELNET", { critical: 1 }]);
    const rule = critical.summary?.rules[0];
    if (rule) rule.severity = "critical"; // exposed on B's untrusted interface
    const [top] = topFailing(latestPerDevice([high, critical]));
    expect(top?.devices).toBe(2);
    expect(top?.rule.severity).toBe("critical");
  });
});

describe("a device's failures by severity", () => {
  it("count each failing rule once, at its worst failing finding", () => {
    const f = (rule_id: string, status: Finding["status"], severity: Finding["severity"]) =>
      ({ rule_id, status, severity }) as Finding;
    const result = {
      rules: [
        { rule_id: "HTTP", status: "FAIL", severity: "high" },
        { rule_id: "SNMP", status: "FAIL", severity: "medium" },
        { rule_id: "NTP", status: "PASS", severity: "low" },
      ],
      findings: [
        f("HTTP", "FAIL", "high"),
        f("HTTP", "FAIL", "critical"), // exposed on an untrusted interface: raised
        f("HTTP", "PASS", "high"),
        f("SNMP", "FAIL", "medium"),
        f("NTP", "PASS", "low"),
      ],
    } as unknown as AuditResult;
    expect(failedBySeverity(result)).toEqual({ critical: 1, medium: 1 });
  });
});

describe("labels", () => {
  it("keep acronyms upper-case", async () => {
    const { titleCase } = await import("./format");
    expect(titleCase("aaa")).toBe("AAA");
    expect(titleCase("os_version")).toBe("OS Version");
    expect(titleCase("management_plane")).toBe("Management Plane");
    expect(titleCase("cloud_filter")).toBe("Cloud Filter");
  });
});

describe("identity sources", () => {
  it("read without markup or folders", async () => {
    const { sourceLabel } = await import("./format");
    expect(sourceLabel("`show version` (cisco_ios_xe/companions/show_version.txt)")).toBe(
      "show version (show_version.txt)",
    );
    expect(sourceLabel("fingerprint (6 signatures)")).toBe("fingerprint (6 signatures)");
  });
});
