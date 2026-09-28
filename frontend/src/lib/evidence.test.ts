import { describe, expect, it } from "vitest";
import type { AuditResult, Evidence, Finding } from "../api/types";
import { configLines, withGaps } from "./evidence";

function ev(line: number, raw: string, file = "r1.cfg", end = line): Evidence {
  return {
    file,
    line_start: line,
    line_end: end,
    raw,
    mapping_id: "cisco_ios_xe/x",
    mapping_version: 1,
    approved_by: ["maintainer"],
  };
}

function finding(status: Finding["status"], evidence: Evidence[]): Finding {
  return {
    rule_id: `R-${status}`,
    entity_id: "Device[device]",
    status,
    severity: "high",
    severity_reason: null,
    reason: "",
    actual: [],
    defaults_used: [],
    evidence,
  };
}

function result(): AuditResult {
  const fact = (evidence: Evidence[]) => ({
    value: 1,
    state: "explicit",
    evidence,
    default_source: null,
  });
  return {
    input: { file: "r1.cfg" },
    sbm: {
      device: {
        key: "device",
        type: "Device",
        evidence: [],
        hostname: fact([ev(3, "hostname R1")]),
      },
      entities: [
        {
          key: "vty",
          type: "Line",
          evidence: [ev(20, "line vty 0 4", "r1.cfg", 22)],
          transport: fact([ev(21, " transport input telnet")]),
        },
      ],
      derived: { "x.y": fact([ev(40, "ip http server"), ev(5, "Serial: X", "show_version.txt")]) },
    },
    findings: [
      finding("PASS", [ev(21, " transport input telnet")]),
      finding("FAIL", [ev(21, " transport input telnet")]),
      finding("REVIEW", [ev(40, "ip http server")]),
    ],
    assurance: {
      unmapped_patterns: [{ pattern_key: "k", count: 1, first_line: 30, example: "foo bar" }],
    },
  } as unknown as AuditResult;
}

describe("the configuration rebuilt from evidence", () => {
  it("holds each cited line once, in order, from the configuration only", () => {
    const lines = configLines(result());
    expect(lines.map((l) => l.line)).toEqual([3, 20, 21, 30, 40]);
    expect(lines.find((l) => l.line === 30)?.mappings.size).toBe(0); // not understood yet
  });

  it("marks a line with its worst verdict and every finding citing it", () => {
    const line = configLines(result()).find((l) => l.line === 21);
    expect(line?.status).toBe("FAIL");
    expect(line?.findings.map((f) => f.status)).toEqual(["PASS", "FAIL"]);
  });

  it("folds the lines between, counting a statement's own lines as shown", () => {
    const rows = withGaps(configLines(result()));
    expect(rows.map((r) => (r.kind === "gap" ? `${r.from}-${r.to}` : r.line.line))).toEqual([
      "1-2",
      3,
      "4-19",
      20,
      21,
      "23-29",
      30,
      "31-39",
      40,
    ]);
  });
});
