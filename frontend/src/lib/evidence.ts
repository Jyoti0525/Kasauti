// The configuration as the audit saw it, rebuilt from its evidence (TODO M2.79).
//
// Kasauti keeps no copy of an uploaded configuration: the audit reads it once and deletes it, and
// only masked evidence lines reach the result. So the viewer shows exactly those lines, in file
// order, with the gaps between them marked, and never anything the result doesn't hold.

import type { AuditResult, Evidence, Fact, Finding, Status } from "../api/types";

export interface Line {
  line: number;
  /** The line's text, or the text of the statement it begins when it spans several lines. */
  raw: string;
  end: number;
  mappings: Set<string>;
  /** The worst verdict among findings citing it. */
  status: Status | null;
  findings: Finding[];
}

export type Row = { kind: "line"; line: Line } | { kind: "gap"; from: number; to: number };

const RANK: Record<Status, number> = { FAIL: 3, REVIEW: 2, PASS: 1, "N/A": 0 };

function isFact(value: unknown): value is Fact {
  return Boolean(value && typeof value === "object" && "state" in value && "evidence" in value);
}

/** Every evidence item the result holds: the device's, each entity's and each derived fact's. */
export function allEvidence(result: AuditResult): Evidence[] {
  const out: Evidence[] = [];
  const entities = [result.sbm.device, ...result.sbm.entities];
  for (const entity of entities) {
    out.push(...entity.evidence);
    for (const value of Object.values(entity)) if (isFact(value)) out.push(...value.evidence);
  }
  for (const fact of Object.values(result.sbm.derived)) out.push(...fact.evidence);
  for (const finding of result.findings) out.push(...finding.evidence);
  return out;
}

/** The configuration file's lines the result holds, in order. Evidence from a command output
 * (another file) is left out: it has its own line numbers. */
export function configLines(result: AuditResult): Line[] {
  const file = result.input.file;
  const lines = new Map<number, Line>();
  const take = (e: Evidence): Line | undefined => {
    if (e.file !== file) return undefined;
    let found = lines.get(e.line_start);
    if (!found) {
      found = {
        line: e.line_start,
        raw: e.raw,
        end: e.line_end,
        mappings: new Set(),
        status: null,
        findings: [],
      };
      lines.set(e.line_start, found);
    }
    if (e.line_end > found.end) found.end = e.line_end;
    if (e.mapping_id) found.mappings.add(`${e.mapping_id}@${e.mapping_version ?? "?"}`);
    return found;
  };
  for (const e of allEvidence(result)) take(e);
  for (const finding of result.findings) {
    for (const e of finding.evidence) {
      const line = take(e);
      if (!line) continue;
      if (!line.findings.includes(finding)) line.findings.push(finding);
      if (!line.status || RANK[finding.status] > RANK[line.status]) line.status = finding.status;
    }
  }
  for (const p of result.assurance.unmapped_patterns) {
    if (!lines.has(p.first_line)) {
      lines.set(p.first_line, {
        line: p.first_line,
        raw: p.example,
        end: p.first_line,
        mappings: new Set(),
        status: null,
        findings: [],
      });
    }
  }
  return [...lines.values()].sort((a, b) => a.line - b.line);
}

/** `lines` with a gap row wherever lines the result doesn't hold lie between two it does. */
export function withGaps(lines: Line[]): Row[] {
  const rows: Row[] = [];
  let next = 1;
  for (const line of lines) {
    if (line.line > next) rows.push({ kind: "gap", from: next, to: line.line - 1 });
    rows.push({ kind: "line", line });
    next = Math.max(next, line.end + 1);
  }
  return rows;
}
