// The dashboard's numbers (TODO M2.76), worked out from the audits' summaries.
//
// Fleet scores pool the devices' rule counts exactly as one device's are worked out
// (backend/kasauti/rules/scoring.py): Compliance % = passed / (passed + failed), what was judged
// and held; Coverage % = (passed + failed) / (passed + failed + review), what could be judged at
// all. Averaging the devices' percentages instead would let a device with 2 applicable rules
// count as much as one with 20.

import type { AuditOut, RuleBrief, ScoreOut, Severity, Summary } from "../api/types";

export interface Device {
  key: string;
  audit: AuditOut;
  summary: Summary;
}

/** The latest succeeded audit of each device (newest first in `audits`, as the API sends). A
 * device is its vendor pack and host name, or its file name when no host name was found. */
export function latestPerDevice(audits: AuditOut[]): Device[] {
  const seen = new Map<string, Device>();
  for (const audit of audits) {
    const summary = audit.summary;
    if (audit.state !== "succeeded" || !summary) continue;
    const key = `${summary.pack}:${summary.hostname ?? audit.name}`;
    if (!seen.has(key)) seen.set(key, { key, audit, summary });
  }
  return [...seen.values()];
}

export interface Pooled {
  passed: number;
  failed: number;
  review: number;
  not_applicable: number;
  compliance_pct: number | null;
  coverage_pct: number | null;
  devices: number;
}

export function pool(scores: ScoreOut[]): Pooled {
  const sum = (f: (s: ScoreOut) => number) => scores.reduce((n, s) => n + f(s), 0);
  const passed = sum((s) => s.passed);
  const failed = sum((s) => s.failed);
  const review = sum((s) => s.review);
  const judged = passed + failed;
  const applicable = judged + review;
  return {
    passed,
    failed,
    review,
    not_applicable: sum((s) => s.not_applicable),
    compliance_pct: judged === 0 ? null : round1((100 * passed) / judged),
    coverage_pct: applicable === 0 ? null : round1((100 * judged) / applicable),
    devices: scores.length,
  };
}

/** Pooled scores per framework over `devices`. */
export function byFramework(devices: Device[]): Map<string, Pooled & { title: string }> {
  const groups = new Map<string, { title: string; scores: ScoreOut[] }>();
  for (const d of devices) {
    for (const s of d.summary.scores) {
      const g = groups.get(s.framework) ?? { title: s.title, scores: [] };
      g.scores.push(s);
      groups.set(s.framework, g);
    }
  }
  return new Map([...groups].map(([id, g]) => [id, { ...pool(g.scores), title: g.title }]));
}

/** Pooled scores (for `framework`) per vendor pack. */
export function byVendor(devices: Device[], framework: string): Map<string, Pooled> {
  const groups = new Map<string, ScoreOut[]>();
  for (const d of devices) {
    const s = d.summary.scores.find((x) => x.framework === framework);
    if (!s) continue;
    groups.set(d.summary.pack, [...(groups.get(d.summary.pack) ?? []), s]);
  }
  return new Map([...groups].map(([pack, scores]) => [pack, pool(scores)]));
}

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
};

/** A device's risk: its failed rules weighted by severity. */
export function risk(summary: Summary): number {
  return Object.entries(summary.failed_by_severity).reduce(
    (n, [sev, count]) => n + SEVERITY_WEIGHT[sev as Severity] * (count ?? 0),
    0,
  );
}

export function riskiest(devices: Device[], limit = 5): Device[] {
  return [...devices]
    .filter((d) => risk(d.summary) > 0)
    .sort((a, b) => risk(b.summary) - risk(a.summary) || a.key.localeCompare(b.key))
    .slice(0, limit);
}

export interface FailingRule {
  rule: RuleBrief;
  devices: number;
}

/** Rules failing on the most devices, the most severe first among equals. */
export function topFailing(devices: Device[], limit = 8): FailingRule[] {
  const counts = new Map<string, FailingRule>();
  for (const d of devices) {
    for (const r of d.summary.rules) {
      if (r.status !== "FAIL") continue;
      const found = counts.get(r.rule_id);
      if (found) found.devices += 1;
      else counts.set(r.rule_id, { rule: r, devices: 1 });
    }
  }
  const weight = (r: RuleBrief) => (r.severity ? SEVERITY_WEIGHT[r.severity] : 0);
  return [...counts.values()]
    .sort(
      (a, b) =>
        b.devices - a.devices ||
        weight(b.rule) - weight(a.rule) ||
        a.rule.rule_id.localeCompare(b.rule.rule_id),
    )
    .slice(0, limit);
}

function round1(n: number): number {
  return Math.round(n * 10) / 10;
}
