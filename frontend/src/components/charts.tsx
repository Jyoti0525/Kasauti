// Small charts drawn as plain elements: no chart library, no inline <style> element.

import { Check, Eye, Minus, X } from "lucide-react";
import type { ReactNode } from "react";
import type { Severity } from "../api/types";
import { pct } from "../lib/format";
import { SEVERITY_TEXT, SeverityGlyph, cx } from "./ui";

export type Tone = "pass" | "fail" | "review" | "brass" | "data";

const FILL: Record<Tone, string> = {
  pass: "bg-pass",
  fail: "bg-fail",
  review: "bg-review",
  brass: "bg-brass",
  data: "bg-data",
};

/** A tone for a compliance percentage. */
export function toneFor(pct: number | null): "pass" | "fail" | "review" {
  if (pct === null) return "review";
  if (pct >= 80) return "pass";
  if (pct >= 50) return "review";
  return "fail";
}

/** One value out of `max` as a thin bar. */
export function Meter({
  value,
  max = 100,
  tone,
  className,
}: {
  value: number | null;
  max?: number;
  tone?: Tone;
  className?: string;
}) {
  const t = tone ?? toneFor(value);
  return (
    <div className={cx("h-1.5 overflow-hidden rounded-full bg-surface-3", className)}>
      <div
        className={cx("h-full rounded-full transition-[width] duration-700", FILL[t])}
        style={{ width: `${Math.max(0, Math.min(100, ((value ?? 0) / max) * 100))}%` }}
      />
    </div>
  );
}

/** One bar split into FAIL / REVIEW / PASS / N/A, each segment set apart by a hairline. */
export function VerdictBar({
  pass = 0,
  fail = 0,
  review = 0,
  na = 0,
  className = "h-2",
}: {
  pass?: number;
  fail?: number;
  review?: number;
  na?: number;
  className?: string;
}) {
  const total = pass + fail + review + na || 1;
  const parts = [
    { n: fail, cls: "bg-fail", label: "fail" },
    { n: review, cls: "bg-review", label: "review" },
    { n: pass, cls: "bg-pass", label: "pass" },
    { n: na, cls: "bg-line-strong", label: "not applicable" },
  ];
  return (
    <div
      className={cx("flex w-full gap-[2px] overflow-hidden rounded-full bg-surface-3", className)}
      role="img"
      aria-label={parts.map((p) => `${p.n} ${p.label}`).join(", ")}
    >
      {parts.map((p) =>
        p.n ? (
          <div key={p.label} className={p.cls} style={{ width: `${(100 * p.n) / total}%` }} />
        ) : null,
      )}
    </div>
  );
}

const VERDICTS = [
  { key: "fail", label: "Fail", icon: <X />, cls: "text-fail" },
  { key: "review", label: "Review", icon: <Eye />, cls: "text-review" },
  { key: "pass", label: "Pass", icon: <Check />, cls: "text-pass" },
  { key: "na", label: "N/A", icon: <Minus />, cls: "text-na" },
] as const;

type Counts = { pass: number; fail: number; review: number; na: number };

/** The four verdict counts, each with its shape. */
export function VerdictCounts({ counts }: { counts: Counts }) {
  return (
    <dl className="grid grid-cols-4 gap-3">
      {VERDICTS.map((v) => (
        <div key={v.key}>
          <dt
            className={cx(
              "flex items-center gap-1 text-[12px] font-medium [&>svg]:size-3.5 [&>svg]:stroke-[2.75]",
              v.cls,
            )}
          >
            {v.icon}
            {v.label}
          </dt>
          <dd className="figure mt-0.5 text-[22px] font-semibold">{counts[v.key]}</dd>
        </div>
      ))}
    </dl>
  );
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

/** Failed checks by severity, one cell each. */
export function SeverityStrip({ counts }: { counts: Partial<Record<Severity, number>> }) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4">
      {SEVERITIES.map((s, i) => (
        <div
          key={s}
          className={cx(
            "flex items-center gap-3 px-5 py-3.5",
            i > 0 && "sm:border-l sm:border-line",
          )}
        >
          <SeverityGlyph severity={s} className={cx("h-4 w-5", SEVERITY_TEXT[s])} />
          <div>
            <div className="figure text-[19px] font-semibold leading-none">{counts[s] ?? 0}</div>
            <div className="mt-1 text-[12px] capitalize text-muted">{s}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

/** The headline of a fleet, an upload or a device: how much holds, what fails and how badly,
 * and how far the figures can be trusted. */
export function Posture({
  framework,
  compliance,
  coverage,
  counts,
  severity,
  understood,
  scope,
}: {
  framework: string;
  compliance: number | null;
  coverage: number | null;
  counts: Counts;
  severity: Partial<Record<Severity, number>>;
  understood?: number | null;
  scope: ReactNode;
}) {
  const judged = counts.pass + counts.fail;
  const tone = toneFor(compliance);
  return (
    <section className="mb-6 overflow-hidden rounded-xl border border-line bg-surface">
      <div className="grid gap-y-6 p-5 lg:grid-cols-12 lg:gap-x-8 lg:p-6">
        <div className="lg:col-span-4">
          <div className="text-[13px] font-medium text-muted">Compliance · {framework}</div>
          <div className="mt-1 flex items-baseline gap-3">
            <span className="figure text-[52px] font-semibold leading-none">
              {compliance === null ? "–" : `${compliance.toFixed(1)}`}
              <span className="ml-0.5 text-[28px] text-muted">%</span>
            </span>
          </div>
          <Meter value={compliance} tone={tone} className="mt-4 max-w-72" />
          <p className="mt-3 text-[13px] text-muted">
            {counts.pass} of {judged} judged checks hold {scope}.
          </p>
        </div>

        <div className="lg:col-span-5 lg:border-l lg:border-line lg:pl-8">
          <div className="text-[13px] font-medium text-muted">Every check, by verdict</div>
          <VerdictBar {...counts} className="mt-3 h-2.5" />
          <div className="mt-4">
            <VerdictCounts counts={counts} />
          </div>
        </div>

        <div className="space-y-4 lg:col-span-3 lg:border-l lg:border-line lg:pl-8">
          <Figure
            label="Coverage"
            value={coverage}
            hint="of checks judged from the files alone; the rest wait for a person"
          />
          {understood !== undefined && (
            <Figure
              label="Configuration understood"
              value={understood}
              hint="of statements read by an approved mapping"
            />
          )}
        </div>
      </div>
      <div className="border-t border-line bg-surface-2">
        <div className="flex items-center justify-between px-5 pt-3 text-[12px] font-medium text-muted">
          Failed checks by severity
          <span className="figure text-muted">{counts.fail} failed</span>
        </div>
        <SeverityStrip counts={severity} />
      </div>
    </section>
  );
}

function Figure({ label, value, hint }: { label: string; value: number | null; hint: string }) {
  return (
    <div>
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[13px] font-medium text-muted">{label}</span>
        <span className="figure text-[19px] font-semibold">{pct(value)}</span>
      </div>
      <Meter value={value} tone="data" className="mt-2" />
      <p className="mt-1.5 text-[12px] leading-snug text-faint">{hint}</p>
    </div>
  );
}

/** n of total, as a row of dots: how many devices a check fails on. */
export function DotCount({ n, total }: { n: number; total: number }) {
  if (total > 12) {
    return (
      <span className="inline-flex items-center gap-2" aria-label={`${n} of ${total}`}>
        <Meter value={n} max={total} tone="fail" className="w-16" />
        <span className="figure text-[13px] text-muted">
          {n}/{total}
        </span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2" aria-label={`${n} of ${total}`}>
      <span className="flex gap-[3px]" aria-hidden>
        {Array.from({ length: total }, (_, i) => (
          <span
            key={i}
            className={cx("size-2 rounded-[2px]", i < n ? "bg-fail" : "bg-surface-3")}
          />
        ))}
      </span>
      <span className="figure text-[13px] text-muted">
        {n}/{total}
      </span>
    </span>
  );
}

export interface FrameworkScore {
  framework: string;
  title: string;
  compliance_pct: number | null;
  coverage_pct: number | null;
  passed: number;
  failed: number;
  review: number;
  note?: string;
  benchmarks?: string[];
}

/** Each selected framework's two numbers, side by side. Nothing when there is only one: the
 * posture above already shows it. */
export function FrameworkStrip({
  scores,
  className,
}: {
  scores: FrameworkScore[];
  className?: string;
}) {
  if (scores.length < 2) return null;
  return (
    <section className={cx("mb-8 grid gap-4 md:grid-cols-3", className)}>
      {scores.map((s) => (
        <div key={s.framework} className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[13px] font-medium text-muted">{s.title}</div>
          {s.note ? (
            <p className="mt-2 text-[13px] text-faint">{s.note}.</p>
          ) : (
            <>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="figure text-[30px] font-semibold leading-none">
                  {s.compliance_pct === null ? "–" : s.compliance_pct.toFixed(1)}
                  <span className="ml-0.5 text-[17px] text-muted">%</span>
                </span>
                <span className="text-[12.5px] text-muted">compliant</span>
              </div>
              <Meter value={s.coverage_pct} tone="data" className="mt-3" />
              <div className="mt-1.5 flex justify-between gap-3 text-[12px] text-muted">
                <span>
                  Coverage {s.coverage_pct === null ? "–" : `${s.coverage_pct.toFixed(1)}%`}
                </span>
                <span className="tabular-nums">
                  {s.passed} pass · {s.failed} fail · {s.review} review
                </span>
              </div>
              {s.benchmarks && s.benchmarks.length > 0 && (
                <p className="mt-2 text-[12px] leading-snug text-faint">
                  {s.benchmarks.join(" · ")}
                </p>
              )}
            </>
          )}
        </div>
      ))}
    </section>
  );
}
