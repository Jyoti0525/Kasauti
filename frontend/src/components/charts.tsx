// Small charts drawn as plain SVG and elements: no chart library, no inline <style>.

import type { ReactNode } from "react";
import { cx } from "./ui";

/** A ring showing a percentage, with the figure in the middle. */
export function Ring({
  value,
  size = 112,
  stroke = 10,
  tone = "gold",
  label,
}: {
  value: number | null;
  size?: number;
  stroke?: number;
  tone?: "gold" | "pass" | "fail" | "review";
  label?: ReactNode;
}) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const shown = value ?? 0;
  const colour = {
    gold: "stroke-gold",
    pass: "stroke-pass",
    fail: "stroke-fail",
    review: "stroke-review",
  }[tone];
  return (
    <div
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth={stroke}
          className="stroke-surface-2"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={c * (1 - shown / 100)}
          className={cx(colour, "transition-[stroke-dashoffset] duration-700")}
        />
      </svg>
      <div className="absolute text-center">
        <div className="text-xl font-semibold tabular-nums">
          {value === null ? "–" : `${Math.round(value)}%`}
        </div>
        {label && <div className="text-[11px] text-muted">{label}</div>}
      </div>
    </div>
  );
}

/** A tone for a compliance percentage. */
export function toneFor(pct: number | null): "pass" | "fail" | "review" {
  if (pct === null) return "review";
  if (pct >= 80) return "pass";
  if (pct >= 50) return "review";
  return "fail";
}

/** One horizontal bar per row, value out of `max` (100 by default). */
export function Bars({
  rows,
  max = 100,
  format = (v) => `${v.toFixed(1)}%`,
}: {
  rows: {
    label: ReactNode;
    value: number | null;
    hint?: ReactNode;
    tone?: "pass" | "fail" | "review" | "gold";
  }[];
  max?: number;
  format?: (v: number) => string;
}) {
  return (
    <ul className="space-y-3">
      {rows.map((row, i) => {
        const tone = row.tone ?? toneFor(row.value);
        const fill = { pass: "bg-pass", fail: "bg-fail", review: "bg-review", gold: "bg-gold" }[
          tone
        ];
        return (
          <li key={i}>
            <div className="mb-1 flex items-baseline justify-between gap-3 text-sm">
              <span className="truncate">{row.label}</span>
              <span className="shrink-0 tabular-nums text-muted">
                {row.value === null ? "–" : format(row.value)}
                {row.hint && <span className="ml-2 text-xs text-faint">{row.hint}</span>}
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-surface-2">
              <div
                className={cx("h-full rounded-full transition-[width] duration-700", fill)}
                style={{ width: `${Math.max(0, Math.min(100, ((row.value ?? 0) / max) * 100))}%` }}
              />
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** One bar split into PASS / FAIL / REVIEW / N/A. */
export function VerdictBar({
  pass = 0,
  fail = 0,
  review = 0,
  na = 0,
}: {
  pass?: number;
  fail?: number;
  review?: number;
  na?: number;
}) {
  const total = pass + fail + review + na || 1;
  const parts = [
    { n: fail, cls: "bg-fail", label: "FAIL" },
    { n: review, cls: "bg-review", label: "REVIEW" },
    { n: pass, cls: "bg-pass", label: "PASS" },
    { n: na, cls: "bg-na/40", label: "N/A" },
  ];
  return (
    <div
      className="flex h-2 w-full overflow-hidden rounded-full bg-surface-2"
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

export function Legend({ items }: { items: { cls: string; label: ReactNode }[] }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
      {items.map((it, i) => (
        <span key={i} className="inline-flex items-center gap-1.5">
          <span className={cx("size-2 rounded-full", it.cls)} aria-hidden />
          {it.label}
        </span>
      ))}
    </div>
  );
}
