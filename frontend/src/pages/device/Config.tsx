import { EyeOff } from "lucide-react";
import { useMemo } from "react";
import type { AuditResult, Finding } from "../../api/types";
import { cx } from "../../components/ui";
import { configLines, withGaps } from "../../lib/evidence";

const TONE = {
  FAIL: "border-l-fail bg-fail-soft/60",
  REVIEW: "border-l-review bg-review-soft/60",
  PASS: "border-l-pass",
  "N/A": "border-l-transparent",
};

/** The configuration's lines as the audit holds them, with every verdict against each. */
export function Config({ result, onOpen }: { result: AuditResult; onOpen: (f: Finding) => void }) {
  const rows = useMemo(() => withGaps(configLines(result)), [result]);
  return (
    <div>
      <div className="mb-3 flex items-start gap-2 rounded-lg bg-surface-2 px-3 py-2 text-xs text-muted">
        <EyeOff className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        <span>
          Kasauti keeps no copy of an uploaded file: it is read once, audited and deleted. What you
          see are the lines the audit cites as evidence, with every secret masked. Lines it doesn't
          cite are folded. Lines marked red or amber carry a FAIL or REVIEW; select one to trace it.
        </span>
      </div>
      <div className="overflow-x-auto rounded-xl border border-line bg-surface font-mono text-[12.5px] leading-6">
        {rows.map((row) =>
          row.kind === "gap" ? (
            <div
              key={`gap-${row.from}`}
              className="select-none border-y border-dashed border-line bg-surface-2/60 px-4 text-[11px] text-faint"
            >
              ⋯ lines {row.from}
              {row.to !== row.from && `–${row.to}`} not cited
            </div>
          ) : (
            <div
              key={row.line.line}
              onClick={() => row.line.findings[0] && onOpen(row.line.findings[0])}
              className={cx(
                "group flex border-l-4",
                row.line.status ? TONE[row.line.status] : "border-l-transparent",
                row.line.findings.length > 0 && "cursor-pointer hover:brightness-95",
              )}
              title={[...row.line.mappings].join("\n") || "not read by any mapping yet"}
            >
              <span className="w-14 shrink-0 select-none pr-3 text-right text-faint">
                {row.line.line}
              </span>
              <span
                className={cx(
                  "whitespace-pre pr-4",
                  row.line.mappings.size === 0 && "text-faint italic",
                )}
              >
                {row.line.raw}
              </span>
              {row.line.findings.length > 0 && (
                <span
                  className="ml-auto max-w-[45%] shrink-0 truncate pl-4 pr-3 font-sans text-[11px] text-muted"
                  title={ruleIds(row.line.findings)}
                >
                  {ruleIds(row.line.findings)}
                </span>
              )}
            </div>
          ),
        )}
      </div>
    </div>
  );
}

function ruleIds(findings: Finding[]): string {
  return [...new Set(findings.map((f) => f.rule_id))].join(", ");
}
