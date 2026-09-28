import { EyeOff } from "lucide-react";
import { useMemo } from "react";
import type { AuditResult, Finding } from "../../api/types";
import { Notice, cx } from "../../components/ui";
import { configLines, withGaps } from "../../lib/evidence";

// Lines on a basalt panel: a verdict shows as a bar in the gutter and a wash across the line.
const TONE = {
  FAIL: "border-l-fail bg-fail/15",
  REVIEW: "border-l-review bg-review/15",
  PASS: "border-l-pass/70",
  "N/A": "border-l-transparent",
};

/** The configuration's lines as the audit holds them, with every verdict against each. */
export function Config({ result, onOpen }: { result: AuditResult; onOpen: (f: Finding) => void }) {
  const rows = useMemo(() => withGaps(configLines(result)), [result]);
  return (
    <div>
      <div className="mb-4">
        <Notice icon={<EyeOff />}>
          Kasauti keeps no copy of an uploaded file: it is read once, audited and deleted. What you
          see are the lines the audit cites as evidence, with every secret masked; lines it doesn't
          cite are folded. A red bar marks a line that fails a check, an indigo one a line waiting
          for review. Select a marked line to trace it.
        </Notice>
      </div>
      <div className="overflow-hidden rounded-xl bg-basalt ring-1 ring-basalt-line">
        <div className="flex items-center justify-between border-b border-basalt-line px-4 py-2 text-[12px] text-on-basalt">
          <span className="font-mono">{result.input.file}</span>
          <span className="flex items-center gap-4">
            <span className="flex items-center gap-1.5">
              <span className="h-3 w-1 rounded-full bg-fail" aria-hidden /> fails
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-3 w-1 rounded-full bg-review" aria-hidden /> review
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-3 w-1 rounded-full bg-pass/70" aria-hidden /> holds
            </span>
          </span>
        </div>
        <div className="overflow-x-auto py-2 font-mono text-[12.5px] leading-6 text-[#e6e1d6]">
          {rows.map((row) =>
            row.kind === "gap" ? (
              <div
                key={`gap-${row.from}`}
                className="my-1 select-none border-y border-dashed border-basalt-line bg-white/2 py-0.5 pl-18 text-[11.5px] text-on-basalt/60"
              >
                ⋯ {row.to === row.from ? `line ${row.from}` : `lines ${row.from}–${row.to}`} not
                cited
              </div>
            ) : (
              <div
                key={row.line.line}
                onClick={() => row.line.findings[0] && onOpen(row.line.findings[0])}
                className={cx(
                  "group flex border-l-[3px]",
                  row.line.status ? TONE[row.line.status] : "border-l-transparent",
                  row.line.findings.length > 0 && "cursor-pointer hover:bg-white/6",
                )}
                title={[...row.line.mappings].join("\n") || "not read by any mapping yet"}
              >
                <span className="w-14 shrink-0 select-none pr-4 text-right text-on-basalt/45">
                  {row.line.line}
                </span>
                <span
                  className={cx(
                    "whitespace-pre pr-4",
                    row.line.mappings.size === 0 && "italic text-on-basalt/55",
                  )}
                >
                  {row.line.raw}
                </span>
                {row.line.findings.length > 0 && (
                  <span
                    className="ml-auto max-w-[45%] shrink-0 truncate pl-4 pr-4 text-[11.5px] text-on-basalt/70 group-hover:text-on-basalt"
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
    </div>
  );
}

function ruleIds(findings: Finding[]): string {
  return [...new Set(findings.map((f) => f.rule_id))].join(", ");
}
