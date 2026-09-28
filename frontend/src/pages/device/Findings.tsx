import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import type { AuditResult, Finding, Severity, Status } from "../../api/types";
import { Chip, Empty, Mono, SeverityBadge, StatusBadge } from "../../components/ui";
import { titleCase } from "../../lib/format";

const STATUSES: Status[] = ["FAIL", "REVIEW", "PASS", "N/A"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const ORDER: Record<Status, number> = { FAIL: 0, REVIEW: 1, PASS: 2, "N/A": 3 };
const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function Findings({
  result,
  onOpen,
}: {
  result: AuditResult;
  onOpen: (f: Finding) => void;
}) {
  const [statuses, setStatuses] = useState<Set<Status>>(new Set(["FAIL", "REVIEW"]));
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());
  const [domain, setDomain] = useState("");
  const [control, setControl] = useState("");
  const [query, setQuery] = useState("");

  const rules = useMemo(() => new Map(result.rules.map((r) => [r.rule_id, r])), [result]);
  const domains = useMemo(() => [...new Set(result.rules.map((r) => r.domain))].sort(), [result]);
  const controls = useMemo(() => result.controls.map((c) => c.control), [result]);

  const shown = result.findings
    .filter((f) => statuses.size === 0 || statuses.has(f.status))
    .filter((f) => severities.size === 0 || (f.severity && severities.has(f.severity)))
    .filter((f) => !domain || rules.get(f.rule_id)?.domain === domain)
    .filter((f) => !control || rules.get(f.rule_id)?.nist_800_53r5.includes(control))
    .filter((f) => {
      if (!query) return true;
      const q = query.toLowerCase();
      const r = rules.get(f.rule_id);
      return [f.rule_id, f.entity_id, f.reason, r?.title ?? "", ...f.evidence.map((e) => e.raw)]
        .join(" ")
        .toLowerCase()
        .includes(q);
    })
    .sort(
      (a, b) =>
        ORDER[a.status] - ORDER[b.status] ||
        (a.severity ? SEV_ORDER[a.severity] : 9) - (b.severity ? SEV_ORDER[b.severity] : 9) ||
        a.rule_id.localeCompare(b.rule_id),
    );

  const count = (s: Status) => result.findings.filter((f) => f.status === s).length;
  const toggle = <T,>(set: Set<T>, value: T, update: (s: Set<T>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    update(next);
  };

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {STATUSES.map((s) => (
          <Chip key={s} active={statuses.has(s)} onClick={() => toggle(statuses, s, setStatuses)}>
            {s} · {count(s)}
          </Chip>
        ))}
        <span className="mx-1 h-4 w-px bg-line" />
        {SEVERITIES.map((s) => (
          <Chip
            key={s}
            active={severities.has(s)}
            onClick={() => toggle(severities, s, setSeverities)}
          >
            {s}
          </Chip>
        ))}
        <select
          aria-label="Domain"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          className="rounded-full border border-line bg-surface px-2.5 py-0.5 text-xs"
        >
          <option value="">All domains</option>
          {domains.map((d) => (
            <option key={d} value={d}>
              {titleCase(d)}
            </option>
          ))}
        </select>
        <select
          aria-label="NIST control"
          value={control}
          onChange={(e) => setControl(e.target.value)}
          className="rounded-full border border-line bg-surface px-2.5 py-0.5 text-xs"
        >
          <option value="">All NIST controls</option>
          {controls.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <label className="ml-auto flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2 py-1">
          <Search className="size-3.5 text-faint" aria-hidden />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search findings, lines…"
            className="w-52 bg-transparent text-sm outline-none"
          />
        </label>
      </div>

      {shown.length === 0 ? (
        <Empty title="No finding matches these filters" />
      ) : (
        <div className="overflow-hidden rounded-xl border border-line bg-surface">
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-b border-line bg-surface-2">
                <th className="px-4 py-2 font-medium">Verdict</th>
                <th className="px-3 py-2 font-medium">Severity</th>
                <th className="px-3 py-2 font-medium">Check</th>
                <th className="px-3 py-2 font-medium">Where</th>
                <th className="px-4 py-2 font-medium">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((f, i) => {
                const r = rules.get(f.rule_id);
                return (
                  <tr
                    key={`${f.rule_id}:${f.entity_id}:${i}`}
                    onClick={() => onOpen(f)}
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onOpen(f)}
                    tabIndex={0}
                    className="cursor-pointer border-b border-line align-top last:border-0 hover:bg-surface-2"
                  >
                    <td className="px-4 py-2.5">
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="px-3 py-2.5">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="font-medium">{r?.title ?? f.rule_id}</div>
                      <div className="mt-0.5 flex flex-wrap gap-x-2 text-[11px] text-faint">
                        <span className="font-mono">{f.rule_id}</span>
                        {r && r.nist_800_53r5.length > 0 && (
                          <span>NIST {r.nist_800_53r5.join(", ")}</span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <Mono className="text-muted">{f.entity_id}</Mono>
                    </td>
                    <td className="max-w-sm px-4 py-2.5">
                      {f.evidence[0] ? (
                        <div className="truncate font-mono text-[12px] text-muted">
                          <span className="text-faint">{f.evidence[0].line_start}: </span>
                          {f.evidence[0].raw}
                        </div>
                      ) : (
                        <span className="text-xs text-faint">
                          {f.defaults_used.length ? "vendor default" : "not configured"}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="mt-3 text-xs text-muted">
        Select a finding to trace it from the configuration line to the control.
      </p>
    </div>
  );
}
