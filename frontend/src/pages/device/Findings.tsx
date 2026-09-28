import { MousePointerClick } from "lucide-react";
import { useMemo, useState } from "react";
import type { AuditResult, Finding, Severity, Status } from "../../api/types";
import {
  Card,
  Chip,
  Empty,
  Mono,
  SearchBox,
  SEVERITY_TEXT,
  SeverityBadge,
  SeverityGlyph,
  StatusBadge,
  Tag,
} from "../../components/ui";
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
            {s === "N/A" ? "N/A" : s.charAt(0) + s.slice(1).toLowerCase()}
            <span className="figure opacity-70">{count(s)}</span>
          </Chip>
        ))}
        <span className="mx-1.5 h-5 w-px bg-line" aria-hidden />
        {SEVERITIES.map((s) => (
          <Chip
            key={s}
            active={severities.has(s)}
            onClick={() => toggle(severities, s, setSeverities)}
          >
            <SeverityGlyph severity={s} className={severities.has(s) ? "" : SEVERITY_TEXT[s]} />
            <span className="capitalize">{s}</span>
          </Chip>
        ))}
        <span className="mx-1.5 h-5 w-px bg-line" aria-hidden />
        <select
          aria-label="Domain"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          className="field h-7! w-auto! rounded-full! text-[12.5px]!"
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
          className="field h-7! w-auto! rounded-full! text-[12.5px]!"
        >
          <option value="">All NIST controls</option>
          {controls.map((c) => (
            <option key={c} value={c}>
              {c}
            </option>
          ))}
        </select>
        <SearchBox
          value={query}
          onChange={setQuery}
          placeholder="Search checks, objects, lines"
          className="min-w-52 flex-1"
        />
      </div>

      <Card bodyClass="p-0">
        {shown.length === 0 ? (
          <Empty title="No finding matches these filters" />
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th className="w-28">Verdict</th>
                <th className="w-28">Severity</th>
                <th>Check</th>
                <th>Object</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((f, i) => {
                const r = rules.get(f.rule_id);
                return (
                  <tr
                    key={`${f.rule_id}:${f.entity_id}:${i}`}
                    data-link
                    onClick={() => onOpen(f)}
                    onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onOpen(f)}
                    tabIndex={0}
                  >
                    <td>
                      <StatusBadge status={f.status} />
                    </td>
                    <td className="pt-3.5!">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>
                      <div className="font-medium">{r?.title ?? f.rule_id}</div>
                      <div className="mt-1 flex flex-wrap items-center gap-1">
                        <span className="mr-1 font-mono text-[11.5px] text-faint">{f.rule_id}</span>
                        {r?.nist_800_53r5.map((c) => (
                          <Tag key={c}>{c}</Tag>
                        ))}
                      </div>
                    </td>
                    <td>
                      <Mono className="text-muted">{f.entity_id}</Mono>
                    </td>
                    <td className="max-w-sm">
                      {f.evidence[0] ? (
                        <div className="flex min-w-0 items-baseline gap-2 font-mono text-[12.5px]">
                          <span className="shrink-0 text-faint">{f.evidence[0].line_start}</span>
                          <span className="truncate">{f.evidence[0].raw.trim()}</span>
                        </div>
                      ) : (
                        <span className="text-[12.5px] italic text-faint">
                          {f.defaults_used.length ? "vendor default" : "not configured"}
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Card>
      <p className="mt-3 flex items-center gap-1.5 text-[12.5px] text-muted">
        <MousePointerClick className="size-3.5" aria-hidden />
        Select a finding to trace it from the configuration line to the control.
      </p>
    </div>
  );
}
