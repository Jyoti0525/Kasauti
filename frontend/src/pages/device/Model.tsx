import { useMemo, useState } from "react";
import type { AuditResult, Entity, Fact, FactState } from "../../api/types";
import { Card, Mono, cx } from "../../components/ui";
import { show } from "../../lib/format";

const STATE: Record<FactState, string> = {
  explicit: "text-text",
  vendor_default: "text-brass-ink",
  absent: "text-faint",
  unknown: "text-review",
};

const LEGEND: { state: FactState; label: string; dot: string }[] = [
  { state: "explicit", label: "Configured", dot: "bg-text" },
  { state: "vendor_default", label: "Vendor default (documented, cited)", dot: "bg-brass" },
  { state: "absent", label: "Absent", dot: "bg-faint" },
  { state: "unknown", label: "Unknown: waits for review, never guessed", dot: "bg-review" },
];

function isFact(v: unknown): v is Fact {
  return Boolean(v && typeof v === "object" && "state" in v && "evidence" in v);
}

/** The vendor-neutral security model the configuration was translated into (PLAN §8). */
export function Model({ result }: { result: AuditResult }) {
  const groups = useMemo(() => {
    const m = new Map<string, Entity[]>();
    for (const e of [result.sbm.device, ...result.sbm.entities])
      m.set(e.type, [...(m.get(e.type) ?? []), e]);
    return [...m].sort((a, b) => a[0].localeCompare(b[0]));
  }, [result]);
  const [type, setType] = useState(groups[0]?.[0] ?? "Device");
  const entities = groups.find(([t]) => t === type)?.[1] ?? [];
  const attributes = [
    ...new Set(entities.flatMap((e) => Object.keys(e).filter((k) => isFact(e[k])))),
  ];
  const item = (active: boolean) =>
    cx(
      "flex w-full items-center justify-between rounded-lg px-3 py-1.5 text-left text-[13.5px] transition-colors",
      active
        ? "bg-surface font-medium shadow-[0_0_0_1px_var(--line)]"
        : "text-muted hover:text-text",
    );

  return (
    <div className="grid gap-6 lg:grid-cols-[15rem_1fr]">
      <nav className="space-y-0.5" aria-label="Entity types">
        <div className="mb-2 px-3 text-[12px] font-medium text-faint">Object types</div>
        {groups.map(([t, list]) => (
          <button key={t} type="button" onClick={() => setType(t)} className={item(t === type)}>
            {t}
            <span className="figure text-[12px] text-faint">{list.length}</span>
          </button>
        ))}
        <div className="my-2 border-t border-line" />
        <button
          type="button"
          onClick={() => setType("__derived")}
          className={item(type === "__derived")}
        >
          Derived facts
          <span className="figure text-[12px] text-faint">
            {Object.keys(result.sbm.derived).length}
          </span>
        </button>
      </nav>

      <div className="min-w-0">
        <div className="mb-3 flex flex-wrap gap-x-5 gap-y-1 text-[12.5px] text-muted">
          {LEGEND.map((l) => (
            <span key={l.state} className="inline-flex items-center gap-1.5">
              <span className={cx("size-2 rounded-full", l.dot)} aria-hidden />
              {l.label}
            </span>
          ))}
        </div>
        <Card bodyClass="p-0 overflow-x-auto">
          {type === "__derived" ? (
            <table className="data compact">
              <thead>
                <tr>
                  <th>Fact</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(result.sbm.derived).map(([name, fact]) => (
                  <tr key={name}>
                    <td className="font-mono text-[12.5px]">{name}</td>
                    <td className={cx("font-mono text-[12.5px]", STATE[fact.state])}>
                      {show(fact.value)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="data compact">
              <thead>
                <tr>
                  <th className="sticky left-0 z-10">Key</th>
                  {attributes.map((a) => (
                    <th key={a} className="font-mono text-[11.5px]">
                      {a}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entities.map((e) => (
                  <tr key={e.key}>
                    <td className="sticky left-0 bg-surface">
                      <Mono className="font-medium">{e.key}</Mono>
                    </td>
                    {attributes.map((a) => {
                      const f = e[a];
                      return (
                        <td
                          key={a}
                          className={cx(
                            "max-w-64 truncate whitespace-nowrap font-mono text-[12.5px]",
                            isFact(f) && STATE[f.state],
                          )}
                          title={
                            isFact(f)
                              ? `${f.state}${f.evidence[0] ? ` · line ${f.evidence[0].line_start}` : ""}${f.default_source ? ` · ${f.default_source}` : ""}`
                              : ""
                          }
                        >
                          {isFact(f) ? show(f.value) : ""}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  );
}
