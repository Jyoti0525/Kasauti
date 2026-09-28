import { useMemo, useState } from "react";
import type { AuditResult, Entity, Fact, FactState } from "../../api/types";
import { Mono, cx } from "../../components/ui";
import { show } from "../../lib/format";

const STATE: Record<FactState, string> = {
  explicit: "text-text",
  vendor_default: "text-gold",
  absent: "text-faint",
  unknown: "text-review",
};

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

  return (
    <div className="grid gap-4 lg:grid-cols-[14rem_1fr]">
      <nav className="space-y-0.5" aria-label="Entity types">
        {groups.map(([t, list]) => (
          <button
            key={t}
            type="button"
            onClick={() => setType(t)}
            className={cx(
              "flex w-full items-center justify-between rounded-lg px-3 py-1.5 text-left text-sm",
              t === type ? "bg-surface-2 font-medium" : "text-muted hover:bg-surface-2",
            )}
          >
            {t}
            <span className="text-xs tabular-nums text-faint">{list.length}</span>
          </button>
        ))}
        <button
          type="button"
          onClick={() => setType("__derived")}
          className={cx(
            "mt-3 flex w-full items-center justify-between rounded-lg px-3 py-1.5 text-left text-sm",
            type === "__derived" ? "bg-surface-2 font-medium" : "text-muted hover:bg-surface-2",
          )}
        >
          Derived facts
          <span className="text-xs tabular-nums text-faint">
            {Object.keys(result.sbm.derived).length}
          </span>
        </button>
      </nav>

      <div className="min-w-0">
        <div className="mb-2 flex flex-wrap gap-3 text-[11px] text-muted">
          <span>
            Values: <b className="font-medium text-text">explicit</b> (configured)
          </span>
          <span className="text-gold">vendor default (documented, cited)</span>
          <span className="text-faint">absent</span>
          <span className="text-review">unknown (REVIEW, never guessed)</span>
        </div>
        {type === "__derived" ? (
          <div className="overflow-x-auto rounded-xl border border-line bg-surface">
            <table className="w-full text-sm">
              <tbody>
                {Object.entries(result.sbm.derived).map(([name, fact]) => (
                  <tr key={name} className="border-b border-line last:border-0">
                    <td className="px-4 py-2 font-mono text-xs">{name}</td>
                    <td className={cx("px-4 py-2 font-mono text-xs", STATE[fact.state])}>
                      {show(fact.value)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-line bg-surface">
            <table className="w-full text-xs">
              <thead className="text-left text-muted">
                <tr className="border-b border-line bg-surface-2">
                  <th className="sticky left-0 bg-surface-2 px-3 py-2 font-medium">key</th>
                  {attributes.map((a) => (
                    <th key={a} className="whitespace-nowrap px-3 py-2 font-medium">
                      {a}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entities.map((e) => (
                  <tr key={e.key} className="border-b border-line last:border-0">
                    <td className="sticky left-0 bg-surface px-3 py-1.5">
                      <Mono>{e.key}</Mono>
                    </td>
                    {attributes.map((a) => {
                      const f = e[a];
                      return (
                        <td
                          key={a}
                          className={cx(
                            "max-w-64 truncate whitespace-nowrap px-3 py-1.5 font-mono",
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
          </div>
        )}
      </div>
    </div>
  );
}
