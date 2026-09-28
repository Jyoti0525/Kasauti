import { Info } from "lucide-react";
import type { AuditResult, Entity, Fact } from "../../api/types";
import { Meter } from "../../components/charts";
import { Card, ControlBadge, Empty, Notice, Tag, cx } from "../../components/ui";
import { pct, show } from "../../lib/format";

/** The NIST SP 800-53 control matrix: each control the rules give evidence for. */
export function Controls({ result }: { result: AuditResult }) {
  const order = {
    "not satisfied": 0,
    "partially satisfied": 1,
    undetermined: 2,
    satisfied: 3,
    "not applicable": 4,
  };
  const rows = [...result.controls].sort(
    (a, b) => order[a.status] - order[b.status] || a.control.localeCompare(b.control),
  );
  return (
    <Card bodyClass="p-0">
      <table className="data">
        <thead>
          <tr>
            <th className="w-28">Control</th>
            <th>Title</th>
            <th className="w-52">Status</th>
            <th>Evidence from</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.control}>
              <td className="font-mono text-[13px] font-medium">{c.control}</td>
              <td>{c.title}</td>
              <td>
                <ControlBadge status={c.status} />
              </td>
              <td>
                <span className="flex flex-wrap gap-1">
                  {c.rules.map((r) => (
                    <Tag key={r}>{r}</Tag>
                  ))}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function value(e: Entity, attr: string): unknown {
  const f = e[attr] as Fact | undefined;
  return f && typeof f === "object" && "value" in f ? f.value : undefined;
}

/** Filtering rules by ruleset, in evaluation order (by position where the vendor numbers them,
 * else as the configuration lists them). */
export function Policy({ result }: { result: AuditResult }) {
  const rules = result.sbm.entities.filter((e) => e.type === "FilterRule");
  const sets = new Map<string, Entity[]>();
  for (const r of rules) {
    const name = show(value(r, "ruleset"));
    sets.set(name, [...(sets.get(name) ?? []), r]);
  }
  for (const list of sets.values()) {
    const pos = (e: Entity) => {
      const p = value(e, "position");
      return typeof p === "number" ? p : Number.MAX_SAFE_INTEGER;
    };
    list.sort((a, b) => pos(a) - pos(b));
  }
  if (!rules.length)
    return (
      <Card>
        <Empty title="No filtering rule in this configuration" />
      </Card>
    );
  const zoned = rules.some(
    (r) => value(r, "zone_from") !== undefined && value(r, "zone_from") !== null,
  );
  const heads = [
    "#",
    "Rule",
    "Action",
    ...(zoned ? ["Zones"] : []),
    "Source",
    "Destination",
    "Service",
    "Enabled",
    "Log",
  ];
  return (
    <div className="space-y-5">
      <Notice icon={<Info />}>
        Every ACL, firewall policy, security group and network ACL entry, normalised to one model
        and shown in the order the device evaluates it. A dash is a setting the configuration
        doesn't state. Analysis of shadowed and redundant rules comes in the next release.
      </Notice>
      {[...sets].map(([name, list]) => (
        <Card
          key={name}
          title={
            <span className="flex items-center gap-2">
              Ruleset <Tag className="text-[12.5px] text-text">{name}</Tag>
            </span>
          }
          action={
            <span className="text-[12.5px] text-muted">
              {list.length} entr{list.length === 1 ? "y" : "ies"}
            </span>
          }
          bodyClass="p-0"
        >
          <div className="overflow-x-auto">
            <table className="data compact">
              <thead>
                <tr>
                  {heads.map((h) => (
                    <th key={h}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="font-mono text-[12.5px]">
                {list.map((r) => {
                  const action = show(value(r, "action"));
                  const named = value(r, "name");
                  return (
                    <tr key={r.key}>
                      <td className="text-faint">{show(value(r, "position"))}</td>
                      <td className="max-w-48 truncate" title={r.key}>
                        {named ? show(named) : r.key}
                      </td>
                      <td>
                        <span
                          className={cx(
                            "rounded px-1.5 py-0.5 font-sans text-[12px] font-semibold",
                            action === "permit"
                              ? "bg-surface-3 text-text"
                              : action === "deny"
                                ? "bg-text text-surface"
                                : "bg-review-soft text-review",
                          )}
                        >
                          {action}
                        </span>
                      </td>
                      {zoned && (
                        <td className="whitespace-nowrap">
                          {show(value(r, "zone_from"))} → {show(value(r, "zone_to"))}
                        </td>
                      )}
                      <td className="max-w-56 truncate">{show(value(r, "src"))}</td>
                      <td className="max-w-56 truncate">{show(value(r, "dst"))}</td>
                      <td className="max-w-56 truncate">{show(value(r, "service"))}</td>
                      <td>{show(value(r, "enabled"))}</td>
                      <td>{show(value(r, "log"))}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      ))}
    </div>
  );
}

/** How much of the file Kasauti understood, and what it didn't (the Training Studio's queue). */
export function Coverage({ result }: { result: AuditResult }) {
  const a = result.assurance;
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Card
        title="How much was understood"
        action={<span className="figure text-[19px] font-semibold">{pct(a.understood_pct)}</span>}
      >
        <Meter value={a.understood_pct} tone="data" className="mb-5" />
        <dl className="grid grid-cols-[1fr_auto] gap-y-2.5 text-[13.5px]">
          <dt className="text-muted">Statements in the file</dt>
          <dd className="figure font-medium">{a.statements}</dd>
          <dt className="text-muted">Read by an approved mapping</dt>
          <dd className="figure font-medium">{a.understood}</dd>
          <dt className="text-muted">Not understood yet</dt>
          <dd className="figure font-medium">{a.unmapped}</dd>
          <dt className="text-muted">Near misses</dt>
          <dd className="figure font-medium">{a.near_miss}</dd>
          <dt className="text-muted">Findings waiting for review</dt>
          <dd className="figure font-medium">{a.review_findings}</dd>
        </dl>
        {result.input.parse_warnings.length > 0 && (
          <div className="mt-5">
            <div className="mb-1.5 text-[12.5px] font-medium text-muted">Reading notes</div>
            <ul className="list-disc space-y-1 pl-5 text-[13px]">
              {result.input.parse_warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </div>
        )}
        {result.warnings.length > 0 && (
          <div className="mt-5">
            <div className="mb-1.5 text-[12.5px] font-medium text-review">Warnings</div>
            <ul className="list-disc space-y-1 pl-5 text-[13px]">
              {result.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </div>
        )}
      </Card>

      <Card title="Not understood yet" bodyClass="p-0">
        {a.unmapped_patterns.length === 0 ? (
          <Empty title="Every statement was read" />
        ) : (
          <>
            <p className="border-b border-line px-5 pb-3 text-[13px] text-muted">
              Grouped by pattern. These are what the Training Studio will teach: one approved
              mapping then covers every device with the same line.
            </p>
            <ul>
              {a.unmapped_patterns.map((p) => (
                <li
                  key={p.pattern_key}
                  className="flex items-center gap-3 border-b border-line px-5 py-2 text-sm last:border-0"
                >
                  <span className="figure w-10 text-right text-[12px] text-faint">
                    {p.first_line}
                  </span>
                  <code className="min-w-0 flex-1 truncate font-mono text-[12.5px]">
                    {p.example}
                  </code>
                  <span className="figure text-[12px] text-muted">×{p.count}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>

      <Card title="Mappings used" action={<Count n={a.mappings_used.length} />} bodyClass="p-0">
        <ul className="max-h-80 overflow-y-auto">
          {a.mappings_used.map((m) => (
            <li
              key={m.mapping}
              className="flex items-center gap-3 border-b border-line px-5 py-2 text-[12.5px] last:border-0"
            >
              <code className="min-w-0 flex-1 truncate font-mono">{m.mapping}</code>
              <span className="text-pass">approved by {m.approved_by.join(", ")}</span>
              <span className="figure w-16 text-right text-muted">{m.facts} facts</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card
        title="Vendor defaults relied on"
        action={<Count n={a.defaults_used.length} />}
        bodyClass="p-0"
      >
        {a.defaults_used.length === 0 ? (
          <Empty title="None" />
        ) : (
          <ul className="max-h-80 overflow-y-auto">
            {a.defaults_used.map((d) => (
              <li
                key={d}
                className="border-b border-line px-5 py-2 font-mono text-[12.5px] last:border-0"
              >
                {d}
              </li>
            ))}
          </ul>
        )}
      </Card>

      {(result.companions.length > 0 || result.inventory.length > 0) && (
        <Card title="Command outputs and inventory" className="lg:col-span-2" bodyClass="p-0">
          <ul>
            {result.companions.map((c) => (
              <li
                key={c.sha256}
                className="border-b border-line px-5 py-2.5 text-[13.5px] last:border-0"
              >
                <span className="font-medium">{c.file}</span>{" "}
                <span className="text-muted">
                  · {c.command ?? "not recognised"} · {c.used ? "used" : "not used"}
                  {c.note && ` · ${c.note}`}
                </span>
              </li>
            ))}
            {result.inventory.map((i, n) => (
              <li key={n} className="border-b border-line px-5 py-2.5 text-[13.5px] last:border-0">
                <span className="font-medium">{i.name}</span>{" "}
                <span className="text-muted">
                  {i.part && `· ${i.part} `}· serial <span className="font-mono">{i.serial}</span> ·{" "}
                  {i.source}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

function Count({ n }: { n: number }) {
  return <span className="figure rounded-full bg-surface-3 px-2 text-[12px] text-muted">{n}</span>;
}
