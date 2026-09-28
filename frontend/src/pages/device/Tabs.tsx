import { Info } from "lucide-react";
import type { AuditResult, Entity, Fact } from "../../api/types";
import { Card, ControlBadge, Empty, Mono, cx } from "../../components/ui";
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
    <div className="overflow-hidden rounded-xl border border-line bg-surface">
      <table className="w-full text-sm">
        <thead className="text-left text-xs text-muted">
          <tr className="border-b border-line bg-surface-2">
            <th className="px-4 py-2 font-medium">Control</th>
            <th className="px-3 py-2 font-medium">Title</th>
            <th className="px-3 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Evidence from</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((c) => (
            <tr key={c.control} className="border-b border-line last:border-0">
              <td className="px-4 py-2 font-mono text-xs font-medium">{c.control}</td>
              <td className="px-3 py-2">{c.title}</td>
              <td className="px-3 py-2">
                <ControlBadge status={c.status} />
              </td>
              <td className="px-4 py-2 font-mono text-[11px] text-muted">{c.rules.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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
  if (!rules.length) return <Empty title="No filtering rule in this configuration" />;
  const zoned = rules.some(
    (r) => value(r, "zone_from") !== undefined && value(r, "zone_from") !== null,
  );
  const heads = [
    "#",
    "rule",
    "action",
    ...(zoned ? ["zones"] : []),
    "source",
    "destination",
    "service",
    "enabled",
    "log",
  ];
  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2 rounded-lg bg-surface-2 px-3 py-2 text-xs text-muted">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        Every ACL, firewall policy, security group and network ACL entry, normalised to one model
        and shown in the order the device evaluates it. A dash is a setting the configuration
        doesn't state. Shadowing and redundancy analysis across rules arrives in M4 (TODO
        M4.18–M4.22).
      </div>
      {[...sets].map(([name, list]) => (
        <Card key={name} title={<Mono>{name}</Mono>} bodyClass="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-left text-muted">
                <tr className="border-b border-line">
                  {heads.map((h) => (
                    <th key={h} className="px-3 py-1.5 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="font-mono">
                {list.map((r) => {
                  const action = show(value(r, "action"));
                  const named = value(r, "name");
                  return (
                    <tr key={r.key} className="border-b border-line last:border-0">
                      <td className="px-3 py-1.5 text-faint">{show(value(r, "position"))}</td>
                      <td className="max-w-48 truncate px-3 py-1.5" title={r.key}>
                        {named ? show(named) : r.key}
                      </td>
                      <td
                        className={cx(
                          "px-3 py-1.5 font-semibold",
                          action === "permit"
                            ? "text-pass"
                            : action === "deny"
                              ? "text-fail"
                              : "text-review",
                        )}
                      >
                        {action}
                      </td>
                      {zoned && (
                        <td className="whitespace-nowrap px-3 py-1.5">
                          {show(value(r, "zone_from"))} → {show(value(r, "zone_to"))}
                        </td>
                      )}
                      <td className="max-w-56 truncate px-3 py-1.5">{show(value(r, "src"))}</td>
                      <td className="max-w-56 truncate px-3 py-1.5">{show(value(r, "dst"))}</td>
                      <td className="max-w-56 truncate px-3 py-1.5">{show(value(r, "service"))}</td>
                      <td className="px-3 py-1.5">{show(value(r, "enabled"))}</td>
                      <td className="px-3 py-1.5">{show(value(r, "log"))}</td>
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
    <div className="grid gap-4 lg:grid-cols-2">
      <Card title={`Understood · ${pct(a.understood_pct)}`}>
        <dl className="grid grid-cols-2 gap-y-2 text-sm">
          <dt className="text-muted">Statements</dt>
          <dd className="tabular-nums">{a.statements}</dd>
          <dt className="text-muted">Read by an approved mapping</dt>
          <dd className="tabular-nums">{a.understood}</dd>
          <dt className="text-muted">Not understood yet</dt>
          <dd className="tabular-nums">{a.unmapped}</dd>
          <dt className="text-muted">Near misses</dt>
          <dd className="tabular-nums">{a.near_miss}</dd>
          <dt className="text-muted">Findings needing review</dt>
          <dd className="tabular-nums">{a.review_findings}</dd>
        </dl>
        {result.input.parse_warnings.length > 0 && (
          <div className="mt-4">
            <div className="mb-1 text-xs font-medium text-muted">Reading notes</div>
            <ul className="list-disc space-y-1 pl-5 text-xs">
              {result.input.parse_warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          </div>
        )}
        {result.warnings.length > 0 && (
          <div className="mt-4">
            <div className="mb-1 text-xs font-medium text-review">Warnings</div>
            <ul className="list-disc space-y-1 pl-5 text-xs">
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
            <p className="border-b border-line px-5 py-2 text-xs text-muted">
              Grouped by pattern. These are what the Training Studio (next) teaches: one approved
              mapping covers every device with the same line.
            </p>
            <ul>
              {a.unmapped_patterns.map((p) => (
                <li
                  key={p.pattern_key}
                  className="flex items-center gap-3 border-b border-line px-5 py-2 text-sm last:border-0"
                >
                  <span className="w-10 text-right text-xs text-faint">{p.first_line}</span>
                  <code className="min-w-0 flex-1 truncate font-mono text-[12px]">{p.example}</code>
                  <span className="text-xs tabular-nums text-muted">×{p.count}</span>
                </li>
              ))}
            </ul>
          </>
        )}
      </Card>

      <Card
        title={`Mappings used · ${a.mappings_used.length}`}
        bodyClass="p-0"
        className="lg:col-span-1"
      >
        <ul className="max-h-80 overflow-y-auto">
          {a.mappings_used.map((m) => (
            <li
              key={m.mapping}
              className="flex items-center gap-3 border-b border-line px-5 py-1.5 text-xs last:border-0"
            >
              <code className="min-w-0 flex-1 truncate font-mono">{m.mapping}</code>
              <span className="text-pass">✓ {m.approved_by.join(", ")}</span>
              <span className="w-14 text-right tabular-nums text-muted">{m.facts} facts</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card title={`Vendor defaults relied on · ${a.defaults_used.length}`} bodyClass="p-0">
        {a.defaults_used.length === 0 ? (
          <Empty title="None" />
        ) : (
          <ul className="max-h-80 overflow-y-auto">
            {a.defaults_used.map((d) => (
              <li
                key={d}
                className="border-b border-line px-5 py-1.5 font-mono text-xs last:border-0"
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
              <li key={c.sha256} className="border-b border-line px-5 py-2 text-sm last:border-0">
                <span className="font-medium">{c.file}</span>{" "}
                <span className="text-muted">
                  · {c.command ?? "not recognised"} · {c.used ? "used" : "not used"}
                  {c.note && ` · ${c.note}`}
                </span>
              </li>
            ))}
            {result.inventory.map((i, n) => (
              <li key={n} className="border-b border-line px-5 py-2 text-sm last:border-0">
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
