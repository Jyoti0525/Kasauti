// The provenance drawer (TODO M2.80, PLAN §3.1 principle 1): for one finding, every step from
// the raw configuration line to the framework control, so no verdict has to be taken on trust.

import {
  BadgeCheck,
  FileCode2,
  GitBranch,
  Hammer,
  Scale,
  ShieldCheck,
  Workflow,
} from "lucide-react";
import type { ReactNode } from "react";
import { useKb, useVendor } from "../../api/hooks";
import type { AuditResult, Evidence, Finding } from "../../api/types";
import { Drawer } from "../../components/Drawer";
import { Mono, SeverityBadge, StatusBadge } from "../../components/ui";

export function Provenance({
  finding,
  result,
  onClose,
}: {
  finding: Finding | null;
  result: AuditResult;
  onClose: () => void;
}) {
  const kb = useKb();
  const vendor = useVendor(result.detection.pack_id);
  if (!finding) return null;
  const rule = kb.data?.rules.find((r) => r.id === finding.rule_id);
  const ruleResult = result.rules.find((r) => r.rule_id === finding.rule_id);
  const title = rule?.title ?? ruleResult?.title ?? finding.rule_id;
  const controls = ruleResult?.nist_800_53r5 ?? rule?.controls.nist_800_53r5 ?? [];
  const mapping = (id: string | null) => vendor.data?.mappings.find((m) => m.id === id);
  const defaults = finding.defaults_used.map((ref) => {
    const id = ref.split("#")[1];
    return { ref, entry: vendor.data?.defaults.find((d) => d.id === id) };
  });

  return (
    <Drawer
      open
      onClose={onClose}
      title={title}
      subtitle={
        <span className="flex flex-wrap items-center gap-2">
          <StatusBadge status={finding.status} />
          <SeverityBadge severity={finding.severity} />
          <Mono className="text-faint">{finding.rule_id}</Mono>
          <span className="text-faint">on</span>
          <Mono>{finding.entity_id}</Mono>
        </span>
      }
    >
      <ol className="relative space-y-6 border-l border-line pl-6">
        <Step icon={<FileCode2 />} title="Raw configuration line" n={1}>
          {finding.evidence.length === 0 ? (
            <p className="text-sm text-muted">
              No line: the verdict rests on what the configuration <i>doesn't</i> say
              {finding.defaults_used.length ? ", and on the vendor defaults below" : ""}. An absent
              setting is judged by the rule's policy for absence, never assumed safe.
            </p>
          ) : (
            <ul className="space-y-2">
              {finding.evidence.map((e, i) => (
                <li key={i} className="overflow-hidden rounded-lg border border-line">
                  <div className="flex items-center justify-between bg-surface-2 px-3 py-1 text-[11px] text-muted">
                    <span className="font-mono">
                      {e.file}:{e.line_start}
                      {e.line_end !== e.line_start && `–${e.line_end}`}
                    </span>
                    <span>secrets masked</span>
                  </div>
                  <pre className="overflow-x-auto px-3 py-2 font-mono text-[12.5px]">{e.raw}</pre>
                </li>
              ))}
            </ul>
          )}
        </Step>

        <Step icon={<GitBranch />} title="Mapping that read it" n={2}>
          {finding.evidence.length === 0 ? (
            <p className="text-sm text-muted">–</p>
          ) : (
            <ul className="space-y-3">
              {firstPerMapping(finding.evidence).map((e) => {
                const key = `${e.mapping_id}@${e.mapping_version}`;
                const m = mapping(e.mapping_id);
                return (
                  <li key={key} className="text-sm">
                    <Mono className="font-medium">{key}</Mono>
                    {m && (
                      <div className="mt-1 rounded-md bg-surface-2 px-2 py-1 font-mono text-[12px] text-muted">
                        {m.context.length > 0 && (
                          <span className="text-faint">{m.context.join(" › ")} › </span>
                        )}
                        {m.match}
                      </div>
                    )}
                    <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
                      <span className="inline-flex items-center gap-1 text-pass">
                        <BadgeCheck className="size-3.5" /> approved by{" "}
                        {e.approved_by.join(", ") || "–"}
                      </span>
                      {m && <span>proposed by {m.proposed_by}</span>}
                      {m && m.signals.length > 0 && <span>signals: {m.signals.join(", ")}</span>}
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Step>

        <Step icon={<Workflow />} title="Fact in the security model" n={3}>
          {finding.actual.length ? (
            <ul className="space-y-1">
              {finding.actual.map((a, i) => (
                <li key={i}>
                  <Mono className="rounded bg-surface-2 px-1.5 py-0.5">{a}</Mono>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted">–</p>
          )}
          {defaults.length > 0 && (
            <div className="mt-3">
              <div className="mb-1 text-xs font-medium text-muted">Vendor defaults relied on</div>
              <ul className="space-y-2">
                {defaults.map(({ ref, entry }) => (
                  <li key={ref} className="rounded-md border border-line p-2 text-xs">
                    <Mono>{ref}</Mono>
                    {entry && (
                      <div className="mt-1 text-muted">
                        {entry.source.replace("_", " ")}:{" "}
                        <span className="break-all">{entry.reference}</span>
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Step>

        <Step icon={<Scale />} title="Rule" n={4}>
          <p className="text-sm">{finding.reason}</p>
          {rule && (
            <div className="mt-2 space-y-1 text-xs text-muted">
              <p>{rule.intent}</p>
              <div className="rounded-md bg-surface-2 px-2 py-1.5 font-mono text-[12px]">
                <div>
                  <span className="text-faint">for each </span>
                  {rule.for_each}
                </div>
                <div>
                  <span className="text-faint">assert </span>
                  {rule.assertion}
                </div>
              </div>
              {finding.severity_reason && <p>Severity: {finding.severity_reason}</p>}
            </div>
          )}
        </Step>

        <Step icon={<ShieldCheck />} title="Framework controls" n={5}>
          {controls.length ? (
            <ul className="space-y-1 text-sm">
              {controls.map((c) => (
                <li key={c}>
                  <Mono className="font-medium">{c}</Mono>{" "}
                  <span className="text-muted">{kb.data?.control_titles[c] ?? ""}</span>
                  <span className="ml-1 text-xs text-faint">· NIST SP 800-53 Rev. 5</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-muted">
              A hardening best practice with no benchmark control.
            </p>
          )}
        </Step>

        <Step icon={<Hammer />} title="Fix and verification" n={6} muted>
          <p className="text-sm text-muted">
            Vendor-specific remediation with pre-checks, rollback and a re-audit of the fixed model
            arrives in M4 (TODO M4.16). Kasauti never pushes a change to a device.
          </p>
        </Step>
      </ol>
    </Drawer>
  );
}

function Step({
  icon,
  title,
  n,
  children,
  muted,
}: {
  icon: ReactNode;
  title: string;
  n: number;
  children: ReactNode;
  muted?: boolean;
}) {
  return (
    <li className="relative">
      <span
        className={`absolute -left-[37px] flex size-6 items-center justify-center rounded-full border border-line bg-surface [&>svg]:size-3.5 ${muted ? "text-faint" : "text-gold"}`}
      >
        {icon}
      </span>
      <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
        {n} · {title}
      </div>
      {children}
    </li>
  );
}

/** The first evidence item of each mapping (id and version) among `evidence`. */
function firstPerMapping(evidence: Evidence[]): Evidence[] {
  const seen = new Map<string, Evidence>();
  for (const e of evidence) {
    const key = `${e.mapping_id}@${e.mapping_version}`;
    if (!seen.has(key)) seen.set(key, e);
  }
  return [...seen.values()];
}
