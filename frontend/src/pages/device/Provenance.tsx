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
import { Mono, Prose, SeverityBadge, StatusBadge, Tag, cx } from "../../components/ui";

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
          <span className="mx-1 h-4 w-px bg-line" aria-hidden />
          <Mono className="text-muted">{finding.rule_id}</Mono>
          <span className="text-faint">on</span>
          <Tag>{finding.entity_id}</Tag>
        </span>
      }
    >
      <ol className="relative ml-3 space-y-7 border-l-2 border-dashed border-line-strong pl-8">
        <Step icon={<FileCode2 />} title="Configuration lines" n={1}>
          {finding.evidence.length === 0 ? (
            <p className="text-sm text-muted">
              No line: the verdict rests on what the configuration <i>doesn't</i> say
              {finding.defaults_used.length ? ", and on the vendor defaults below" : ""}. An absent
              setting is judged by the rule's policy for absence, never assumed safe.
            </p>
          ) : (
            <div className="space-y-3">
              {byFile(finding.evidence).map(([file, lines]) => (
                <div
                  key={file}
                  className="overflow-hidden rounded-lg bg-basalt ring-1 ring-basalt-line"
                >
                  <div className="flex items-center justify-between border-b border-basalt-line px-4 py-2 text-[12px] text-on-basalt">
                    <span className="font-mono">{file}</span>
                    <span>secrets masked</span>
                  </div>
                  <div className="overflow-x-auto py-2 font-mono text-[13px] leading-6 text-[#f1ede2]">
                    {lines.map((e, i) => (
                      <div key={i} className="flex">
                        <span className="w-12 shrink-0 select-none pr-3 text-right text-on-basalt/50">
                          {e.line_start}
                        </span>
                        <span className="whitespace-pre pr-4">{e.raw}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
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
                      <div className="mt-1.5 rounded-md border border-line bg-surface-2 px-2.5 py-1.5 font-mono text-[12.5px] text-muted">
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
                  <Mono className="rounded-md border border-line bg-surface-2 px-2 py-1">{a}</Mono>
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
              <p>
                <Prose text={rule.intent} />
              </p>
              <div className="rounded-md border border-line bg-surface-2 px-2.5 py-2 font-mono text-[12.5px] text-text">
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
            Vendor-specific remediation, with pre-checks, a rollback plan and a re-audit of the
            fixed configuration, comes in the next release. Kasauti never pushes a change to a
            device.
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
        className={cx(
          "absolute -left-[47px] -top-1 flex size-7 items-center justify-center rounded-full border [&>svg]:size-3.5",
          muted
            ? "border-line bg-surface-2 text-faint"
            : "border-brass/40 bg-brass-soft text-brass-ink",
        )}
      >
        {icon}
      </span>
      <div className="mb-2.5 flex items-baseline gap-2">
        <span className="figure text-[12px] font-medium text-faint">0{n}</span>
        <span className={cx("text-[14px] font-semibold", muted && "text-muted")}>{title}</span>
      </div>
      {children}
    </li>
  );
}

/** Evidence grouped by file, each file's lines in order. */
function byFile(evidence: Evidence[]): [string, Evidence[]][] {
  const files = new Map<string, Evidence[]>();
  for (const e of evidence) files.set(e.file, [...(files.get(e.file) ?? []), e]);
  for (const lines of files.values()) lines.sort((a, b) => a.line_start - b.line_start);
  return [...files];
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
