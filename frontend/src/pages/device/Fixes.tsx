import { Check, ChevronDown, Copy, ShieldCheck, TriangleAlert, Wrench } from "lucide-react";
import { useMemo, useState } from "react";
import type { AuditResult, Fix, FixStep, Proof, Severity } from "../../api/types";
import { Card, Empty, Prose, SEVERITY_LEVEL, SeverityBadge, Tag, cx } from "../../components/ui";
import { pct } from "../../lib/format";

const PROOF: Record<Proof, { label: string; cls: string; hint: string }> = {
  verified: {
    label: "Re-audit verified",
    cls: "bg-pass-soft text-pass",
    hint: "Applied to a copy of this configuration and re-audited: the check no longer fails, and nothing else got worse.",
  },
  not_verified: {
    label: "Didn't hold",
    cls: "bg-fail-soft text-fail",
    hint: "Applied to a copy and re-audited, and it didn't clear the check or made another worse.",
  },
  not_checked: {
    label: "Not re-audited",
    cls: "bg-review-soft text-review",
    hint: "Shown, but not proven on a copy of this configuration.",
  },
};

const STEPS: {
  key: "precheck" | "change" | "verify" | "save" | "rollback";
  label: string;
  what: string;
}[] = [
  { key: "precheck", label: "Pre-check", what: "See what is there now" },
  { key: "change", label: "Change", what: "Make the change" },
  { key: "verify", label: "Verify", what: "Confirm it took" },
  { key: "save", label: "Save", what: "Keep it across a reload" },
  { key: "rollback", label: "Rollback", what: "Undo, if you need to" },
];

/** Every failed check's fix: the commands in five steps, each proven on a copy of this
 * configuration before it is shown as verified. */
export function Fixes({ result, focus }: { result: AuditResult; focus: string | null }) {
  const rem = result.remediation;
  const titles = useMemo(() => new Map(result.rules.map((r) => [r.rule_id, r.title])), [result]);
  const worst = useMemo(() => {
    const out = new Map<string, Severity>();
    for (const f of result.findings) {
      if (f.status !== "FAIL" || !f.severity) continue;
      const seen = out.get(f.rule_id);
      if (!seen || SEVERITY_LEVEL[f.severity] > SEVERITY_LEVEL[seen])
        out.set(f.rule_id, f.severity);
    }
    return out;
  }, [result]);
  const fixes = useMemo(
    () =>
      [...(rem?.fixes ?? [])].sort(
        (a, b) =>
          SEVERITY_LEVEL[worst.get(b.rule_id) ?? "low"] -
            SEVERITY_LEVEL[worst.get(a.rule_id) ?? "low"] || a.rule_id.localeCompare(b.rule_id),
      ),
    [rem, worst],
  );
  const [open, setOpen] = useState<Set<string>>(
    () => new Set(focus ? [focus] : fixes.slice(0, 1).map((f) => f.rule_id)),
  );

  if (!rem)
    return (
      <Card>
        <Empty icon={<ShieldCheck />} title="Nothing to fix">
          No check failed on this device.
        </Empty>
      </Card>
    );

  const verified = rem.fixes.filter((f) => f.proof === "verified").length;
  const c = rem.combined;
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <div className="space-y-6">
      <section className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="grid gap-6 p-5 md:grid-cols-[auto_1fr] md:items-center">
          <div className="flex items-center gap-5">
            <div>
              <div className="text-[12px] font-medium text-muted">
                Failed checks, with every fix applied
              </div>
              <div className="mt-1 flex items-baseline gap-3 font-semibold tracking-[-0.02em]">
                <span className="figure text-[40px] leading-none text-fail">
                  {c?.failed_before ?? "–"}
                </span>
                <span className="text-[22px] text-faint" aria-label="becomes">
                  →
                </span>
                <span
                  className={cx(
                    "figure text-[40px] leading-none",
                    c && c.failed_after === 0 ? "text-pass" : "text-text",
                  )}
                >
                  {c?.failed_after ?? "–"}
                </span>
              </div>
            </div>
            {c?.compliance_after_pct != null && (
              <div className="border-l border-line pl-5">
                <div className="text-[12px] font-medium text-muted">Compliance after</div>
                <div className="figure mt-1 text-[28px] font-semibold leading-none">
                  {pct(c.compliance_after_pct)}
                </div>
              </div>
            )}
          </div>
          <div className="space-y-2 text-[13.5px]">
            <div className="flex flex-wrap items-center gap-2">
              <ProofBadge proof={c?.proof ?? "not_checked"} />
              <span className="text-muted">
                {rem.fixes.length} fix{rem.fixes.length === 1 ? "" : "es"}, {verified} verified
                {c && c.left_for_review.length > 0 && (
                  <>
                    {" · "}
                    <span className="text-review">
                      {c.left_for_review.length} left for a person to review
                    </span>
                  </>
                )}
              </span>
            </div>
            {c && <p className="text-muted">{c.detail}</p>}
          </div>
        </div>
        <div className="flex gap-2.5 border-t border-line bg-surface-2 px-5 py-3 text-[12.5px] text-muted">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-pass" aria-hidden />
          <p>{rem.basis}</p>
        </div>
      </section>

      {rem.unfixed.length > 0 && (
        <Card
          title="Failures without a command recipe"
          description="Listed so none is dropped silently."
        >
          <ul className="space-y-1 font-mono text-[12.5px] text-muted">
            {rem.unfixed.map((u) => (
              <li key={u}>{u}</li>
            ))}
          </ul>
        </Card>
      )}

      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-[14.5px] font-semibold">One fix per failed check</h2>
          <button
            type="button"
            className="text-[12.5px] font-medium text-brass-ink hover:underline"
            onClick={() =>
              setOpen((prev) =>
                prev.size === fixes.length ? new Set() : new Set(fixes.map((f) => f.rule_id)),
              )
            }
          >
            {open.size === fixes.length ? "Collapse all" : "Expand all"}
          </button>
        </div>
        {fixes.map((fix) => (
          <FixCard
            key={fix.rule_id}
            fix={fix}
            title={titles.get(fix.rule_id) ?? fix.rule_id}
            severity={worst.get(fix.rule_id) ?? null}
            open={open.has(fix.rule_id)}
            onToggle={() => toggle(fix.rule_id)}
          />
        ))}
      </div>
    </div>
  );
}

function ProofBadge({ proof }: { proof: Proof }) {
  const p = PROOF[proof];
  return (
    <span
      title={p.hint}
      className={cx(
        "inline-flex h-6 items-center gap-1 rounded-md px-2 text-[12px] font-semibold [&>svg]:size-3.5 [&>svg]:stroke-[2.5]",
        p.cls,
      )}
    >
      {proof === "verified" ? <ShieldCheck /> : <TriangleAlert />}
      {p.label}
    </span>
  );
}

function FixCard({
  fix,
  title,
  severity,
  open,
  onToggle,
}: {
  fix: Fix;
  title: string;
  severity: Severity | null;
  open: boolean;
  onToggle: () => void;
}) {
  const objects = fix.entity_ids.filter((e) => !e.startsWith("Device["));
  return (
    <section
      id={`fix-${fix.rule_id}`}
      className="overflow-hidden rounded-xl border border-line bg-surface"
    >
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="flex w-full items-center gap-4 px-5 py-3.5 text-left hover:bg-surface-2"
      >
        <SeverityBadge severity={severity} />
        <span className="min-w-0 flex-1">
          <span className="block font-medium">{title}</span>
          <span className="mt-0.5 flex flex-wrap items-center gap-x-2 text-[12px] text-faint">
            <span className="font-mono">{fix.rule_id}</span>
            {objects.length > 0 && (
              <span>
                · {objects.length} object{objects.length === 1 ? "" : "s"}
              </span>
            )}
            {fix.placeholders.length > 0 && (
              <span>
                · {fix.placeholders.length} value{fix.placeholders.length === 1 ? "" : "s"} to fill
                in
              </span>
            )}
          </span>
        </span>
        <ProofBadge proof={fix.proof} />
        <ChevronDown
          className={cx("size-4 shrink-0 text-faint transition-transform", open && "rotate-180")}
          aria-hidden
        />
      </button>
      {open && (
        <div className="space-y-4 border-t border-line px-5 pb-5 pt-4">
          <p className="text-[13px] text-muted">{fix.proof_detail}</p>
          {objects.length > 0 && (
            <div className="flex flex-wrap items-center gap-1">
              <span className="mr-1 text-[12px] font-medium text-muted">Fixes</span>
              {objects.slice(0, 8).map((e) => (
                <Tag key={e}>{e}</Tag>
              ))}
              {objects.length > 8 && (
                <span className="text-[12px] text-faint">and {objects.length - 8} more</span>
              )}
            </div>
          )}
          {fix.note && (
            <div className="flex gap-2.5 rounded-lg bg-brass-soft px-3.5 py-2.5 text-[13px] text-text">
              <Wrench className="mt-0.5 size-4 shrink-0 text-brass-ink" aria-hidden />
              <p>
                <Prose text={fix.note} />
              </p>
            </div>
          )}
          {fix.placeholders.length > 0 && (
            <div>
              <div className="mb-1.5 text-[12px] font-medium text-muted">
                Fill in before you apply
              </div>
              <dl className="grid gap-x-6 gap-y-1 text-[13px] sm:grid-cols-[max-content_1fr]">
                {fix.placeholders.map((p) => (
                  <div key={p.name} className="contents">
                    <dt className="font-mono text-[12.5px] font-medium text-brass-ink">{`<${p.name}>`}</dt>
                    <dd className="text-muted">{p.means}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
          <ol className="relative space-y-3">
            {STEPS.map((s, i) => {
              const step = fix[s.key];
              if (!step) return null;
              return <StepBlock key={s.key} n={i + 1} label={s.label} what={s.what} step={step} />;
            })}
          </ol>
          <p className="text-[11.5px] text-faint">
            Recipe {fix.recipe} ({fix.source})
          </p>
        </div>
      )}
    </section>
  );
}

function StepBlock({
  n,
  label,
  what,
  step,
}: {
  n: number;
  label: string;
  what: string;
  step: FixStep;
}) {
  const [copied, setCopied] = useState(false);
  const text = step.commands.join("\n");
  const copy = () => {
    navigator.clipboard?.writeText(text).then(
      () => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      },
      () => setCopied(false),
    );
  };
  return (
    <li className="grid grid-cols-[1.75rem_1fr] gap-3">
      <span className="figure mt-0.5 grid size-7 place-items-center rounded-full border border-line-strong bg-surface-2 text-[12px] font-semibold text-muted">
        {n}
      </span>
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-2">
          <span className="text-[13.5px] font-semibold">{label}</span>
          <span className="text-[12.5px] text-faint">{what}</span>
        </div>
        {step.commands.length > 0 && (
          <div className="group relative mt-1.5 overflow-hidden rounded-lg bg-basalt ring-1 ring-basalt-line">
            <pre className="overflow-x-auto px-4 py-3 font-mono text-[12.5px] leading-6 text-[#e6e1d6]">
              {text}
            </pre>
            <button
              type="button"
              onClick={copy}
              className="absolute right-2 top-2 inline-flex items-center gap-1 rounded-md bg-basalt-2 px-2 py-1 text-[11.5px] text-on-basalt opacity-0 ring-1 ring-basalt-line transition group-hover:opacity-100 focus:opacity-100"
              aria-label={`Copy the ${label.toLowerCase()} commands`}
            >
              {copied ? <Check className="size-3.5 text-pass" /> : <Copy className="size-3.5" />}
              {copied ? "Copied" : "Copy"}
            </button>
          </div>
        )}
        {step.note && (
          <p className="mt-1.5 text-[12.5px] text-muted">
            <Prose text={step.note} />
          </p>
        )}
      </div>
    </li>
  );
}
