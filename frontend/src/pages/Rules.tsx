import { CheckCircle2, ExternalLink, Search, XCircle } from "lucide-react";
import { useState } from "react";
import { useKb } from "../api/hooks";
import type { RuleOut } from "../api/types";
import { Card, Chip, ErrorBox, Loading, Mono, PageHeader, SeverityBadge } from "../components/ui";
import { titleCase } from "../lib/format";

/** Frameworks and rules (TODO M2.83): each rule, the controls it gives evidence for, and the
 * fixtures that prove it passes a hardened configuration and fails a weak one. */
export function Rules() {
  const kb = useKb();
  const [domain, setDomain] = useState("");
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  if (kb.isPending) return <Loading what="Loading rules" />;
  if (kb.isError) return <ErrorBox error={kb.error} />;
  const { rules, frameworks, control_titles } = kb.data;
  const domains = [...new Set(rules.map((r) => r.domain))].sort();
  const q = query.toLowerCase();
  const shown = rules.filter(
    (r) =>
      (!domain || r.domain === domain) &&
      (!q ||
        `${r.id} ${r.title} ${r.intent} ${Object.values(r.controls).flat().join(" ")}`
          .toLowerCase()
          .includes(q)),
  );

  return (
    <>
      <PageHeader
        title="Frameworks & rules"
        subtitle="Every rule is written once against the vendor-neutral model, so it judges every vendor the same way."
      />
      <div className="mb-6 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {frameworks.map((f) => (
          <Card key={f.id}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="font-semibold">{f.title}</div>
                <div className="mt-0.5 text-xs text-muted">
                  Release {f.version} · {f.controls} controls · {f.licence}
                </div>
              </div>
              <span className="rounded bg-pass-soft px-1.5 py-0.5 text-[11px] font-semibold text-pass">
                enabled
              </span>
            </div>
            <a
              href={f.source_url}
              target="_blank"
              rel="noreferrer noopener"
              className="mt-3 inline-flex items-center gap-1 text-xs text-muted hover:text-text"
            >
              Imported from the official catalogue on {f.retrieved}{" "}
              <ExternalLink className="size-3" />
            </a>
          </Card>
        ))}
        <Card className="border-dashed">
          <div className="font-semibold text-muted">CIS · DISA STIG · ISO 27001</div>
          <p className="mt-1 text-xs text-muted">
            Arrive through the crosswalk hub from the NIST anchors (TODO M3), each mapping reviewed.
          </p>
        </Card>
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Chip active={!domain} onClick={() => setDomain("")}>
          All · {rules.length}
        </Chip>
        {domains.map((d) => (
          <Chip key={d} active={domain === d} onClick={() => setDomain(domain === d ? "" : d)}>
            {titleCase(d)} · {rules.filter((r) => r.domain === d).length}
          </Chip>
        ))}
        <label className="ml-auto flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2 py-1">
          <Search className="size-3.5 text-faint" aria-hidden />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search rules or controls…"
            className="w-56 bg-transparent text-sm outline-none"
          />
        </label>
      </div>

      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        {shown.map((r) => (
          <RuleRow
            key={r.id}
            rule={r}
            open={open === r.id}
            onToggle={() => setOpen(open === r.id ? null : r.id)}
            titles={control_titles}
          />
        ))}
      </div>
    </>
  );
}

function RuleRow({
  rule: r,
  open,
  onToggle,
  titles,
}: {
  rule: RuleOut;
  open: boolean;
  onToggle: () => void;
  titles: Record<string, string>;
}) {
  const nist = r.controls.nist_800_53r5 ?? [];
  return (
    <div className="border-b border-line last:border-0">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="grid w-full grid-cols-[1fr_6rem_12rem] items-center gap-3 px-5 py-3 text-left hover:bg-surface-2"
      >
        <div className="min-w-0">
          <div className="font-medium">{r.title}</div>
          <div className="font-mono text-[11px] text-faint">{r.id}</div>
        </div>
        <SeverityBadge severity={r.severity} />
        <div className="truncate font-mono text-xs text-muted">
          {nist.length ? nist.join(", ") : r.hardening_best_practice ? "best practice" : "–"}
        </div>
      </button>
      {open && (
        <div className="grid gap-4 bg-surface-2/60 px-5 py-4 text-sm lg:grid-cols-2">
          <div>
            <p>{r.intent}</p>
            <div className="mt-3 rounded-md border border-line bg-surface px-3 py-2 font-mono text-[12px]">
              <div>
                <span className="text-faint">for each </span>
                {r.for_each}
              </div>
              <div>
                <span className="text-faint">assert </span>
                {r.assertion}
              </div>
            </div>
            <div className="mt-3 text-xs text-muted">
              Applies to: {r.applies_to.map(titleCase).join(", ")}
            </div>
          </div>
          <div className="space-y-3">
            <div>
              <div className="mb-1 text-xs font-medium text-muted">NIST SP 800-53 Rev. 5</div>
              <ul className="space-y-0.5">
                {nist.map((c) => (
                  <li key={c}>
                    <Mono className="font-medium">{c}</Mono>{" "}
                    <span className="text-muted">{titles[c]}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="mb-1 text-xs font-medium text-muted">
                Fixtures (proved in CI on every change)
              </div>
              <ul className="space-y-0.5 font-mono text-[12px]">
                {r.fixtures_pass.map((f) => (
                  <li key={f} className="flex items-center gap-1.5">
                    <CheckCircle2 className="size-3.5 text-pass" aria-label="passes" /> {f}
                  </li>
                ))}
                {r.fixtures_fail.map((f) => (
                  <li key={f} className="flex items-center gap-1.5">
                    <XCircle className="size-3.5 text-fail" aria-label="fails" /> {f}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
