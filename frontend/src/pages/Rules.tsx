import { Check, ChevronDown, ExternalLink, X } from "lucide-react";
import { useState } from "react";
import { useKb } from "../api/hooks";
import type { RuleOut } from "../api/types";
import {
  Card,
  Chip,
  ErrorBox,
  Loading,
  Mono,
  PageHeader,
  Prose,
  SearchBox,
  SeverityBadge,
  Tag,
  cx,
} from "../components/ui";
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
        title="Rules and frameworks"
        subtitle="Each rule is written once, against the vendor-neutral model, so it judges every vendor the same way, and each cites the framework controls it gives evidence for."
      />
      <div className="mb-8 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {frameworks.map((f) => (
          <Card key={f.id}>
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="text-[15px] font-semibold">{f.title}</div>
                <div className="mt-1 text-[12.5px] text-muted">
                  Release {f.version} · {f.controls} controls · {f.licence}
                </div>
              </div>
              <span className="inline-flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md bg-pass-soft px-2 py-0.5 text-[12px] font-semibold text-pass">
                <Check className="size-3.5" strokeWidth={2.75} /> In use
              </span>
            </div>
            <a
              href={f.source_url}
              target="_blank"
              rel="noreferrer noopener"
              className="mt-4 inline-flex items-center gap-1 text-[12.5px] text-muted hover:text-text"
            >
              Imported from the official catalogue, {f.retrieved}
              <ExternalLink className="size-3.5" />
            </a>
          </Card>
        ))}
        <div className="rounded-xl border border-dashed border-line-strong p-5">
          <div className="text-[15px] font-semibold text-muted">
            CIS Benchmarks · DISA STIG · ISO/IEC 27001
          </div>
          <p className="mt-1 text-[12.5px] leading-relaxed text-muted">
            Coming through a reviewed crosswalk from the NIST SP 800-53 controls each rule already
            cites, one mapping at a time.
          </p>
        </div>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Chip active={!domain} onClick={() => setDomain("")}>
          All <span className="figure opacity-70">{rules.length}</span>
        </Chip>
        {domains.map((d) => (
          <Chip key={d} active={domain === d} onClick={() => setDomain(domain === d ? "" : d)}>
            {titleCase(d)}{" "}
            <span className="figure opacity-70">{rules.filter((r) => r.domain === d).length}</span>
          </Chip>
        ))}
        <SearchBox
          value={query}
          onChange={setQuery}
          placeholder="Search rules or controls"
          className="ml-auto w-72"
        />
      </div>

      <Card bodyClass="p-0">
        <div className="grid grid-cols-[1fr_7.5rem_14rem_1.5rem] gap-4 border-b border-line bg-surface-2 px-5 py-2.5 text-[12px] font-medium text-muted">
          <span>Rule</span>
          <span>Severity</span>
          <span>NIST SP 800-53</span>
          <span />
        </div>
        {shown.map((r) => (
          <RuleRow
            key={r.id}
            rule={r}
            open={open === r.id}
            onToggle={() => setOpen(open === r.id ? null : r.id)}
            titles={control_titles}
          />
        ))}
      </Card>
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
        className={cx(
          "grid w-full grid-cols-[1fr_7.5rem_14rem_1.5rem] items-center gap-4 px-5 py-3 text-left transition-colors hover:bg-surface-2",
          open && "bg-surface-2",
        )}
      >
        <div className="min-w-0">
          <div className="font-medium">{r.title}</div>
          <div className="font-mono text-[11.5px] text-faint">{r.id}</div>
        </div>
        <SeverityBadge severity={r.severity} />
        <div className="flex flex-wrap gap-1">
          {nist.length ? (
            nist.map((c) => <Tag key={c}>{c}</Tag>)
          ) : (
            <span className="text-[12.5px] text-muted">
              {r.hardening_best_practice ? "Hardening best practice" : "–"}
            </span>
          )}
        </div>
        <ChevronDown
          className={cx("size-4 text-faint transition-transform", open && "rotate-180")}
          aria-hidden
        />
      </button>
      {open && (
        <div className="grid gap-6 border-t border-line bg-surface-2 px-5 py-5 text-[13.5px] lg:grid-cols-2">
          <div>
            <p className="leading-relaxed">
              <Prose text={r.intent} />
            </p>
            <div className="mt-4 rounded-lg bg-basalt px-4 py-3 font-mono text-[12.5px] leading-6 text-[#f1ede2] ring-1 ring-basalt-line">
              <div>
                <span className="text-brass">for each </span>
                {r.for_each}
              </div>
              <div>
                <span className="text-brass">assert </span>
                {r.assertion}
              </div>
            </div>
            <div className="mt-3 text-[12.5px] text-muted">
              Applies to {r.applies_to.map(titleCase).join(", ")}
            </div>
          </div>
          <div className="space-y-5">
            <div>
              <div className="mb-1.5 text-[12px] font-medium text-muted">
                NIST SP 800-53 Rev. 5 controls
              </div>
              <ul className="space-y-1">
                {nist.map((c) => (
                  <li key={c} className="flex gap-2">
                    <Mono className="w-16 shrink-0 font-medium">{c}</Mono>
                    <span className="text-muted">{titles[c]}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="mb-1.5 text-[12px] font-medium text-muted">
                Proved on every change against sample configurations
              </div>
              <ul className="space-y-1 font-mono text-[12.5px]">
                {r.fixtures_pass.map((f) => (
                  <li key={f} className="flex items-center gap-2">
                    <Check className="size-3.5 text-pass" strokeWidth={2.75} aria-label="passes" />
                    {f}
                  </li>
                ))}
                {r.fixtures_fail.map((f) => (
                  <li key={f} className="flex items-center gap-2">
                    <X className="size-3.5 text-fail" strokeWidth={2.75} aria-label="fails" />
                    {f}
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
