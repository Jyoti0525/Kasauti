import { ArrowRight, Plus, ServerCog, ShieldAlert } from "lucide-react";
import { Link, useNavigate } from "react-router";
import { useAudits, useKb, usePackName } from "../api/hooks";
import { Bars, Legend, Ring, toneFor, VerdictBar } from "../components/charts";
import {
  Button,
  Card,
  Empty,
  ErrorBox,
  JobBadge,
  Loading,
  PageHeader,
  SeverityBadge,
  Stat,
} from "../components/ui";
import { byFramework, byVendor, latestPerDevice, riskiest, topFailing } from "../lib/fleet";
import { ago, pct } from "../lib/format";

const NIST = "nist_800_53r5";

export function Dashboard() {
  const audits = useAudits();
  const kb = useKb();
  const packName = usePackName();
  const navigate = useNavigate();

  if (audits.isPending) return <Loading what="Loading the fleet" />;
  if (audits.isError) return <ErrorBox error={audits.error} />;

  const devices = latestPerDevice(audits.data);
  const newAudit = (
    <Button variant="primary" onClick={() => navigate("/audits/new")}>
      <Plus className="size-4" /> New audit
    </Button>
  );
  if (devices.length === 0) {
    return (
      <>
        <PageHeader title="Fleet compliance" actions={newAudit} />
        <Card>
          <Empty icon={<ServerCog className="size-10" />} title="No device audited yet">
            Drop configuration files from any of the installed vendors (Cisco, Juniper, Arista, Palo
            Alto, Fortinet, AWS) and Kasauti scores each against NIST SP 800-53, showing the
            evidence line behind every verdict.
            <div className="mt-4">{newAudit}</div>
          </Empty>
        </Card>
      </>
    );
  }

  const frameworks = byFramework(devices);
  const primary = frameworks.get(NIST) ?? [...frameworks.values()][0];
  // Worst first: the vendor needing attention leads.
  const vendors = new Map(
    [...byVendor(devices, NIST)].sort(
      (a, b) => (a[1].compliance_pct ?? -1) - (b[1].compliance_pct ?? -1),
    ),
  );
  const failing = topFailing(devices);
  const risky = riskiest(devices);
  const sev = devices.reduce(
    (n, d) => {
      for (const [k, v] of Object.entries(d.summary.failed_by_severity))
        n[k] = (n[k] ?? 0) + (v ?? 0);
      return n;
    },
    {} as Record<string, number>,
  );
  const understood = devices
    .map((d) => d.summary.understood_pct)
    .filter((v): v is number => v !== null);
  const controlsOf = (ruleId: string) =>
    kb.data?.rules.find((r) => r.id === ruleId)?.controls[NIST] ?? [];

  return (
    <>
      <PageHeader
        title="Fleet compliance"
        subtitle={`${devices.length} device${devices.length === 1 ? "" : "s"} · latest audit of each · ${vendors.size} vendor${vendors.size === 1 ? "" : "s"}`}
        actions={newAudit}
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat
          label="Compliance · NIST SP 800-53"
          value={pct(primary?.compliance_pct ?? null)}
          hint={`${primary?.passed ?? 0} passed of ${(primary?.passed ?? 0) + (primary?.failed ?? 0)} judged`}
          tone={toneFor(primary?.compliance_pct ?? null)}
        />
        <Stat
          label="Coverage"
          value={pct(primary?.coverage_pct ?? null)}
          hint={`${primary?.review ?? 0} need a person to review`}
          tone="gold"
        />
        <Stat
          label="Failed checks"
          value={primary?.failed ?? 0}
          hint={
            <span className="flex gap-3">
              <span className="text-critical">{sev.critical ?? 0} critical</span>
              <span className="text-high">{sev.high ?? 0} high</span>
              <span className="text-medium">{sev.medium ?? 0} medium</span>
            </span>
          }
          tone="fail"
        />
        <Stat
          label="Configuration understood"
          value={pct(
            understood.length ? understood.reduce((a, b) => a + b, 0) / understood.length : null,
          )}
          hint="lines read by an approved mapping"
        />
      </div>

      <div className="mb-6 grid gap-6 lg:grid-cols-5">
        <Card title="By framework" className="lg:col-span-2">
          <div className="space-y-6">
            {[...frameworks].map(([id, f]) => (
              <div key={id} className="flex items-center gap-6">
                <Ring
                  value={f.compliance_pct}
                  tone={toneFor(f.compliance_pct)}
                  label="compliance"
                />
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{f.title}</div>
                  <div className="mt-1 text-sm text-muted">
                    Coverage {pct(f.coverage_pct)} · {f.devices} device{f.devices === 1 ? "" : "s"}
                  </div>
                  <div className="mt-3">
                    <VerdictBar
                      pass={f.passed}
                      fail={f.failed}
                      review={f.review}
                      na={f.not_applicable}
                    />
                  </div>
                  <div className="mt-2">
                    <Legend
                      items={[
                        { cls: "bg-fail", label: `${f.failed} fail` },
                        { cls: "bg-review", label: `${f.review} review` },
                        { cls: "bg-pass", label: `${f.passed} pass` },
                        { cls: "bg-na/40", label: `${f.not_applicable} n/a` },
                      ]}
                    />
                  </div>
                </div>
              </div>
            ))}
            <p className="text-xs leading-relaxed text-muted">
              <b className="font-medium text-text">Compliance</b> is what held among the checks that
              could be judged. <b className="font-medium text-text">Coverage</b> is how many could
              be judged at all; the rest are REVIEW, never guessed as PASS.
            </p>
          </div>
        </Card>

        <Card title="By vendor · NIST SP 800-53" className="lg:col-span-3">
          <Bars
            rows={[...vendors].map(([pack, p]) => ({
              label: packName(pack),
              value: p.compliance_pct,
              hint: `coverage ${pct(p.coverage_pct, 0)} · ${p.devices} dev`,
            }))}
          />
        </Card>
      </div>

      <div className="mb-6 grid gap-6 lg:grid-cols-5">
        <Card title="Top failing checks" className="lg:col-span-3" bodyClass="p-0">
          {failing.length === 0 ? (
            <Empty title="Nothing fails">Every judged check holds on every device.</Empty>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-left text-xs text-muted">
                <tr className="border-b border-line">
                  <th className="px-5 py-2 font-medium">Check</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">NIST controls</th>
                  <th className="px-5 py-2 text-right font-medium">Devices</th>
                </tr>
              </thead>
              <tbody>
                {failing.map(({ rule, devices: n }) => (
                  <tr key={rule.rule_id} className="border-b border-line last:border-0">
                    <td className="px-5 py-2.5">
                      <div className="font-medium">{rule.title}</div>
                      <div className="font-mono text-[11px] text-faint">{rule.rule_id}</div>
                    </td>
                    <td className="px-3 py-2.5">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="px-3 py-2.5 font-mono text-xs text-muted">
                      {controlsOf(rule.rule_id).join(", ") || "–"}
                    </td>
                    <td className="px-5 py-2.5 text-right tabular-nums">
                      <span className="font-semibold text-fail">{n}</span>
                      <span className="text-faint"> / {devices.length}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card title="Riskiest devices" className="lg:col-span-2" bodyClass="p-2">
          {risky.length === 0 ? (
            <Empty icon={<ShieldAlert className="size-8" />} title="No failing device" />
          ) : (
            <ul>
              {risky.map((d) => {
                const s = d.summary;
                const score = s.scores.find((x) => x.framework === NIST) ?? s.scores[0];
                return (
                  <li key={d.key}>
                    <Link
                      to={`/devices/${d.audit.job_id}`}
                      className="flex items-center gap-3 rounded-lg px-3 py-2.5 hover:bg-surface-2"
                    >
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-medium">{s.hostname ?? d.audit.name}</div>
                        <div className="truncate text-xs text-muted">{packName(s.pack)}</div>
                      </div>
                      <div className="text-right text-xs">
                        <div className="font-semibold tabular-nums">
                          {pct(score?.compliance_pct ?? null, 0)}
                        </div>
                        <div className="text-fail">
                          {(s.failed_by_severity.critical ?? 0) + (s.failed_by_severity.high ?? 0)}{" "}
                          high+
                        </div>
                      </div>
                      <ArrowRight className="size-4 text-faint" aria-hidden />
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        <Card title="Coverage per vendor" className="lg:col-span-2">
          <Bars
            rows={[...vendors].map(([pack, p]) => ({
              label: packName(pack),
              value: p.coverage_pct,
              tone: "gold" as const,
            }))}
          />
        </Card>
        <Card
          title="Recent audits"
          className="lg:col-span-3"
          bodyClass="p-0"
          action={
            <Link to="/audits" className="text-xs font-medium text-muted hover:text-text">
              All audits →
            </Link>
          }
        >
          <ul>
            {audits.data.slice(0, 6).map((a) => (
              <li key={a.job_id} className="border-b border-line last:border-0">
                <Link
                  to={a.state === "succeeded" ? `/devices/${a.job_id}` : `/uploads/${a.upload_id}`}
                  className="flex items-center gap-3 px-5 py-2.5 text-sm hover:bg-surface-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{a.summary?.hostname ?? a.name}</div>
                    <div className="truncate text-xs text-muted">
                      {a.label ?? "Untitled audit"} · {a.name}
                    </div>
                  </div>
                  {a.summary && (
                    <span className="w-14 text-right tabular-nums">
                      {pct(a.summary.scores[0]?.compliance_pct ?? null, 0)}
                    </span>
                  )}
                  <JobBadge state={a.state} />
                  <span className="w-20 text-right text-xs text-faint">
                    {ago(a.finished_at ?? a.created_at)}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  );
}
