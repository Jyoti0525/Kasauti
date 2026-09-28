import { ArrowRight, ChevronRight, ServerCog } from "lucide-react";
import { Link } from "react-router";
import { useAudits, useKb, usePackName } from "../api/hooks";
import { DotCount, Meter, Posture } from "../components/charts";
import {
  Card,
  Empty,
  ErrorBox,
  JobBadge,
  Loading,
  PageHeader,
  SEVERITY_TEXT,
  SeverityBadge,
  SeverityGlyph,
  Tag,
  cx,
} from "../components/ui";
import {
  byFramework,
  byVendor,
  latestPerDevice,
  riskiest,
  severityTotals,
  topFailing,
} from "../lib/fleet";
import { ago, pct } from "../lib/format";

const NIST = "nist_800_53r5";

export function Dashboard() {
  const audits = useAudits();
  const kb = useKb();
  const packName = usePackName();

  if (audits.isPending) return <Loading what="Loading the fleet" />;
  if (audits.isError) return <ErrorBox error={audits.error} />;

  const devices = latestPerDevice(audits.data);
  if (devices.length === 0) {
    return (
      <>
        <PageHeader title="Fleet overview" />
        <Card>
          <Empty icon={<ServerCog />} title="No device audited yet">
            Drop configuration files from any installed vendor (Cisco, Juniper, Arista, Palo Alto,
            Fortinet, AWS) and Kasauti scores each one against NIST SP 800-53, with the evidence
            line behind every verdict.
            <div className="mt-5">
              <Link
                to="/audits/new"
                className="inline-flex h-9 items-center rounded-lg bg-brass px-4 text-[13.5px] font-semibold text-on-brass"
              >
                Start the first audit
              </Link>
            </div>
          </Empty>
        </Card>
      </>
    );
  }

  const frameworks = byFramework(devices);
  const primary = frameworks.get(NIST) ?? [...frameworks.values()][0];
  // Worst first: the vendor needing attention leads.
  const vendors = [...byVendor(devices, NIST)].sort(
    (a, b) => (a[1].compliance_pct ?? -1) - (b[1].compliance_pct ?? -1),
  );
  const failing = topFailing(devices, 6);
  const risky = riskiest(devices, 5);
  const understood = devices
    .map((d) => d.summary.understood_pct)
    .filter((v): v is number => v !== null);
  const controlsOf = (ruleId: string) =>
    kb.data?.rules.find((r) => r.id === ruleId)?.controls[NIST] ?? [];
  const latest = audits.data.reduce<string | null>(
    (t, a) => (a.finished_at && (!t || a.finished_at > t) ? a.finished_at : t),
    null,
  );
  const failedOn = (pack: string) =>
    devices
      .filter((d) => d.summary.pack === pack)
      .reduce(
        (n, d) =>
          n +
          (d.summary.failed_by_severity.critical ?? 0) +
          (d.summary.failed_by_severity.high ?? 0),
        0,
      );

  return (
    <>
      <PageHeader
        title="Fleet overview"
        meta={
          <>
            <span>
              {devices.length} device{devices.length === 1 ? "" : "s"} · {vendors.length} vendor
              {vendors.length === 1 ? "" : "s"}
            </span>
            <span>Latest audit of each device</span>
            {latest && <span>Updated {ago(latest)}</span>}
          </>
        }
      />

      <Posture
        framework={primary?.title ?? "NIST SP 800-53 Rev. 5"}
        compliance={primary?.compliance_pct ?? null}
        coverage={primary?.coverage_pct ?? null}
        counts={{
          pass: primary?.passed ?? 0,
          fail: primary?.failed ?? 0,
          review: primary?.review ?? 0,
          na: primary?.not_applicable ?? 0,
        }}
        severity={severityTotals(devices.map((d) => d.summary))}
        understood={
          understood.length ? understood.reduce((a, b) => a + b, 0) / understood.length : null
        }
        scope={`across ${devices.length} device${devices.length === 1 ? "" : "s"}`}
      />

      <div className="mb-6 grid gap-6 lg:grid-cols-12">
        <Card
          title="By vendor"
          description="Weakest first. Scores pool rule counts, so a small device can't skew them."
          className="lg:col-span-7"
          bodyClass="p-0"
        >
          <table className="data">
            <thead>
              <tr>
                <th>Vendor</th>
                <th className="w-[38%]">Compliance</th>
                <th className="text-right">Coverage</th>
                <th className="text-right">Critical + high</th>
              </tr>
            </thead>
            <tbody>
              {vendors.map(([pack, p]) => (
                <tr key={pack}>
                  <td>
                    <div className="font-medium">{packName(pack)}</div>
                    <div className="text-[12px] text-muted">
                      {p.devices} device{p.devices === 1 ? "" : "s"}
                    </div>
                  </td>
                  <td className="align-middle">
                    <div className="flex items-center gap-3">
                      <Meter value={p.compliance_pct} className="flex-1" />
                      <span className="figure w-14 text-right font-semibold">
                        {pct(p.compliance_pct)}
                      </span>
                    </div>
                  </td>
                  <td className="figure text-right align-middle text-muted">
                    {pct(p.coverage_pct)}
                  </td>
                  <td className="figure text-right align-middle">
                    {failedOn(pack) ? (
                      <span className="font-semibold text-fail">{failedOn(pack)}</span>
                    ) : (
                      <span className="text-faint">0</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card
          title="Needs attention"
          description="Devices ranked by failed checks, weighted by severity."
          className="lg:col-span-5"
          bodyClass="px-2 pb-2"
        >
          {risky.length === 0 ? (
            <Empty title="No device fails a check" />
          ) : (
            <ol>
              {risky.map((d, i) => {
                const s = d.summary;
                const score = s.scores.find((x) => x.framework === NIST) ?? s.scores[0];
                return (
                  <li key={d.key}>
                    <Link
                      to={`/devices/${d.audit.job_id}`}
                      className="group flex items-center gap-3 rounded-lg px-3 py-2.5 hover:bg-surface-2"
                    >
                      <span className="figure w-4 text-[12px] text-faint">{i + 1}</span>
                      <div className="min-w-0 flex-1">
                        <div className="truncate font-semibold">{s.hostname ?? d.audit.name}</div>
                        <div className="truncate text-[12.5px] text-muted">{packName(s.pack)}</div>
                      </div>
                      <div className="flex items-center gap-3 text-[12.5px]">
                        {(["critical", "high"] as const).map((sev) =>
                          s.failed_by_severity[sev] ? (
                            <span
                              key={sev}
                              className={cx("inline-flex items-center gap-1", SEVERITY_TEXT[sev])}
                              title={`${s.failed_by_severity[sev]} ${sev}`}
                            >
                              <SeverityGlyph severity={sev} />
                              <span className="figure font-semibold">
                                {s.failed_by_severity[sev]}
                              </span>
                            </span>
                          ) : null,
                        )}
                      </div>
                      <span className="figure w-12 text-right font-semibold">
                        {pct(score?.compliance_pct ?? null, 0)}
                      </span>
                      <ChevronRight
                        className="size-4 text-faint transition-transform group-hover:translate-x-0.5"
                        aria-hidden
                      />
                    </Link>
                  </li>
                );
              })}
            </ol>
          )}
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-12">
        <Card
          title="Most common failures"
          description="Checks that fail on the most devices, the most severe first."
          className="lg:col-span-7"
          bodyClass="p-0"
        >
          {failing.length === 0 ? (
            <Empty title="Nothing fails">Every judged check holds on every device.</Empty>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Check</th>
                  <th>Severity</th>
                  <th>Devices</th>
                </tr>
              </thead>
              <tbody>
                {failing.map(({ rule, devices: n }) => (
                  <tr key={rule.rule_id}>
                    <td>
                      <div className="font-medium">{rule.title}</div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        <Tag className="border-transparent bg-transparent px-0 text-faint">
                          {rule.rule_id}
                        </Tag>
                        {controlsOf(rule.rule_id).map((c) => (
                          <Tag key={c}>{c}</Tag>
                        ))}
                      </div>
                    </td>
                    <td className="whitespace-nowrap">
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td className="whitespace-nowrap">
                      <DotCount n={n} total={devices.length} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>

        <Card
          title="Recent audits"
          className="lg:col-span-5"
          bodyClass="px-2 pb-2"
          action={
            <Link
              to="/audits"
              className="inline-flex items-center gap-1 text-[13px] font-medium text-muted hover:text-text"
            >
              All audits <ArrowRight className="size-3.5" aria-hidden />
            </Link>
          }
        >
          <ul>
            {audits.data.slice(0, 7).map((a) => (
              <li key={a.job_id}>
                <Link
                  to={a.state === "succeeded" ? `/devices/${a.job_id}` : `/uploads/${a.upload_id}`}
                  className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm hover:bg-surface-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{a.summary?.hostname ?? a.name}</div>
                    <div className="truncate text-[12.5px] text-muted">
                      {a.label ?? "Untitled audit"}
                    </div>
                  </div>
                  {a.summary ? (
                    <span className="figure w-12 text-right font-semibold">
                      {pct(a.summary.scores[0]?.compliance_pct ?? null, 0)}
                    </span>
                  ) : (
                    <JobBadge state={a.state} />
                  )}
                  <span className="w-20 text-right text-[12px] text-faint">
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
