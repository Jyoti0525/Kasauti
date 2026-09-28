import { Download, FileArchive, Loader2 } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router";
import { useAudits, useKb, usePackName, useUpload } from "../api/hooks";
import type { AuditOut } from "../api/types";
import { Meter, Posture, VerdictBar } from "../components/charts";
import {
  Card,
  Empty,
  ErrorBox,
  JobBadge,
  LinkButton,
  Loading,
  Notice,
  PageHeader,
} from "../components/ui";
import { pool, severityTotals } from "../lib/fleet";
import { pct, when } from "../lib/format";

export function UploadResults() {
  const { uploadId } = useParams();
  const upload = useUpload(uploadId);
  const audits = useAudits(uploadId);
  const kb = useKb();

  if (upload.isPending || audits.isPending) return <Loading what="Loading results" />;
  if (upload.isError) return <ErrorBox error={upload.error} />;
  if (audits.isError) return <ErrorBox error={audits.error} />;

  const u = upload.data;
  const list = audits.data;
  const done = list.flatMap((a) => (a.summary ? [a.summary] : []));
  const running = list.filter((a) => a.state === "queued" || a.state === "running").length;
  const failed = list.filter((a) => a.state === "failed").length;
  const pooled = pool(done.flatMap((s) => s.scores.slice(0, 1)));
  const frameworkTitle = (id: string) => kb.data?.frameworks.find((f) => f.id === id)?.title ?? id;

  return (
    <>
      <PageHeader
        crumbs={[{ label: "Audits", to: "/audits" }]}
        title={u.label ?? "Untitled audit"}
        meta={
          <>
            <span>
              {list.length} device{list.length === 1 ? "" : "s"}
              {failed > 0 && <span className="text-fail"> · {failed} could not be audited</span>}
            </span>
            {u.started_at && <span>Started {when(u.started_at)}</span>}
            <span>{u.frameworks.map(frameworkTitle).join(", ")}</span>
          </>
        }
        actions={
          done.length > 0 && (
            <LinkButton href={`/api/uploads/${u.id}/reports.zip`} download variant="primary">
              <FileArchive /> Download all reports
            </LinkButton>
          )
        }
      />

      {running > 0 && (
        <div className="mb-5">
          <Notice icon={<Loader2 className="animate-spin text-brass" />}>
            Auditing {running} device{running === 1 ? "" : "s"}. Each runs in its own sandboxed
            worker; results appear here as they finish.
          </Notice>
        </div>
      )}

      {done.length > 0 && (
        <Posture
          framework={frameworkTitle(u.frameworks[0] ?? "nist_800_53r5").split(":")[0] ?? ""}
          compliance={pooled.compliance_pct}
          coverage={pooled.coverage_pct}
          counts={{
            pass: pooled.passed,
            fail: pooled.failed,
            review: pooled.review,
            na: pooled.not_applicable,
          }}
          severity={severityTotals(done)}
          scope={`across the ${done.length} device${done.length === 1 ? "" : "s"} in this audit`}
          understood={mean(done.map((s) => s.understood_pct))}
        />
      )}

      <Card title="Devices" bodyClass="p-0">
        {list.length === 0 ? (
          <Empty title="No device audit yet" />
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Device</th>
                <th className="w-44">Compliance</th>
                <th className="w-56">Checks</th>
                <th>Identity</th>
                <th className="text-right">Report</th>
              </tr>
            </thead>
            <tbody>
              {list.map((a) => (
                <DeviceRow key={a.job_id} audit={a} />
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

function DeviceRow({ audit: a }: { audit: AuditOut }) {
  const packName = usePackName();
  const navigate = useNavigate();
  const s = a.summary;
  if (!s) {
    return (
      <tr>
        <td>
          <div className="font-medium">{a.name}</div>
          {a.error && <div className="mt-0.5 max-w-xl text-[12.5px] text-fail">{a.error}</div>}
        </td>
        <td colSpan={3} />
        <td className="text-right">
          <JobBadge state={a.state} />
        </td>
      </tr>
    );
  }
  const score = s.scores[0];
  const open = () => navigate(`/devices/${a.job_id}`);
  return (
    <tr data-link onClick={open}>
      <td>
        <Link
          to={`/devices/${a.job_id}`}
          className="font-semibold"
          onClick={(e) => e.stopPropagation()}
        >
          {s.hostname ?? a.name}
        </Link>
        <div className="text-[12.5px] text-muted">
          {packName(s.pack)}
          {s.os_version && ` ${s.os_version}`}
        </div>
      </td>
      <td className="align-middle">
        <div className="flex items-center gap-3">
          <Meter value={score?.compliance_pct ?? null} className="flex-1" />
          <span className="figure w-12 text-right font-semibold">
            {pct(score?.compliance_pct ?? null, 0)}
          </span>
        </div>
      </td>
      <td className="align-middle">
        <VerdictBar
          pass={s.statuses.PASS}
          fail={s.statuses.FAIL}
          review={s.statuses.REVIEW}
          na={s.statuses["N/A"]}
        />
        <div className="figure mt-1.5 text-[12px] text-muted">
          <span className="font-medium text-fail">{s.statuses.FAIL ?? 0} fail</span> ·{" "}
          {s.statuses.REVIEW ?? 0} review · {s.statuses.PASS ?? 0} pass
        </div>
      </td>
      <td className="align-middle text-[13px]">
        <span className={s.identity_found === s.identity_total ? "text-pass" : "text-muted"}>
          {s.identity_found} of {s.identity_total} fields
        </span>
      </td>
      <td className="text-right align-middle">
        <a
          href={`/api/jobs/${a.job_id}/report.pdf`}
          download
          onClick={(e) => e.stopPropagation()}
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-[13px] font-medium text-muted hover:bg-surface-3 hover:text-text"
        >
          <Download className="size-4" /> PDF
        </a>
      </td>
    </tr>
  );
}

/** The mean of the known values, or null when none is known. */
function mean(values: (number | null)[]): number | null {
  const known = values.filter((v): v is number => v !== null);
  return known.length ? known.reduce((a, b) => a + b, 0) / known.length : null;
}
