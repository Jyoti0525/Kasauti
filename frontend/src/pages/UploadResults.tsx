import { ArrowRight, Download, FileArchive, Loader2 } from "lucide-react";
import { Link, useParams } from "react-router";
import { useAudits, usePackName, useUpload } from "../api/hooks";
import type { AuditOut } from "../api/types";
import { toneFor, VerdictBar } from "../components/charts";
import {
  Card,
  Empty,
  ErrorBox,
  JobBadge,
  LinkButton,
  Loading,
  PageHeader,
  Stat,
  cx,
} from "../components/ui";
import { pool } from "../lib/fleet";
import { pct, when } from "../lib/format";

export function UploadResults() {
  const { uploadId } = useParams();
  const upload = useUpload(uploadId);
  const audits = useAudits(uploadId);
  const packName = usePackName();

  if (upload.isPending || audits.isPending) return <Loading what="Loading results" />;
  if (upload.isError) return <ErrorBox error={upload.error} />;
  if (audits.isError) return <ErrorBox error={audits.error} />;

  const u = upload.data;
  const list = audits.data;
  const done = list.filter((a) => a.summary);
  const running = list.filter((a) => a.state === "queued" || a.state === "running").length;
  const failed = list.filter((a) => a.state === "failed");
  const scores = done.flatMap((a) => a.summary?.scores.slice(0, 1) ?? []);
  const pooled = pool(scores);

  return (
    <>
      <PageHeader
        eyebrow={
          <Link to="/audits" className="hover:underline">
            Audits
          </Link>
        }
        title={u.label ?? "Untitled audit"}
        subtitle={`${list.length} device${list.length === 1 ? "" : "s"} · started ${when(u.started_at)} · ${u.frameworks.join(", ")}`}
        actions={
          done.length > 0 && (
            <LinkButton href={`/api/uploads/${u.id}/reports.zip`} download variant="primary">
              <FileArchive className="size-4" /> All reports (.zip)
            </LinkButton>
          )
        }
      />

      {running > 0 && (
        <div className="mb-4 flex items-center gap-2 rounded-lg border border-gold/40 bg-gold-soft px-4 py-2.5 text-sm">
          <Loader2 className="size-4 animate-spin text-gold" /> Auditing {running} device
          {running === 1 ? "" : "s"}… each runs in its own sandboxed worker.
        </div>
      )}

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat
          label="Compliance"
          value={pct(pooled.compliance_pct)}
          tone={toneFor(pooled.compliance_pct)}
          hint="pooled over the devices below"
        />
        <Stat label="Coverage" value={pct(pooled.coverage_pct)} tone="gold" />
        <Stat label="Failed checks" value={pooled.failed} tone="fail" />
        <Stat
          label="Devices audited"
          value={`${done.length}/${list.length}`}
          hint={failed.length ? `${failed.length} could not be audited` : undefined}
        />
      </div>

      <Card title="Devices" bodyClass="p-0">
        {list.length === 0 ? (
          <Empty title="No device audit yet" />
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-b border-line">
                <th className="px-5 py-2.5 font-medium">Device</th>
                <th className="px-3 py-2.5 font-medium">Compliance</th>
                <th className="px-3 py-2.5 font-medium">Coverage</th>
                <th className="w-48 px-3 py-2.5 font-medium">Checks</th>
                <th className="px-3 py-2.5 font-medium">Identity</th>
                <th className="px-5 py-2.5 text-right font-medium">Report</th>
              </tr>
            </thead>
            <tbody>
              {list.map((a) => (
                <DeviceRow key={a.job_id} audit={a} packName={packName} />
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

function DeviceRow({ audit: a, packName }: { audit: AuditOut; packName: (id: string) => string }) {
  const s = a.summary;
  if (!s) {
    return (
      <tr className="border-b border-line last:border-0">
        <td className="px-5 py-3">
          <div className="font-medium">{a.name}</div>
          {a.error && <div className="mt-0.5 max-w-xl text-xs text-fail">{a.error}</div>}
        </td>
        <td colSpan={4} />
        <td className="px-5 py-3 text-right">
          <JobBadge state={a.state} />
        </td>
      </tr>
    );
  }
  const score = s.scores[0];
  return (
    <tr className="border-b border-line last:border-0 hover:bg-surface-2">
      <td className="px-5 py-3">
        <Link
          to={`/devices/${a.job_id}`}
          className="group inline-flex items-center gap-1.5 font-medium"
        >
          {s.hostname ?? a.name}
          <ArrowRight
            className="size-3.5 text-faint opacity-0 transition-opacity group-hover:opacity-100"
            aria-hidden
          />
        </Link>
        <div className="text-xs text-muted">
          {packName(s.pack)}
          {s.os_version && ` · ${s.os_version}`} · {a.name}
        </div>
      </td>
      <td
        className={cx(
          "px-3 py-3 font-semibold tabular-nums",
          { pass: "text-pass", fail: "text-fail", review: "text-review" }[
            toneFor(score?.compliance_pct ?? null)
          ],
        )}
      >
        {pct(score?.compliance_pct ?? null)}
      </td>
      <td className="px-3 py-3 tabular-nums text-muted">{pct(score?.coverage_pct ?? null)}</td>
      <td className="px-3 py-3">
        <VerdictBar
          pass={s.statuses.PASS}
          fail={s.statuses.FAIL}
          review={s.statuses.REVIEW}
          na={s.statuses["N/A"]}
        />
        <div className="mt-1 text-[11px] text-muted">
          <span className="text-fail">{s.statuses.FAIL ?? 0} fail</span> · {s.statuses.REVIEW ?? 0}{" "}
          review · {s.statuses.PASS ?? 0} pass
        </div>
      </td>
      <td className="px-3 py-3 text-xs">
        <span className={s.identity_found === s.identity_total ? "text-pass" : "text-muted"}>
          {s.identity_found}/{s.identity_total} fields
        </span>
      </td>
      <td className="px-5 py-3 text-right">
        <a
          href={`/api/jobs/${a.job_id}/report.pdf`}
          download
          className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-muted hover:bg-surface hover:text-text"
        >
          <Download className="size-3.5" /> PDF
        </a>
      </td>
    </tr>
  );
}
