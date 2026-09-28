import { FolderOpen, Plus } from "lucide-react";
import { Link, useNavigate } from "react-router";
import { useUploads } from "../api/hooks";
import type { UploadBrief } from "../api/types";
import { Button, Card, Empty, ErrorBox, Loading, PageHeader, cx } from "../components/ui";
import { ago, when } from "../lib/format";

export function Audits() {
  const uploads = useUploads();
  const navigate = useNavigate();
  if (uploads.isPending) return <Loading what="Loading audits" />;
  if (uploads.isError) return <ErrorBox error={uploads.error} />;
  return (
    <>
      <PageHeader
        title="Audits"
        subtitle="Every upload, newest first. An upload is audited device by device."
        actions={
          <Button variant="primary" onClick={() => navigate("/audits/new")}>
            <Plus className="size-4" /> New audit
          </Button>
        }
      />
      <Card bodyClass="p-0">
        {uploads.data.length === 0 ? (
          <Empty icon={<FolderOpen className="size-10" />} title="No audit yet" />
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted">
              <tr className="border-b border-line">
                <th className="px-5 py-2.5 font-medium">Audit</th>
                <th className="px-3 py-2.5 font-medium">Files</th>
                <th className="px-3 py-2.5 font-medium">Devices</th>
                <th className="px-3 py-2.5 font-medium">State</th>
                <th className="px-5 py-2.5 text-right font-medium">Created</th>
              </tr>
            </thead>
            <tbody>
              {uploads.data.map((u) => (
                <tr key={u.id} className="border-b border-line last:border-0 hover:bg-surface-2">
                  <td className="px-5 py-3">
                    <Link
                      to={u.state === "open" ? `/audits/new/${u.id}` : `/uploads/${u.id}`}
                      className="font-medium hover:underline"
                    >
                      {u.label ?? "Untitled audit"}
                    </Link>
                    <div className="font-mono text-[11px] text-faint">{u.id.slice(0, 8)}</div>
                  </td>
                  <td className="px-3 py-3 tabular-nums">
                    {u.accepted}
                    {u.refused > 0 && <span className="text-fail"> +{u.refused} refused</span>}
                  </td>
                  <td className="px-3 py-3">
                    <AuditCounts audits={u.audits} />
                  </td>
                  <td className="px-3 py-3">
                    <UploadStateBadge state={u.state} />
                  </td>
                  <td
                    className="px-5 py-3 text-right text-xs text-muted"
                    title={when(u.created_at)}
                  >
                    {ago(u.created_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}

function AuditCounts({ audits }: { audits: UploadBrief["audits"] }) {
  const parts = [
    { n: audits.succeeded, label: "done", cls: "text-pass" },
    {
      n: (audits.queued ?? 0) + (audits.running ?? 0) || undefined,
      label: "running",
      cls: "text-gold",
    },
    { n: audits.failed, label: "failed", cls: "text-fail" },
  ].filter((p) => p.n);
  if (!parts.length) return <span className="text-faint">–</span>;
  return (
    <span className="flex gap-3 text-xs">
      {parts.map((p) => (
        <span key={p.label} className={p.cls}>
          {p.n} {p.label}
        </span>
      ))}
    </span>
  );
}

function UploadStateBadge({ state }: { state: UploadBrief["state"] }) {
  const cls = {
    open: "bg-gold-soft text-gold",
    started: "bg-pass-soft text-pass",
    discarded: "bg-na-soft text-na",
    expired: "bg-na-soft text-na",
  }[state];
  return (
    <span className={cx("rounded px-1.5 py-0.5 text-[11px] font-semibold", cls)}>
      {state === "open" ? "taking files" : state}
    </span>
  );
}
