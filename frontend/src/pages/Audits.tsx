import { ChevronRight, FolderOpen } from "lucide-react";
import { Link, useNavigate } from "react-router";
import { useUploads } from "../api/hooks";
import type { UploadBrief } from "../api/types";
import { Card, Empty, ErrorBox, Loading, PageHeader, cx } from "../components/ui";
import { ago, when } from "../lib/format";

export function Audits() {
  const uploads = useUploads();
  const navigate = useNavigate();
  if (uploads.isPending) return <Loading what="Loading audits" />;
  if (uploads.isError) return <ErrorBox error={uploads.error} />;
  const target = (u: UploadBrief) =>
    u.state === "open" ? `/audits/new/${u.id}` : `/uploads/${u.id}`;
  return (
    <>
      <PageHeader
        title="Audits"
        subtitle="Every upload, newest first. Each is audited device by device, in its own sandboxed worker."
      />
      <Card bodyClass="p-0">
        {uploads.data.length === 0 ? (
          <Empty icon={<FolderOpen />} title="No audit yet">
            <Link to="/audits/new" className="font-medium text-brass-ink underline">
              Start the first one
            </Link>
          </Empty>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Audit</th>
                <th>Files</th>
                <th>Devices</th>
                <th>Status</th>
                <th className="text-right">Created</th>
                <th className="w-10" aria-label="Open" />
              </tr>
            </thead>
            <tbody>
              {uploads.data.map((u) => (
                <tr key={u.id} data-link onClick={() => navigate(target(u))}>
                  <td>
                    <Link
                      to={target(u)}
                      className="font-semibold"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {u.label ?? "Untitled audit"}
                    </Link>
                    <div className="font-mono text-[11.5px] text-faint">{u.id.slice(0, 8)}</div>
                  </td>
                  <td className="figure align-middle">
                    {u.accepted}
                    {u.refused > 0 && <span className="text-fail"> +{u.refused} refused</span>}
                  </td>
                  <td className="align-middle">
                    <AuditCounts audits={u.audits} />
                  </td>
                  <td className="align-middle">
                    <UploadState state={u.state} />
                  </td>
                  <td
                    className="text-right align-middle text-[13px] text-muted"
                    title={when(u.created_at)}
                  >
                    {ago(u.created_at)}
                  </td>
                  <td className="align-middle">
                    <ChevronRight className="size-4 text-faint" aria-hidden />
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
    { n: audits.succeeded, label: "audited", cls: "text-text" },
    {
      n: (audits.queued ?? 0) + (audits.running ?? 0) || undefined,
      label: "in progress",
      cls: "text-brass-ink",
    },
    { n: audits.failed, label: "failed", cls: "text-fail" },
  ].filter((p) => p.n);
  if (!parts.length) return <span className="text-faint">–</span>;
  return (
    <span className="flex gap-3 text-[13px]">
      {parts.map((p) => (
        <span key={p.label} className={p.cls}>
          <span className="figure font-semibold">{p.n}</span> {p.label}
        </span>
      ))}
    </span>
  );
}

function UploadState({ state }: { state: UploadBrief["state"] }) {
  const s = {
    open: { dot: "bg-brass", label: "Taking files" },
    started: { dot: "bg-pass", label: "Started" },
    discarded: { dot: "bg-na", label: "Discarded" },
    expired: { dot: "bg-na", label: "Expired" },
  }[state];
  return (
    <span className="inline-flex items-center gap-1.5 text-[13px] text-muted">
      <span className={cx("size-2 rounded-full", s.dot)} aria-hidden />
      {s.label}
    </span>
  );
}
