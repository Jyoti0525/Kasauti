import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CheckCircle2,
  FileText,
  Loader2,
  Play,
  Server,
  Terminal,
  Trash2,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { api } from "../api/client";
import { useHealth, useKb, usePackName, useUpload } from "../api/hooks";
import type { DeviceOut, FileOut, Upload } from "../api/types";
import { ENTERABLE } from "../api/types";
import { DropZone, type Picked } from "../components/DropZone";
import { Button, Card, ErrorBox, Loading, PageHeader, cx } from "../components/ui";
import { bytes, titleCase } from "../lib/format";

const PARALLEL = 3;
let nextSend = 0;

interface Sending {
  id: number;
  name: string;
  state: "sending" | "sent" | "error";
  error?: string;
}

export function NewAudit() {
  const { uploadId } = useParams();
  const navigate = useNavigate();
  const queries = useQueryClient();
  const health = useHealth();
  const kb = useKb();
  const upload = useUpload(uploadId);

  const [label, setLabel] = useState("");
  const [frameworks, setFrameworks] = useState<string[]>(["nist_800_53r5"]);
  const [vendor, setVendor] = useState("");
  const [sending, setSending] = useState<Sending[]>([]);
  const [error, setError] = useState<unknown>(null);

  const refresh = () => queries.invalidateQueries({ queryKey: ["upload", uploadId] });

  const send = async (id: string, picked: Picked[]) => {
    const batch = picked.map((p) => ({ ...p, key: nextSend++ }));
    setSending((s) => [
      ...s,
      ...batch.map((p) => ({ id: p.key, name: p.name, state: "sending" as const })),
    ]);
    const mark = (key: number, change: Partial<Sending>) =>
      setSending((s) => s.map((x) => (x.id === key ? { ...x, ...change } : x)));
    const queue = [...batch];
    const worker = async () => {
      for (let p = queue.shift(); p; p = queue.shift()) {
        try {
          await api.sendFile(`/api/uploads/${id}/files`, p.file, p.name);
          mark(p.key, { state: "sent" });
        } catch (err) {
          mark(p.key, { state: "error", error: err instanceof Error ? err.message : String(err) });
        }
        void queries.invalidateQueries({ queryKey: ["upload", id] });
      }
    };
    await Promise.all(Array.from({ length: PARALLEL }, worker));
  };

  const onFiles = async (picked: Picked[]) => {
    setError(null);
    if (!picked.length) return;
    try {
      let id = uploadId;
      if (!id) {
        const created = await api.post<Upload>("/api/uploads", {
          label: label.trim() || null,
          frameworks,
          vendor: vendor || null,
        });
        id = created.id;
        queries.setQueryData(["upload", id], created);
        navigate(`/audits/new/${id}`, { replace: true });
      }
      await send(id, picked);
    } catch (err) {
      setError(err);
    }
  };

  const start = useMutation({
    mutationFn: () => api.post<Upload>(`/api/uploads/${uploadId}/start`),
    onSuccess: () => {
      void queries.invalidateQueries({ queryKey: ["uploads"] });
      void queries.invalidateQueries({ queryKey: ["audits"] });
      navigate(`/uploads/${uploadId}`);
    },
  });
  const discard = useMutation({
    mutationFn: () => api.delete<undefined>(`/api/uploads/${uploadId}`),
    onSuccess: () => {
      setSending([]);
      navigate("/audits/new", { replace: true });
    },
  });

  const u = upload.data;
  if (uploadId && upload.isPending) return <Loading what="Loading the upload" />;
  if (uploadId && upload.isError) return <ErrorBox error={upload.error} />;
  if (u && u.state !== "open") {
    return (
      <>
        <PageHeader title={u.label ?? "Audit"} />
        <Card>
          <p className="text-sm">
            This upload is <b>{u.state}</b>.{" "}
            {u.state === "started" ? (
              <Link className="font-medium text-gold underline" to={`/uploads/${u.id}`}>
                See its results
              </Link>
            ) : (
              <Link className="font-medium text-gold underline" to="/audits/new">
                Start a new audit
              </Link>
            )}
          </p>
        </Card>
      </>
    );
  }

  const installed = health.data?.frameworks ?? [];
  const busy = sending.some((s) => s.state === "sending");
  const canStart = Boolean(u && u.accepted > 0 && u.recognising === 0 && !busy);

  return (
    <>
      <PageHeader
        title={u ? (u.label ?? "New audit") : "New audit"}
        subtitle="Name it, choose frameworks, drop the files, check the devices found, start."
        actions={
          u && (
            <>
              <Button
                variant="danger"
                onClick={() => discard.mutate()}
                disabled={discard.isPending}
              >
                <Trash2 className="size-4" /> Discard
              </Button>
              <Button
                variant="primary"
                onClick={() => start.mutate()}
                disabled={!canStart || start.isPending}
              >
                {start.isPending ? (
                  <Loader2 className="size-4 animate-spin" />
                ) : (
                  <Play className="size-4" />
                )}
                Start audit
                {u.devices.length > 0 &&
                  ` · ${u.devices.length} device${u.devices.length === 1 ? "" : "s"}`}
              </Button>
            </>
          )
        }
      />
      {(error || start.error || discard.error) && (
        <div className="mb-4">
          <ErrorBox error={error ?? start.error ?? discard.error} />
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-1">
          <Card title="1 · Audit">
            <label className="block text-sm font-medium" htmlFor="label">
              Name
            </label>
            <input
              id="label"
              value={u ? (u.label ?? "") : label}
              disabled={Boolean(u)}
              onChange={(e) => setLabel(e.target.value)}
              maxLength={200}
              placeholder="e.g. Branch routers, Q3 review"
              className="mt-1 w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm disabled:bg-surface-2"
            />
            <fieldset className="mt-4">
              <legend className="text-sm font-medium">2 · Frameworks</legend>
              <div className="mt-2 space-y-1.5">
                {installed.map((f) => (
                  <label key={f} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      disabled={Boolean(u)}
                      checked={u ? u.frameworks.includes(f) : frameworks.includes(f)}
                      onChange={(e) =>
                        setFrameworks((cur) =>
                          e.target.checked ? [...cur, f] : cur.filter((x) => x !== f),
                        )
                      }
                    />
                    {kb.data?.frameworks.find((x) => x.id === f)?.title ?? f}
                  </label>
                ))}
              </div>
              <p className="mt-2 text-xs text-muted">
                Every rule is anchored to NIST SP 800-53 Rev. 5. CIS, DISA STIG and ISO 27001 arrive
                through the crosswalk (M3).
              </p>
            </fieldset>
            <label className="mt-4 block text-sm font-medium" htmlFor="vendor">
              Vendor
            </label>
            <select
              id="vendor"
              value={u ? (u.vendor ?? "") : vendor}
              disabled={Boolean(u)}
              onChange={(e) => setVendor(e.target.value)}
              className="mt-1 w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm disabled:bg-surface-2"
            >
              <option value="">Recognise each file automatically</option>
              {kb.data?.vendors.map((v) => (
                <option key={v.id} value={v.id}>
                  {v.name}
                </option>
              ))}
            </select>
          </Card>
          {sending.length > 0 && <SendLog sending={sending} />}
        </div>

        <div className="space-y-6 lg:col-span-2">
          <DropZone onFiles={onFiles} disabled={!u && frameworks.length === 0} />
          {u && <Files upload={u} onChange={refresh} />}
          {u && u.devices.length > 0 && <Devices upload={u} onChange={refresh} />}
        </div>
      </div>
    </>
  );
}

function SendLog({ sending }: { sending: Sending[] }) {
  const sent = sending.filter((s) => s.state === "sent").length;
  const failed = sending.filter((s) => s.state === "error");
  return (
    <Card title={`Sending · ${sent}/${sending.length}`}>
      <div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
        <div
          className="h-full bg-gold transition-[width]"
          style={{ width: `${(100 * sent) / sending.length}%` }}
        />
      </div>
      {failed.map((f) => (
        <div key={f.id} className="mt-2 text-xs text-fail">
          {f.name}: {f.error}
        </div>
      ))}
    </Card>
  );
}

function Files({ upload, onChange }: { upload: Upload; onChange: () => void }) {
  const packName = usePackName();
  const remove = useMutation({
    mutationFn: (fileId: string) =>
      api.delete<undefined>(`/api/uploads/${upload.id}/files/${fileId}`),
    onSuccess: onChange,
  });
  return (
    <Card
      title={`Files · ${upload.accepted} accepted${upload.refused ? ` · ${upload.refused} refused` : ""}`}
      action={
        upload.recognising > 0 && (
          <span className="inline-flex items-center gap-1.5 text-xs text-muted">
            <Loader2 className="size-3.5 animate-spin" /> recognising {upload.recognising}
          </span>
        )
      }
      bodyClass="p-0"
    >
      <ul className="max-h-96 overflow-y-auto">
        {upload.files.map((f) => (
          <li
            key={f.id}
            className="flex items-center gap-3 border-b border-line px-5 py-2 text-sm last:border-0"
          >
            <FileIcon file={f} />
            <div className="min-w-0 flex-1">
              <div className="truncate font-medium">{f.name}</div>
              <div className={cx("truncate text-xs", f.accepted ? "text-muted" : "text-fail")}>
                {describe(f, packName)}
              </div>
            </div>
            <span className="text-xs tabular-nums text-faint">{bytes(f.size)}</span>
            <button
              type="button"
              onClick={() => remove.mutate(f.id)}
              className="rounded p-1 text-faint hover:bg-surface-2 hover:text-fail"
              aria-label={`Remove ${f.name}`}
            >
              <Trash2 className="size-4" />
            </button>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function FileIcon({ file }: { file: FileOut }) {
  if (!file.accepted) return <XCircle className="size-4 shrink-0 text-fail" aria-label="refused" />;
  if (file.recognition === "pending")
    return <Loader2 className="size-4 shrink-0 animate-spin text-faint" aria-label="recognising" />;
  if (file.kind === "config")
    return <Server className="size-4 shrink-0 text-gold" aria-label="configuration" />;
  if (file.kind === "companion")
    return <Terminal className="size-4 shrink-0 text-muted" aria-label="command output" />;
  return <FileText className="size-4 shrink-0 text-faint" aria-label="not recognised" />;
}

function describe(f: FileOut, packName: (id: string | null) => string): string {
  if (!f.accepted) return f.reason ?? "refused";
  if (f.recognition === "pending") return "recognising…";
  const parts: string[] = [];
  if (f.kind === "config") parts.push(`${packName(f.vendor)} configuration`);
  else if (f.kind === "companion")
    parts.push(`${f.command ?? "command"} output${f.vendor ? ` · ${packName(f.vendor)}` : ""}`);
  else parts.push("not recognised: audited on its own, which says why");
  if (f.hostname) parts.push(`host ${f.hostname}`);
  if (f.note) parts.push(f.note);
  return parts.join(" · ");
}

function Devices({ upload, onChange }: { upload: Upload; onChange: () => void }) {
  const packName = usePackName();
  const byId = new Map(upload.files.map((f) => [f.id, f]));
  const outputs = upload.files.filter((f) => f.accepted && f.kind === "companion");
  const configs = upload.devices;

  const pair = useMutation({
    mutationFn: ({ file, to }: { file: string; to: string }) =>
      to === "auto"
        ? api.delete<Upload>(`/api/uploads/${upload.id}/files/${file}/pairing`)
        : api.put<Upload>(`/api/uploads/${upload.id}/files/${file}/pairing`, {
            config: to === "none" ? null : to,
          }),
    onSuccess: onChange,
  });

  return (
    <>
      <Card title={`3 · Devices found · ${configs.length}`} bodyClass="p-0">
        {pair.error && (
          <div className="p-4">
            <ErrorBox error={pair.error} />
          </div>
        )}
        <ul>
          {configs.map((d) => (
            <DeviceRow
              key={d.config}
              upload={upload}
              device={d}
              files={byId}
              packName={packName}
              onChange={onChange}
            />
          ))}
        </ul>
      </Card>
      {outputs.length > 0 && (
        <Card title="Command outputs · which device each belongs to" bodyClass="p-0">
          <ul>
            {outputs.map((f) => {
              const value = f.paired_by === "hand" ? (f.device ?? "none") : "auto";
              return (
                <li
                  key={f.id}
                  className="flex flex-wrap items-center gap-3 border-b border-line px-5 py-2.5 text-sm last:border-0"
                >
                  <Terminal className="size-4 text-muted" aria-hidden />
                  <div className="min-w-0 flex-1">
                    <div className="truncate font-medium">{f.name}</div>
                    <div className="truncate text-xs text-muted">
                      {f.device
                        ? `with ${byId.get(f.device)?.name ?? "?"} (${f.paired_by === "hand" ? "by hand" : `matched by ${f.paired_by}`})`
                        : (f.note ?? "in no audit")}
                    </div>
                  </div>
                  <select
                    aria-label={`Device for ${f.name}`}
                    value={value}
                    onChange={(e) => pair.mutate({ file: f.id, to: e.target.value })}
                    className="rounded-lg border border-line bg-surface px-2 py-1 text-sm"
                  >
                    <option value="auto">Automatic</option>
                    {configs.map((d) => (
                      <option key={d.config} value={d.config}>
                        {d.hostname ?? d.name}
                      </option>
                    ))}
                    <option value="none">Leave out</option>
                  </select>
                </li>
              );
            })}
          </ul>
        </Card>
      )}
    </>
  );
}

function DeviceRow({
  upload,
  device,
  files,
  packName,
  onChange,
}: {
  upload: Upload;
  device: DeviceOut;
  files: Map<string, FileOut>;
  packName: (id: string | null) => string;
  onChange: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [values, setValues] = useState<Record<string, string>>(device.entered);
  const save = useMutation({
    mutationFn: () => {
      const body = Object.fromEntries(Object.entries(values).filter(([, v]) => v.trim()));
      return api.put<Upload>(`/api/uploads/${upload.id}/files/${device.config}/identity`, body);
    },
    onSuccess: () => {
      onChange();
      setOpen(false);
    },
  });
  const typed = Object.keys(device.entered).length;
  return (
    <li className="border-b border-line px-5 py-3 last:border-0">
      <div className="flex items-center gap-3">
        <Server className="size-4 text-gold" aria-hidden />
        <div className="min-w-0 flex-1">
          <div className="truncate font-medium">{device.hostname ?? device.name}</div>
          <div className="truncate text-xs text-muted">
            {packName(device.vendor)} · {device.name}
            {device.companions.length > 0 &&
              ` · with ${device.companions.map((c) => files.get(c)?.name ?? "?").join(", ")}`}
          </div>
        </div>
        {typed > 0 && (
          <span className="inline-flex items-center gap-1 text-xs text-pass">
            <CheckCircle2 className="size-3.5" /> {typed} typed
          </span>
        )}
        <Button variant="ghost" onClick={() => setOpen(!open)}>
          {open ? "Close" : "Add details"}
        </Button>
      </div>
      {open && (
        <form
          className="mt-3 rounded-lg bg-surface-2 p-4"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <p className="mb-3 text-xs text-muted">
            Details no file gives, such as a serial number from an asset register. Shown in the
            report as <i>entered by hand</i>, used only where no file gives the value, and never
            used to judge a rule.
          </p>
          <div className="grid gap-3 sm:grid-cols-2">
            {ENTERABLE.map((field) => (
              <label key={field} className="text-xs font-medium">
                {titleCase(field)}
                <input
                  value={values[field] ?? ""}
                  onChange={(e) => setValues({ ...values, [field]: e.target.value })}
                  maxLength={200}
                  className="mt-1 w-full rounded-md border border-line bg-surface px-2 py-1.5 text-sm font-normal"
                />
              </label>
            ))}
          </div>
          {save.error && (
            <div className="mt-3">
              <ErrorBox error={save.error} />
            </div>
          )}
          <div className="mt-3 flex justify-end gap-2">
            <Button variant="primary" type="submit" disabled={save.isPending}>
              Save details
            </Button>
          </div>
        </form>
      )}
    </li>
  );
}
