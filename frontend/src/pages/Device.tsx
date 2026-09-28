import { Download, FileJson, Fingerprint } from "lucide-react";
import { useCallback, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useAudits, usePackName, useResult } from "../api/hooks";
import type { Finding } from "../api/types";
import { Ring, toneFor, VerdictBar } from "../components/charts";
import { Card, ErrorBox, LinkButton, Loading, PageHeader, Tabs, cx } from "../components/ui";
import { shortHash, titleCase } from "../lib/format";
import { Config } from "./device/Config";
import { Findings } from "./device/Findings";
import { Model } from "./device/Model";
import { Provenance } from "./device/Provenance";
import { Controls, Coverage, Policy } from "./device/Tabs";

type Tab = "findings" | "controls" | "config" | "policy" | "model" | "coverage";

export function DevicePage() {
  const { jobId } = useParams();
  const result = useResult(jobId);
  const audits = useAudits();
  const packName = usePackName();
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab | null) ?? "findings";
  const [open, setOpen] = useState<Finding | null>(null);
  const close = useCallback(() => setOpen(null), []);

  if (result.isPending) return <Loading what="Loading the audit" />;
  if (result.isError) return <ErrorBox error={result.error} />;
  const r = result.data;
  const audit = audits.data?.find((a) => a.job_id === jobId);
  const score = r.scores[0];
  const counts = (s: string) => r.rules.filter((x) => x.status === s).length;
  const hostname = r.identity.hostname?.value;
  const filterRules = r.sbm.entities.filter((e) => e.type === "FilterRule").length;

  return (
    <>
      <PageHeader
        eyebrow={
          audit ? (
            <Link to={`/uploads/${audit.upload_id}`} className="hover:underline">
              {audit.label ?? "Untitled audit"}
            </Link>
          ) : (
            "Device"
          )
        }
        title={hostname ?? r.input.file}
        subtitle={`${packName(r.detection.pack_id)}${r.identity.os_version?.value ? ` ${r.identity.os_version.value}` : ""} · ${r.input.file}`}
        actions={
          <>
            <LinkButton
              href={`/api/jobs/${jobId}/result`}
              download={`${(hostname ?? r.input.file).replace(/[^A-Za-z0-9._-]+/g, "_")}.kasauti.json`}
            >
              <FileJson className="size-4" /> JSON
            </LinkButton>
            <LinkButton href={`/api/jobs/${jobId}/report.pdf`} download variant="primary">
              <Download className="size-4" /> PDF report
            </LinkButton>
          </>
        }
      />

      <div className="mb-6 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <div className="flex items-center justify-around gap-4">
            <div className="text-center">
              <Ring
                value={score?.compliance_pct ?? null}
                tone={toneFor(score?.compliance_pct ?? null)}
                label="compliance"
              />
            </div>
            <div className="text-center">
              <Ring value={score?.coverage_pct ?? null} tone="gold" label="coverage" />
            </div>
          </div>
          <div className="mt-4">
            <VerdictBar
              pass={counts("PASS")}
              fail={counts("FAIL")}
              review={counts("REVIEW")}
              na={counts("N/A")}
            />
            <div className="mt-2 flex justify-between text-xs text-muted">
              <span className="text-fail">{counts("FAIL")} fail</span>
              <span className="text-review">{counts("REVIEW")} review</span>
              <span className="text-pass">{counts("PASS")} pass</span>
              <span>{counts("N/A")} n/a</span>
            </div>
          </div>
          <p className="mt-3 text-[11px] leading-relaxed text-faint">
            {score?.title}. Verified against Kasauti's model of the device, not on hardware.
          </p>
        </Card>

        <Card title="Identity" className="lg:col-span-1" bodyClass="py-3">
          <dl className="space-y-1.5 text-sm">
            {["hostname", "vendor", "os_version", "model", "serial", "hardware"].map((k) => {
              const f = r.identity[k];
              return (
                <div key={k} className="grid grid-cols-[6.5rem_1fr] gap-2">
                  <dt className="text-muted">{titleCase(k)}</dt>
                  <dd className="min-w-0">
                    {f?.value ? (
                      <span title={f.source} className="font-medium">
                        {f.value}
                      </span>
                    ) : (
                      <span className="text-xs text-faint" title={f?.source}>
                        not in the files
                      </span>
                    )}
                    {f?.value && <div className="truncate text-[11px] text-faint">{f.source}</div>}
                  </dd>
                </div>
              );
            })}
          </dl>
        </Card>

        <Card title="How it was read" className="lg:col-span-1" bodyClass="py-3">
          <dl className="space-y-2 text-sm">
            <Row label="Vendor pack">
              {r.kb.vendor_pack}{" "}
              <span className="text-xs text-muted">
                · {r.detection.chosen_by}
                {r.detection.score !== null &&
                  ` (score ${r.detection.score} ≥ ${r.detection.min_score})`}
              </span>
            </Row>
            <Row label="Signatures">
              <span className="inline-flex items-center gap-1 text-xs text-muted">
                <Fingerprint className="size-3.5" /> {r.detection.signatures.join(", ") || "–"}
              </span>
            </Row>
            <Row label="Understood">
              {r.assurance.understood}/{r.assurance.statements} statements
            </Row>
            <Row label="File SHA-256">
              <span className="font-mono text-xs" title={r.input.sha256}>
                {shortHash(r.input.sha256, 16)}…
              </span>
            </Row>
            <Row label="Knowledge base">
              <span className="font-mono text-xs" title={r.kb.kb_version}>
                {shortHash(r.kb.kb_version, 16)}…
              </span>
            </Row>
            <Row label="Audit id">
              <span className="font-mono text-xs">{r.audit_id}</span>
            </Row>
          </dl>
        </Card>
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={(t) => setParams({ tab: t }, { replace: true })}
        tabs={[
          { id: "findings", label: "Findings", count: r.findings.length },
          { id: "controls", label: "Controls", count: r.controls.length },
          { id: "config", label: "Configuration" },
          { id: "policy", label: "Filtering policy", count: filterRules },
          { id: "model", label: "Security model", count: r.sbm.entities.length + 1 },
          { id: "coverage", label: "Coverage" },
        ]}
      />
      <div className={cx(tab !== "findings" && "hidden")}>
        <Findings result={r} onOpen={setOpen} />
      </div>
      {tab === "controls" && <Controls result={r} />}
      {tab === "config" && <Config result={r} onOpen={setOpen} />}
      {tab === "policy" && <Policy result={r} />}
      {tab === "model" && <Model result={r} />}
      {tab === "coverage" && <Coverage result={r} />}

      <Provenance finding={open} result={r} onClose={close} />
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[6.5rem_1fr] gap-2">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}
