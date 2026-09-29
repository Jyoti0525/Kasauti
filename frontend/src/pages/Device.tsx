import { Download, FileJson, GraduationCap } from "lucide-react";
import { useCallback, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import { useAudits, useKb, usePackName, useResult } from "../api/hooks";
import type { Finding } from "../api/types";
import { Posture } from "../components/charts";
import {
  Card,
  ErrorBox,
  LinkButton,
  Loading,
  Notice,
  PageHeader,
  Tabs,
  Tag,
  cx,
  type Crumb,
} from "../components/ui";
import { failedBySeverity } from "../lib/fleet";
import { shortHash, sourceLabel, titleCase } from "../lib/format";
import { Config } from "./device/Config";
import { Findings } from "./device/Findings";
import { Fixes } from "./device/Fixes";
import { Model } from "./device/Model";
import { Provenance } from "./device/Provenance";
import { Controls, Coverage, FrameworkScores, Policy } from "./device/Tabs";

type Tab = "findings" | "fixes" | "controls" | "config" | "policy" | "model" | "coverage";

const IDENTITY = ["hostname", "vendor", "os_version", "model", "serial", "hardware"];

export function DevicePage() {
  const { jobId } = useParams();
  const result = useResult(jobId);
  const audits = useAudits();
  const packName = usePackName();
  const kb = useKb();
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
  const os = r.identity.os_version?.value;
  const filterRules = r.sbm.entities.filter((e) => e.type === "FilterRule").length;
  const crumbs: Crumb[] = [{ label: "Audits", to: "/audits" }];
  if (audit)
    crumbs.push({ label: audit.label ?? "Untitled audit", to: `/uploads/${audit.upload_id}` });

  return (
    <>
      <PageHeader
        crumbs={crumbs}
        title={hostname ?? r.input.file}
        meta={
          <>
            <span className="font-medium text-text">
              {packName(r.detection.pack_id)}
              {os && <span className="font-normal text-muted"> {os}</span>}
            </span>
            <Tag>{r.input.file}</Tag>
          </>
        }
        actions={
          <>
            <LinkButton
              href={`/api/jobs/${jobId}/result`}
              download={`${(hostname ?? r.input.file).replace(/[^A-Za-z0-9._-]+/g, "_")}.kasauti.json`}
            >
              <FileJson /> JSON
            </LinkButton>
            <LinkButton href={`/api/jobs/${jobId}/report.pdf`} download variant="primary">
              <Download /> PDF report
            </LinkButton>
          </>
        }
      />

      <Posture
        framework={score?.title ?? "NIST SP 800-53 Rev. 5"}
        compliance={score?.compliance_pct ?? null}
        coverage={score?.coverage_pct ?? null}
        counts={{
          pass: counts("PASS"),
          fail: counts("FAIL"),
          review: counts("REVIEW"),
          na: counts("N/A"),
        }}
        severity={failedBySeverity(r)}
        understood={r.assurance.understood_pct}
        scope="on this device, judged against Kasauti's model of its configuration"
      />
      {kb.data?.vendors.find((v) => v.id === r.detection.pack_id)?.learning && (
        <div className="mb-6">
          <Notice icon={<GraduationCap />}>
            {packName(r.detection.pack_id)} is still being taught: Kasauti reads{" "}
            {r.assurance.understood} of {r.assurance.statements} statements of this file, and a
            check that rests on something it can't read yet stays in review.{" "}
            <Link
              to={`/studio?pack=${r.detection.pack_id}`}
              className="font-medium text-text underline"
            >
              Teach it in the Training Studio
            </Link>
          </Notice>
        </div>
      )}
      <FrameworkScores result={r} />

      <div className="mb-8 grid gap-6 lg:grid-cols-12">
        <Card
          title="Identity"
          description="What the files say this device is, and where each value came from."
          className="lg:col-span-7"
        >
          <dl className="grid gap-x-8 gap-y-4 sm:grid-cols-2">
            {IDENTITY.map((k) => {
              const f = r.identity[k];
              return (
                <div key={k} className="min-w-0">
                  <dt className="text-[12px] font-medium text-muted">{titleCase(k)}</dt>
                  <dd className="mt-0.5">
                    {f?.value ? (
                      <>
                        <div className="truncate font-semibold">{f.value}</div>
                        <div className="truncate text-[12px] text-faint" title={f.source}>
                          {sourceLabel(f.source)}
                        </div>
                      </>
                    ) : (
                      <div className="text-[13px] text-faint" title={f?.source}>
                        Not in the files
                      </div>
                    )}
                  </dd>
                </div>
              );
            })}
          </dl>
        </Card>

        <Card
          title="How it was read"
          description="Enough to reproduce this audit exactly."
          className="lg:col-span-5"
        >
          <dl className="space-y-3 text-[13.5px]">
            <Row label="Vendor pack">
              <span className="font-medium">{r.kb.vendor_pack.replace("@", " v")}</span>
              <span className="text-muted">
                {" "}
                · {r.detection.chosen_by}
                {r.detection.score !== null &&
                  `, score ${r.detection.score} (threshold ${r.detection.min_score})`}
              </span>
            </Row>
            <Row label="Recognised by">
              <span className="flex flex-wrap gap-1">
                {r.detection.signatures.length
                  ? r.detection.signatures.map((s) => <Tag key={s}>{s}</Tag>)
                  : "–"}
              </span>
            </Row>
            <Row label="Understood">
              <span className="figure">
                {r.assurance.understood} of {r.assurance.statements} statements
              </span>
            </Row>
            <Row label="File SHA-256">
              <span className="font-mono text-[12.5px]" title={r.input.sha256}>
                {shortHash(r.input.sha256, 16)}…
              </span>
            </Row>
            <Row label="Knowledge base">
              <span className="font-mono text-[12.5px]" title={r.kb.kb_version}>
                {shortHash(r.kb.kb_version, 16)}…
              </span>
            </Row>
            <Row label="Audit id">
              <span className="font-mono text-[12.5px]">{r.audit_id}</span>
            </Row>
          </dl>
        </Card>
      </div>

      <Tabs<Tab>
        value={tab}
        onChange={(t) => setParams({ tab: t }, { replace: true })}
        tabs={[
          { id: "findings", label: "Findings", count: r.findings.length },
          { id: "fixes", label: "Fixes", count: r.remediation?.fixes.length ?? 0 },
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
      {tab === "fixes" && (
        <Fixes key={params.get("fix") ?? ""} result={r} focus={params.get("fix")} />
      )}
      {tab === "controls" && (
        <Controls
          result={r}
          framework={params.get("fw")}
          onFramework={(f) => setParams({ tab: "controls", fw: f }, { replace: true })}
        />
      )}
      {tab === "config" && <Config result={r} onOpen={setOpen} />}
      {tab === "policy" && <Policy result={r} />}
      {tab === "model" && <Model result={r} />}
      {tab === "coverage" && <Coverage result={r} />}

      <Provenance
        finding={open}
        result={r}
        onClose={close}
        onFix={(ruleId) => {
          setOpen(null);
          setParams({ tab: "fixes", fix: ruleId }, { replace: true });
          window.setTimeout(
            () => document.getElementById(`fix-${ruleId}`)?.scrollIntoView({ block: "start" }),
            50,
          );
        }}
      />
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[7.5rem_1fr] gap-3">
      <dt className="text-muted">{label}</dt>
      <dd className="min-w-0 wrap-break-word">{children}</dd>
    </div>
  );
}
