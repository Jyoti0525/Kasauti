// The Training Studio (PLAN §11; R-03, R-05, R-08): teach Kasauti what a vendor's configuration
// lines mean, one pattern at a time. Nothing counts until it is approved; an approval changes the
// next audit with the server never restarted.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FileSearch, Lock, Trash2, Undo2, UserRound } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { api } from "../api/client";
import { may, useMe } from "../api/hooks";
import type {
  StudioDecision,
  StudioMeaning,
  StudioPattern,
  StudioProposal,
  StudioState,
  StudioTaught,
} from "../api/types";
import { Meter, VerdictBar, VerdictCounts } from "../components/charts";
import { DropZone, type Picked } from "../components/DropZone";
import {
  Button,
  Card,
  Chip,
  Empty,
  ErrorBox,
  Loading,
  Notice,
  PageHeader,
  cx,
} from "../components/ui";
import { ago, pct } from "../lib/format";
import { Preview, TeachCard } from "./studio/Teach";

export function Studio() {
  const queries = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const me = useMe().data;
  const [selected, setSelected] = useState<string | null>(null);
  const [adding, setAdding] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [deciding, setDeciding] = useState(false);

  const state = useQuery({
    queryKey: ["studio"],
    queryFn: () => api.get<StudioState>("/api/studio"),
  });
  const meanings = useQuery({
    queryKey: ["studio", "meanings"],
    queryFn: () => api.get<StudioMeaning[]>("/api/studio/meanings"),
    staleTime: Infinity,
  });
  const packs = state.data?.packs ?? [];
  const withFiles = packs.filter((p) => p.files > 0);
  const pack =
    params.get("pack") ??
    withFiles.find((p) => p.learning)?.id ??
    withFiles[0]?.id ??
    packs.find((p) => p.learning)?.id ??
    null;
  const current = packs.find((p) => p.id === pack);
  const version = state.data?.kb_version;

  const queue = useQuery({
    queryKey: ["studio", "queue", pack, version, state.data?.files.length],
    queryFn: () => api.get<StudioPattern[]>(`/api/studio/packs/${pack}/queue`),
    enabled: Boolean(pack && current && current.files > 0),
  });
  const taught = useQuery({
    queryKey: ["studio", "taught", pack, version],
    queryFn: () => api.get<StudioTaught[]>(`/api/studio/packs/${pack}/taught`),
    enabled: Boolean(pack),
  });
  const pending = useQuery({
    queryKey: ["studio", "proposals", version],
    queryFn: () => api.get<StudioProposal[]>("/api/studio/proposals"),
  });
  const decisions = useQuery({
    queryKey: ["studio", "decisions", version],
    queryFn: () => api.get<StudioDecision[]>("/api/studio/decisions"),
  });

  const refresh = async () => {
    await queries.invalidateQueries({ queryKey: ["studio"] });
    await queries.invalidateQueries({ queryKey: ["health"] });
    await queries.invalidateQueries({ queryKey: ["kb"] });
  };

  const add = async (picked: Picked[]) => {
    setError(null);
    for (const p of picked) {
      setAdding(p.name);
      try {
        await api.sendFile("/api/studio/files", p.file, p.name);
      } catch (e) {
        setError(e);
      }
    }
    setAdding(null);
    await refresh();
  };

  const items = queue.data ?? [];
  const chosen = items.find((p) => p.key === selected) ?? items[0];

  if (state.isPending || meanings.isPending) return <Loading what="Opening the Training Studio" />;
  if (state.isError) return <ErrorBox error={state.error} />;
  if (meanings.isError) return <ErrorBox error={meanings.error} />;
  const meaningLabel = (id: string) => meanings.data.find((m) => m.id === id)?.label ?? id;
  const s = state.data;
  const tally = current?.tally;

  return (
    <>
      <PageHeader
        title="Training Studio"
        subtitle="Teach Kasauti what a vendor's configuration lines mean, one pattern at a time. Nothing counts until it is approved; the next audit reads it, with the server never restarted."
        actions={
          me && (
            <span className="inline-flex items-center gap-1.5 text-[12.5px] text-muted">
              <UserRound className="size-3.5" aria-hidden />
              <span>
                Teaching as <strong className="font-medium text-text">{me.name}</strong>, {me.role}
              </span>
            </span>
          )
        }
      />

      {me && !may(me.role, "trainer") && (
        <div className="mb-6">
          <Notice icon={<Lock />}>
            You can see what Kasauti has been taught. Teaching it needs the trainer role, which an
            administrator gives.
          </Notice>
        </div>
      )}

      {me && (pending.data ?? []).length > 0 && (
        <Card
          className="mb-6 border-review/40"
          title="Waiting for approval"
          description="Lessons proposed and not yet decided. One that makes a check pass needs an approver other than the person who proposed it."
        >
          <div className="space-y-5">
            {(pending.data ?? []).map((p) => (
              <div key={p.id} className="rounded-lg border border-line p-4">
                <div className="mb-3 flex flex-wrap items-baseline gap-x-2 text-[13px]">
                  <PatternText text={p.pattern} />
                  <span className="text-muted">
                    as {meaningLabel(p.meaning)} · proposed by{" "}
                    <span className="capitalize">{p.proposed_by}</span>
                  </span>
                </div>
                <Preview
                  proposal={p}
                  me={me}
                  busy={deciding}
                  onDecide={async (how) => {
                    setDeciding(true);
                    setError(null);
                    try {
                      await api.post(`/api/studio/proposals/${p.id}/${how}`);
                      await refresh();
                    } catch (e) {
                      setError(e);
                    } finally {
                      setDeciding(false);
                    }
                  }}
                />
              </div>
            ))}
            {error !== null && <ErrorBox error={error} />}
          </div>
        </Card>
      )}

      <div className="mb-6 grid items-start gap-6 lg:grid-cols-12">
        <Card
          className="lg:col-span-7"
          title="What Kasauti reads"
          description="Across the configurations below, for the vendor being taught."
          action={
            <div className="flex flex-wrap justify-end gap-1.5" role="group" aria-label="Vendor">
              {packs
                .filter((p) => p.files > 0 || p.learning)
                .map((p) => (
                  <Chip
                    key={p.id}
                    active={p.id === pack}
                    onClick={() => {
                      setSelected(null);
                      setParams({ pack: p.id }, { replace: true });
                    }}
                  >
                    {p.name}
                  </Chip>
                ))}
            </div>
          }
        >
          {!current || !tally ? (
            <p className="text-[13.5px] text-muted">
              Add a configuration of this vendor to see what Kasauti reads of it.
            </p>
          ) : (
            <div className="grid gap-6 sm:grid-cols-2">
              <div>
                <div className="flex items-baseline justify-between">
                  <span className="text-[13px] font-medium text-muted">Lines understood</span>
                  <span className="figure text-[26px] font-semibold">
                    {pct(tally.statements ? (100 * tally.understood) / tally.statements : null, 0)}
                  </span>
                </div>
                <Meter
                  value={tally.statements ? (100 * tally.understood) / tally.statements : 0}
                  tone="data"
                  className="mt-2"
                />
                <p className="mt-2 text-[12.5px] text-muted">
                  {tally.understood} of {tally.statements} statements read by an approved mapping ·{" "}
                  {current.mappings} mapping{current.mappings === 1 ? "" : "s"}, {current.taught}{" "}
                  taught here
                </p>
              </div>
              <div>
                <span className="text-[13px] font-medium text-muted">Every check, by verdict</span>
                <VerdictBar
                  pass={tally.passed}
                  fail={tally.failed}
                  review={tally.review}
                  na={tally.not_applicable}
                  className="mt-3 h-2.5"
                />
                <div className="mt-3">
                  <VerdictCounts
                    counts={{
                      pass: tally.passed,
                      fail: tally.failed,
                      review: tally.review,
                      na: tally.not_applicable,
                    }}
                  />
                </div>
              </div>
            </div>
          )}
          {current?.learning && (
            <p className="mt-4 text-[12.5px] leading-relaxed text-faint">
              {current.name} is still being taught: a check that rests on something Kasauti can't
              read yet stays in review, never a guessed pass or fail.
            </p>
          )}
        </Card>

        <Card
          className="lg:col-span-5"
          title="Configurations to learn from"
          description="Kept in this server's memory only, never written to disk; gone when removed or when the server restarts."
        >
          {s.files.length > 0 && (
            <ul className="mb-4 divide-y divide-line rounded-lg border border-line">
              {s.files.map((f) => (
                <li key={f.id} className="flex items-center gap-3 px-3 py-2.5">
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13.5px] font-medium">{f.name}</div>
                    <div className="text-[12px] text-muted">
                      {packs.find((p) => p.id === f.pack)?.name ?? f.pack} ·{" "}
                      {pct(
                        f.tally.statements ? (100 * f.tally.understood) / f.tally.statements : null,
                        0,
                      )}{" "}
                      understood · added {ago(f.added)}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    title="Open it as a new audit, read with everything taught so far"
                    onClick={async () => {
                      try {
                        const r = await api.post<{ upload_id: string }>(
                          `/api/studio/files/${f.id}/audit`,
                        );
                        navigate(`/audits/new/${r.upload_id}`);
                      } catch (e) {
                        setError(e);
                      }
                    }}
                  >
                    <FileSearch /> Audit
                  </Button>
                  <Button
                    variant="ghost"
                    aria-label={`Remove ${f.name}`}
                    onClick={async () => {
                      await api.delete(`/api/studio/files/${f.id}`);
                      await refresh();
                    }}
                  >
                    <Trash2 />
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <DropZone
            onFiles={add}
            disabled={adding !== null}
            hint="Running configurations of the vendor to teach; it's recognised from each file."
          />
          {adding && <p className="mt-2 text-[12.5px] text-muted">Reading {adding}…</p>}
          {error !== null && (
            <div className="mt-3">
              <ErrorBox error={error} />
            </div>
          )}
        </Card>
      </div>

      {current && current.files > 0 && (
        <div className="mb-8 grid items-start gap-6 lg:grid-cols-12">
          <Card
            className="lg:col-span-5"
            bodyClass="p-0"
            title="To teach"
            description="Patterns the pack doesn't read yet, the likeliest to matter first."
          >
            {queue.isPending ? (
              <Loading what="Reading the configurations" />
            ) : items.length === 0 ? (
              <Empty title="Every line is read">Nothing left to teach in these files.</Empty>
            ) : (
              <ol className="max-h-[42rem] divide-y divide-line overflow-y-auto border-t border-line">
                {items.map((p) => (
                  <li key={p.key}>
                    <QueueRow
                      item={p}
                      active={p.key === chosen?.key}
                      onClick={() => setSelected(p.key)}
                    />
                  </li>
                ))}
              </ol>
            )}
          </Card>
          <div className="lg:col-span-7">
            {chosen && meanings.data ? (
              <TeachCard
                key={`${chosen.key}:${version}`}
                item={chosen}
                pack={pack ?? ""}
                meanings={meanings.data}
                me={me}
                onDone={async () => {
                  setSelected(null);
                  await refresh();
                }}
              />
            ) : null}
          </div>
        </div>
      )}

      {current && (
        <div className="grid gap-6 lg:grid-cols-12">
          <Card
            className="lg:col-span-7"
            title="Taught so far"
            description="Stored in the data folder with who proposed and who approved each; every later audit reads them."
          >
            {(taught.data ?? []).length === 0 ? (
              <p className="text-[13.5px] text-muted">Nothing taught for {current.name} yet.</p>
            ) : (
              <ul className="divide-y divide-line">
                {(taught.data ?? []).map((m) => (
                  <li key={m.id} className="flex items-center gap-3 py-2.5">
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-[12.5px]">
                        {m.context.length > 0 && (
                          <span className="text-faint">{m.context.join(" › ")} › </span>
                        )}
                        {m.match}
                      </div>
                      <div className="text-[12px] text-muted">
                        proposed by {person(m.proposed_by)} · approved by{" "}
                        {m.approved_by.map(person).join(", ")}
                      </div>
                    </div>
                    <Button
                      variant="ghost"
                      title="Take it back out; later audits no longer read what it read"
                      onClick={async () => {
                        try {
                          await api.delete(`/api/studio/packs/${pack}/taught/${m.id}`);
                          await refresh();
                        } catch (e) {
                          setError(e);
                        }
                      }}
                    >
                      <Undo2 /> Undo
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card className="lg:col-span-5" title="Decisions" description="The Studio's record.">
            <DecisionLog decisions={decisions.data ?? []} />
          </Card>
        </div>
      )}
    </>
  );
}

function QueueRow({
  item,
  active,
  onClick,
}: {
  item: StudioPattern;
  active: boolean;
  onClick: () => void;
}) {
  const top = item.suggestions[0];
  const locked = item.block !== null && !item.block_taught;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active}
      className={cx(
        "block w-full px-5 py-3 text-left transition-colors",
        active ? "bg-brass-soft/70" : "hover:bg-surface-2",
      )}
    >
      {item.block && (
        <div className="mb-0.5 truncate font-mono text-[11.5px] text-faint">
          {item.block} <span aria-hidden>›</span>
        </div>
      )}
      <div className="flex items-start justify-between gap-3">
        <PatternText text={item.pattern} />
        <span className="shrink-0 rounded-full bg-surface-3 px-1.5 text-[11.5px] tabular-nums text-muted">
          {item.count}
        </span>
      </div>
      <div className="mt-1 flex items-center gap-1.5 text-[12px] text-muted">
        {locked ? (
          <>
            <Lock className="size-3" /> Teach its block's line first
          </>
        ) : top ? (
          <>Looks like: {top.label.toLowerCase()}</>
        ) : (
          <span className="text-faint">No suggestion</span>
        )}
      </div>
    </button>
  );
}

/** A pattern with its value slots (`<INT>`, `<IP>`…) set apart from the vendor's own words. */
export function PatternText({ text, className }: { text: string; className?: string }) {
  const parts = useMemo(() => text.split(/(<[A-Z]+>)/), [text]);
  return (
    <span className={cx("min-w-0 break-words font-mono text-[13px]", className)}>
      {parts.map((p, i) =>
        /^<[A-Z]+>$/.test(p) ? (
          <span key={i} className="rounded bg-surface-3 px-1 text-[11.5px] text-muted">
            {p.slice(1, -1).toLowerCase()}
          </span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </span>
  );
}

const ACTION: Record<StudioDecision["action"], string> = {
  propose: "proposed",
  approve: "approved",
  reject: "rejected",
  ignore: "ignored",
  undo: "took back",
};

function DecisionLog({ decisions }: { decisions: StudioDecision[] }) {
  if (!decisions.length) return <p className="text-[13.5px] text-muted">No decision yet.</p>;
  return (
    <ol className="max-h-72 space-y-2 overflow-y-auto text-[12.5px]">
      {decisions.slice(0, 40).map((d, i) => (
        <li key={i} className="flex gap-2">
          <span className="w-16 shrink-0 text-faint">{ago(d.at)}</span>
          <span className="min-w-0">
            <span className="font-medium capitalize">{d.by}</span> {ACTION[d.action]}{" "}
            <span className="break-all font-mono text-[11.5px] text-muted">
              {d.line ?? d.pattern ?? "a line"}
            </span>
            {d.action === "approve" && d.proposed_by && d.proposed_by !== d.by && (
              <span className="text-muted"> (proposed by {d.proposed_by}; second approver)</span>
            )}
          </span>
        </li>
      ))}
    </ol>
  );
}

/** "trainer:asha" → "asha": the role is shown beside the account, not in its name. */
function person(recorded: string): string {
  return recorded.replace(/^[a-z]+:/, "");
}
