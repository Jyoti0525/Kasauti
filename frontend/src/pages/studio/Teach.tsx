// One pattern being taught: its lines, which words are values, what it means, and the preview
// of what approving it would change (PLAN §11.1 steps 2-6).

import { ArrowRight, Check, Clock, EyeOff, ShieldAlert, X } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../../api/client";
import { may } from "../../api/hooks";
import type {
  Me,
  SlotType,
  StudioMeaning,
  StudioPattern,
  StudioProposal,
  StudioSuggestion,
} from "../../api/types";
import { Button, Card, ErrorBox, Notice, StatusBadge, cx } from "../../components/ui";

interface Word {
  text: string;
  slot: SlotType | null;
  role: string | null;
}

const SLOT_LABEL: Record<SlotType, string> = {
  INT: "number",
  IP: "address",
  IFNAME: "interface",
  STR: "name",
  LIST: "rest of line",
};

/** The pattern's words, with the suggestion's roles. A role on a plain word (a description's
 * first word) makes it the value that role takes: the rest of the line, for free text. */
function initialWords(
  item: StudioPattern,
  suggestion: StudioSuggestion | undefined,
  meaning: StudioMeaning | undefined,
): Word[] {
  return item.tokens.map((t, i) => {
    const role = suggestion?.roles[String(i)] ?? null;
    const types = meaning?.roles.find((r) => r.name === role)?.types ?? [];
    const slot = t.slot ?? (role ? (types.includes("LIST") ? "LIST" : (types[0] ?? null)) : null);
    return { text: t.text, slot, role };
  });
}

/** Index of the rest-of-line value, if any: the words after it belong to it. */
function restFrom(words: Word[]): number {
  const i = words.findIndex((w) => w.slot === "LIST");
  return i < 0 ? words.length : i;
}

function valueType(text: string): SlotType {
  return /^\d+$/.test(text) ? "INT" : "STR";
}

export function TeachCard({
  item,
  pack,
  meanings,
  me,
  onDone,
}: {
  item: StudioPattern;
  pack: string;
  meanings: StudioMeaning[];
  me: Me | null | undefined;
  onDone: () => Promise<void>;
}) {
  const top = item.suggestions[0];
  const [meaningId, setMeaningId] = useState<string | null>(top?.meaning ?? null);
  const [words, setWords] = useState<Word[]>(() =>
    initialWords(
      item,
      top,
      meanings.find((m) => m.id === top?.meaning),
    ),
  );
  const [choices, setChoices] = useState<Record<string, string | string[]>>(top?.choices ?? {});
  const [proposal, setProposal] = useState<StudioProposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const meaning = meanings.find((m) => m.id === meaningId) ?? null;
  const suggested = new Set(item.suggestions.map((s) => s.meaning));
  const others = useMemo(
    () =>
      meanings.filter((m) => !suggested.has(m.id)).sort((a, b) => a.label.localeCompare(b.label)),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [meanings, item.key],
  );
  const locked = item.block !== null && !item.block_taught;

  const changed = () => {
    setProposal(null);
    setError(null);
  };
  const pick = (id: string) => {
    const s = item.suggestions.find((x) => x.meaning === id);
    setMeaningId(id);
    setChoices(s?.choices ?? {});
    const m = meanings.find((x) => x.id === id);
    setWords(
      s ? initialWords(item, s, m) : (ws) => ws.map((w, i) => ({ ...w, role: autoRole(m, ws, i) })),
    );
    changed();
  };
  const toggle = (i: number) => {
    setWords((ws) =>
      ws.map((w, j) => {
        if (j !== i || w.text.includes("*")) return w; // a masked secret is always a value
        return w.slot ? { ...w, slot: null, role: null } : { ...w, slot: valueType(w.text) };
      }),
    );
    changed();
  };
  const setSlot = (i: number, slot: SlotType) => {
    setWords((ws) => ws.map((w, j) => (j === i ? { ...w, slot } : w)));
    changed();
  };
  const setRole = (i: number, role: string | null) => {
    setWords((ws) =>
      ws.map((w, j) =>
        j === i ? { ...w, role } : w.role === role && role ? { ...w, role: null } : w,
      ),
    );
    changed();
  };

  const preview = async () => {
    if (!meaning) return;
    setBusy(true);
    setError(null);
    try {
      setProposal(
        await api.post<StudioProposal>("/api/studio/proposals", {
          pack,
          key: item.key,
          meaning: meaning.id,
          tokens: words,
          choices,
        }),
      );
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const decide = async (how: "approve" | "reject") => {
    if (!proposal) return;
    setBusy(true);
    setError(null);
    try {
      await api.post(`/api/studio/proposals/${proposal.id}/${how}`);
      await onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const ignore = async () => {
    setBusy(true);
    try {
      await api.post("/api/studio/ignore", { pack, key: item.key });
      await onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card
      title="Teach this pattern"
      description={`Seen ${item.count} time${item.count === 1 ? "" : "s"} in ${item.files} file${item.files === 1 ? "" : "s"}.`}
      action={
        <Button variant="ghost" onClick={ignore} disabled={busy} title="Not security-relevant">
          <EyeOff /> Ignore
        </Button>
      }
    >
      <ol className="space-y-6">
        <Step n={1} title="The lines">
          <div className="overflow-x-auto rounded-lg bg-basalt px-4 py-3 font-mono text-[12.5px] leading-6 text-[#f1ede2] ring-1 ring-basalt-line">
            {item.examples.map((e, i) => (
              <div key={i} className="whitespace-pre">
                <span className="mr-3 inline-block w-28 select-none truncate align-bottom text-[11px] text-[#8f8a7d]">
                  {e.file}:{e.line}
                </span>
                {e.block && <span className="text-[#8f8a7d]">{e.block} › </span>}
                {e.text}
              </div>
            ))}
          </div>
          {locked && (
            <div className="mt-3">
              <Notice icon={<ShieldAlert />}>
                These lines sit inside <code className="font-mono">{item.block}</code>, which isn't
                taught yet. Teach that block's own line first: what these lines set belongs to it.
              </Notice>
            </div>
          )}
        </Step>

        <Step
          n={2}
          title="Which words are values"
          hint="Click a word to switch it between a fixed word and a value that changes from device to device."
        >
          <div className="flex flex-wrap items-start gap-2">
            {words.map((w, i) => {
              const rest = restFrom(words);
              // A rest-of-line value is one group: the words after it sit beside it, and its
              // selects under the whole phrase rather than pushing those words away.
              if (i > rest) return null;
              const tail = i === rest ? words.slice(i + 1) : [];
              return (
                <div key={i} className="flex flex-col items-start gap-1">
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => toggle(i)}
                      aria-pressed={w.slot !== null}
                      className={cx(
                        "h-8 rounded-md border px-2.5 font-mono text-[13px] transition-colors",
                        w.slot
                          ? "border-brass/60 bg-brass-soft text-text"
                          : "border-line-strong/70 bg-surface hover:bg-surface-2",
                      )}
                    >
                      {w.text}
                    </button>
                    {tail.map((t, j) => (
                      <button
                        key={j}
                        type="button"
                        disabled
                        title="Part of the value before it"
                        className="h-8 rounded-md border border-dashed border-brass/60 bg-brass-soft px-2.5 font-mono text-[13px] text-text opacity-70"
                      >
                        {t.text}
                      </button>
                    ))}
                  </div>
                  {w.slot && (
                    <span className="flex items-center gap-1 text-[11px] text-muted">
                      <select
                        aria-label={`Kind of value ${w.text} is`}
                        value={w.slot}
                        onChange={(e) => setSlot(i, e.target.value as SlotType)}
                        disabled={w.text.includes("*")}
                        className="rounded border border-line bg-surface px-1 text-[11px]"
                      >
                        {(Object.keys(SLOT_LABEL) as SlotType[]).map((k) => (
                          <option key={k} value={k}>
                            {SLOT_LABEL[k]}
                          </option>
                        ))}
                      </select>
                      {meaning && meaning.roles.length > 0 && (
                        <select
                          aria-label={`What ${w.text} is`}
                          value={w.role ?? ""}
                          onChange={(e) => setRole(i, e.target.value || null)}
                          className="rounded border border-line bg-surface px-1 text-[11px]"
                        >
                          <option value="">not used</option>
                          {meaning.roles
                            .filter((r) => r.types.includes(w.slot as SlotType))
                            .map((r) => (
                              <option key={r.name} value={r.name}>
                                {r.label}
                              </option>
                            ))}
                        </select>
                      )}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </Step>

        <Step n={3} title="What it means">
          <div className="grid gap-2">
            {item.suggestions.map((s) => (
              <label
                key={s.meaning}
                className={cx(
                  "flex cursor-pointer items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors",
                  meaningId === s.meaning
                    ? "border-brass/60 bg-brass-soft/60"
                    : "border-line-strong/70 hover:bg-surface-2",
                )}
              >
                <input
                  type="radio"
                  name={`meaning-${item.key}`}
                  checked={meaningId === s.meaning}
                  onChange={() => pick(s.meaning)}
                  className="mt-1 accent-brass"
                />
                <span className="min-w-0">
                  <span className="text-[13.5px] font-medium">{s.label}</span>
                  <span className="mt-0.5 block text-[12px] text-muted">Suggested: {s.why}</span>
                </span>
              </label>
            ))}
          </div>
          <select
            aria-label="Another meaning"
            value={meaningId && !suggested.has(meaningId) ? meaningId : ""}
            onChange={(e) => e.target.value && pick(e.target.value)}
            className="field mt-2"
          >
            <option value="">
              {item.suggestions.length ? "Something else…" : "Choose a meaning…"}
            </option>
            {others.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
          {meaning && <p className="mt-2 text-[12.5px] text-muted">{meaning.explain}</p>}
          {meaning?.choices.map((c) => (
            <div key={c.name} className="mt-3">
              <div className="mb-1.5 text-[12px] font-medium capitalize text-muted">
                {c.name}
                {c.many && " (all that apply)"}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {c.options.map((o) => {
                  const cur = choices[c.name];
                  const on = Array.isArray(cur) ? cur.includes(o) : cur === o;
                  return (
                    <button
                      key={o}
                      type="button"
                      aria-pressed={on}
                      onClick={() => {
                        setChoices((prev) => {
                          if (!c.many) return { ...prev, [c.name]: o };
                          const list = Array.isArray(prev[c.name])
                            ? (prev[c.name] as string[])
                            : [];
                          return {
                            ...prev,
                            [c.name]: on ? list.filter((x) => x !== o) : [...list, o],
                          };
                        });
                        changed();
                      }}
                      className={cx(
                        "h-7 rounded-full border px-3 font-mono text-[12px] transition-colors",
                        on
                          ? "border-text bg-text text-surface"
                          : "border-line-strong/70 text-muted hover:text-text",
                      )}
                    >
                      {o}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </Step>

        <Step n={4} title="What approving it would change">
          {!proposal ? (
            <Button variant="primary" onClick={preview} disabled={!meaning || busy || locked}>
              Preview the change
            </Button>
          ) : (
            <Preview proposal={proposal} me={me} busy={busy} onDecide={decide} onLeave={onDone} />
          )}
          {error !== null && (
            <div className="mt-3">
              <ErrorBox error={error} />
            </div>
          )}
        </Step>
      </ol>
    </Card>
  );
}

/** The first role of the meaning this value's type fits, after earlier values took theirs. */
function autoRole(meaning: StudioMeaning | undefined, words: Word[], i: number): string | null {
  const slot = words[i]?.slot;
  if (!meaning || !slot) return null;
  const taken = new Set<string>();
  for (const w of words.slice(0, i)) {
    const s = w.slot;
    const r = s ? meaning.roles.find((x) => !taken.has(x.name) && x.types.includes(s)) : undefined;
    if (r) taken.add(r.name);
  }
  return meaning.roles.find((r) => !taken.has(r.name) && r.types.includes(slot))?.name ?? null;
}

function Step({
  n,
  title,
  hint,
  children,
}: {
  n: number;
  title: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <li className="grid grid-cols-[1.75rem_1fr] gap-3">
      <span className="flex size-7 items-center justify-center rounded-full border border-line-strong/70 text-[12px] font-semibold tabular-nums text-muted">
        {n}
      </span>
      <div className="min-w-0 pt-0.5">
        <div className="text-[13.5px] font-semibold">{title}</div>
        {hint && <p className="mt-0.5 text-[12.5px] text-muted">{hint}</p>}
        <div className="mt-2.5">{children}</div>
      </div>
    </li>
  );
}

/** What a proposal would change, and the decision on it. Shown after proposing, and to anyone
 * who signs in while it waits for approval. */
export function Preview({
  proposal,
  me,
  busy,
  onDecide,
  onLeave,
}: {
  proposal: StudioProposal;
  me: Me | null | undefined;
  busy: boolean;
  onDecide: (how: "approve" | "reject") => void;
  /** Leave it waiting for an approver (when this person may not approve it). */
  onLeave?: () => void;
}) {
  const i = proposal.impact;
  const own = proposal.proposed_by === me?.username;
  const approver = may(me?.role, "approver");
  const blocked = !may(me?.role, "trainer") || (proposal.needs_second && (own || !approver));
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <Figure
          label="Lines read"
          value={`${i.lines}`}
          note={`in ${i.files} file${i.files === 1 ? "" : "s"}`}
        />
        <Figure
          label="Understood"
          value={`${i.understood_before} → ${i.understood_after}`}
          note={`of ${i.statements} statements`}
        />
        <Figure label="Checks changed" value={`${i.flips.length}`} note={`${i.to_pass} to pass`} />
      </div>
      {i.flips.length > 0 && (
        <table className="data">
          <thead>
            <tr>
              <th>Check</th>
              <th>File</th>
              <th className="w-56">Verdict</th>
            </tr>
          </thead>
          <tbody>
            {i.flips.map((f, k) => (
              <tr key={k}>
                <td>
                  <div className="text-[13px]">{f.title}</div>
                  <div className="font-mono text-[11px] text-faint">{f.rule}</div>
                </td>
                <td className="font-mono text-[12px]">{f.file}</td>
                <td>
                  <span className="inline-flex items-center gap-1.5">
                    <StatusBadge status={f.before} />
                    <ArrowRight className="size-3.5 text-faint" />
                    <StatusBadge status={f.after} />
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <details className="rounded-lg border border-line">
        <summary className="cursor-pointer px-3 py-2 text-[12.5px] font-medium text-muted">
          The mapping, exactly as it will be stored
        </summary>
        <pre className="overflow-x-auto border-t border-line bg-surface-2 px-3 py-2 font-mono text-[12px] leading-5">
          {proposal.mapping}
        </pre>
      </details>
      {proposal.needs_second && (
        <Notice icon={<ShieldAlert />}>
          This makes {i.to_pass} check{i.to_pass === 1 ? "" : "s"} pass, so an approver other than{" "}
          <strong className="capitalize">{proposal.proposed_by}</strong>, who proposed it, must
          approve it (four-eyes).
          {own && " It waits under Waiting for approval until an approver signs in."}
          {!own && !approver && ` You are a ${me?.role ?? "guest"}, not an approver.`}
        </Notice>
      )}
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" onClick={() => onDecide("approve")} disabled={busy || blocked}>
          <Check /> Approve as {me?.name ?? "…"}
        </Button>
        {blocked && onLeave && may(me?.role, "trainer") ? (
          <Button onClick={onLeave} disabled={busy}>
            <Clock /> Leave it for an approver
          </Button>
        ) : null}
        <Button onClick={() => onDecide("reject")} disabled={busy || !may(me?.role, "trainer")}>
          <X /> Reject
        </Button>
      </div>
    </div>
  );
}

function Figure({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="rounded-lg border border-line px-3 py-2.5">
      <div className="text-[12px] text-muted">{label}</div>
      <div className="figure mt-0.5 text-[20px] font-semibold">{value}</div>
      <div className="text-[11.5px] text-faint">{note}</div>
    </div>
  );
}
