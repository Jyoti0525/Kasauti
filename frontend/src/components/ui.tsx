import { AlertTriangle, Check, ChevronRight, Eye, Loader2, Minus, Search, X } from "lucide-react";
import { useEffect, type ReactNode } from "react";
import { Link } from "react-router";
import type { ControlStatus, JobState, Severity, Status } from "../api/types";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

// Verdicts: a hue and a shape each, so none is read by colour alone.
const STATUS: Record<Status, { cls: string; icon: ReactNode; label: string }> = {
  PASS: { cls: "bg-pass-soft text-pass", icon: <Check />, label: "Pass" },
  FAIL: { cls: "bg-fail-soft text-fail", icon: <X />, label: "Fail" },
  REVIEW: { cls: "bg-review-soft text-review", icon: <Eye />, label: "Review" },
  "N/A": { cls: "bg-na-soft text-na", icon: <Minus />, label: "N/A" },
};

export function StatusBadge({ status }: { status: Status }) {
  const s = STATUS[status];
  return (
    <span
      className={cx(
        "inline-flex h-6 min-w-[4.5rem] items-center gap-1 rounded-md px-2 text-[12px] font-semibold [&>svg]:size-3.5 [&>svg]:stroke-[2.75]",
        s.cls,
      )}
    >
      {s.icon}
      {s.label}
    </span>
  );
}

export const SEVERITY_LEVEL: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
export const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

/** Four rising bars, as many lit as the severity is high. */
export function SeverityGlyph({ severity, className }: { severity: Severity; className?: string }) {
  const lit = SEVERITY_LEVEL[severity];
  return (
    <svg viewBox="0 0 14 12" className={cx("h-3 w-3.5", className)} aria-hidden>
      {[0, 1, 2, 3].map((i) => (
        <rect
          key={i}
          x={i * 3.6}
          y={9 - i * 3}
          width="2.6"
          height={3 + i * 3}
          rx="0.8"
          className={i < lit ? "fill-current" : "fill-line-strong"}
        />
      ))}
    </svg>
  );
}

export function SeverityBadge({ severity }: { severity: Severity | null }) {
  if (!severity) return <span className="text-faint">–</span>;
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 text-[13px] font-medium capitalize",
        SEVERITY_TEXT[severity],
      )}
    >
      <SeverityGlyph severity={severity} />
      {severity}
    </span>
  );
}

const CONTROL: Record<ControlStatus, { cls: string; icon: ReactNode }> = {
  satisfied: { cls: "bg-pass-soft text-pass", icon: <Check /> },
  "partially satisfied": { cls: "bg-review-soft text-review", icon: <Eye /> },
  "not satisfied": { cls: "bg-fail-soft text-fail", icon: <X /> },
  undetermined: { cls: "bg-review-soft text-review", icon: <Eye /> },
  "not applicable": { cls: "bg-na-soft text-na", icon: <Minus /> },
};

export function ControlBadge({ status }: { status: ControlStatus }) {
  const c = CONTROL[status];
  return (
    <span
      className={cx(
        "inline-flex h-6 items-center gap-1 rounded-md px-2 text-[12px] font-semibold first-letter:uppercase [&>svg]:size-3.5 [&>svg]:stroke-[2.75]",
        c.cls,
      )}
    >
      {c.icon}
      {status}
    </span>
  );
}

const JOB: Record<JobState, { dot: string; label: string }> = {
  queued: { dot: "bg-na", label: "Queued" },
  running: { dot: "bg-brass", label: "Auditing" },
  succeeded: { dot: "bg-pass", label: "Done" },
  failed: { dot: "bg-fail", label: "Failed" },
  cancelled: { dot: "bg-na", label: "Cancelled" },
};

export function JobBadge({ state }: { state: JobState }) {
  const j = JOB[state];
  return (
    <span className="inline-flex items-center gap-1.5 text-[12.5px] text-muted">
      {state === "running" ? (
        <Loader2 className="size-3.5 animate-spin text-brass" aria-hidden />
      ) : (
        <span className={cx("size-2 rounded-full", j.dot)} aria-hidden />
      )}
      {j.label}
    </span>
  );
}

export function Card({
  title,
  description,
  action,
  children,
  className,
  bodyClass,
}: {
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
}) {
  return (
    <section className={cx("rounded-xl border border-line bg-surface", className)}>
      {(title || action) && (
        <header className="flex items-start justify-between gap-3 px-5 pb-3 pt-4">
          <div className="min-w-0">
            <h2 className="text-[14.5px] font-semibold tracking-[-0.005em]">{title}</h2>
            {description && <p className="mt-0.5 text-[13px] text-muted">{description}</p>}
          </div>
          {action}
        </header>
      )}
      <div className={bodyClass ?? (title || action ? "px-5 pb-5" : "p-5")}>{children}</div>
    </section>
  );
}

export interface Crumb {
  label: ReactNode;
  to?: string;
}

export function PageHeader({
  title,
  subtitle,
  actions,
  crumbs,
  meta,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  crumbs?: Crumb[];
  meta?: ReactNode;
}) {
  const tabTitle = typeof title === "string" ? `${title} · Kasauti` : "Kasauti";
  useEffect(() => {
    document.title = tabTitle;
  }, [tabTitle]);
  return (
    <div className="mb-7">
      {crumbs && crumbs.length > 0 && (
        <nav aria-label="Breadcrumb" className="mb-2 flex items-center gap-1 text-[13px]">
          {crumbs.map((c, i) => (
            <span key={i} className="inline-flex items-center gap-1">
              {c.to ? (
                <Link to={c.to} className="text-muted hover:text-text">
                  {c.label}
                </Link>
              ) : (
                <span className="text-muted">{c.label}</span>
              )}
              <ChevronRight className="size-3.5 text-faint" aria-hidden />
            </span>
          ))}
        </nav>
      )}
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <h1 className="truncate text-[26px] font-semibold leading-tight tracking-[-0.02em]">
            {title}
          </h1>
          {subtitle && <p className="mt-1.5 max-w-3xl text-[14px] text-muted">{subtitle}</p>}
          {meta && (
            <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-[13px] text-muted">
              {meta}
            </div>
          )}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return (
    <div className="flex items-center gap-2 px-1 py-10 text-sm text-muted" role="status">
      <Loader2 className="size-4 animate-spin text-brass" aria-hidden /> {what}…
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div
      role="alert"
      className="flex items-start gap-2.5 rounded-lg border border-fail/25 bg-fail-soft px-4 py-3 text-sm text-fail"
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>{message}</span>
    </div>
  );
}

export function Notice({ icon, children }: { icon?: ReactNode; children: ReactNode }) {
  return (
    <div className="flex items-start gap-2.5 rounded-lg border border-line bg-surface-2 px-4 py-3 text-[13px] leading-relaxed text-muted [&>svg]:mt-0.5 [&>svg]:size-4 [&>svg]:shrink-0">
      {icon}
      <div>{children}</div>
    </div>
  );
}

export function Empty({
  icon,
  title,
  children,
}: {
  icon?: ReactNode;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      {icon && (
        <div className="mb-1 flex size-12 items-center justify-center rounded-full bg-surface-3 text-muted [&>svg]:size-6">
          {icon}
        </div>
      )}
      <div className="font-semibold">{title}</div>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

const BUTTON = {
  primary:
    "bg-brass text-on-brass font-semibold shadow-[inset_0_1px_0_rgba(255,255,255,0.25),0_1px_2px_rgba(0,0,0,0.08)] hover:brightness-105",
  secondary: "border border-line-strong/70 bg-surface text-text hover:bg-surface-2",
  ghost: "text-muted hover:bg-surface-3 hover:text-text",
  danger: "border border-line-strong/70 bg-surface text-fail hover:bg-fail-soft",
};
const BUTTON_BASE =
  "inline-flex h-9 items-center justify-center gap-1.5 rounded-lg px-3.5 text-[13.5px] font-medium transition disabled:cursor-not-allowed disabled:opacity-50 [&>svg]:size-4";

export function Button({
  children,
  variant = "secondary",
  className,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: keyof typeof BUTTON }) {
  return (
    <button type="button" {...rest} className={cx(BUTTON_BASE, BUTTON[variant], className)}>
      {children}
    </button>
  );
}

/** A link styled as a button; downloads use it (a plain navigation, so no script is involved). */
export function LinkButton({
  href,
  children,
  download,
  variant = "secondary",
}: {
  href: string;
  children: ReactNode;
  /** true, or the file name to save as. */
  download?: boolean | string;
  variant?: keyof typeof BUTTON;
}) {
  return (
    <a href={href} download={download} className={cx(BUTTON_BASE, BUTTON[variant])}>
      {children}
    </a>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: ReactNode; count?: number }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div
      role="tablist"
      className="mb-5 flex gap-6 overflow-x-auto overflow-y-hidden border-b border-line"
    >
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          type="button"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={cx(
            "-mb-px flex items-center gap-2 whitespace-nowrap border-b-2 pb-2.5 pt-1 text-[14px] font-medium transition-colors",
            value === t.id
              ? "border-brass text-text"
              : "border-transparent text-muted hover:text-text",
          )}
        >
          {t.label}
          {t.count !== undefined && (
            <span
              className={cx(
                "rounded-full px-1.5 text-[11.5px] tabular-nums",
                value === t.id ? "bg-text text-surface" : "bg-surface-3 text-muted",
              )}
            >
              {t.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}

export function Chip({
  active,
  children,
  onClick,
}: {
  active: boolean;
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={active}
      onClick={onClick}
      className={cx(
        "inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-[12.5px] font-medium transition-colors",
        active
          ? "border-text bg-text text-surface"
          : "border-line-strong/70 bg-surface text-muted hover:border-line-strong hover:text-text",
      )}
    >
      {children}
    </button>
  );
}

export function SearchBox({
  value,
  onChange,
  placeholder,
  className,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  className?: string;
}) {
  return (
    <label
      className={cx(
        "flex h-8 items-center gap-2 rounded-lg border border-line-strong/70 bg-surface px-2.5 focus-within:border-brass focus-within:ring-2 focus-within:ring-brass/20",
        className,
      )}
    >
      <Search className="size-4 text-faint" aria-hidden />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className="w-full bg-transparent text-[13.5px] outline-none placeholder:text-faint"
      />
    </label>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx("font-mono text-[12.5px]", className)}>{children}</code>;
}

/** A small label for a vendor, framework or control id. */
export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cx(
        "inline-flex items-center rounded border border-line bg-surface-2 px-1.5 font-mono text-[11.5px] leading-5 text-muted",
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Text from the knowledge base, with its `backticked` spans shown as code. Split, never parsed as
 * markup: the text is data. */
export function Prose({ text }: { text: string }) {
  return (
    <>
      {text.split("`").map((part, i) =>
        i % 2 ? (
          <code key={i} className="rounded bg-surface-3 px-1 font-mono text-[0.9em] text-text">
            {part}
          </code>
        ) : (
          part
        ),
      )}
    </>
  );
}
