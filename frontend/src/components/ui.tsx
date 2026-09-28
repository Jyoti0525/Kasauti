import { AlertTriangle, Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import type { ControlStatus, JobState, Severity, Status } from "../api/types";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

const STATUS_STYLE: Record<Status, string> = {
  PASS: "bg-pass-soft text-pass",
  FAIL: "bg-fail-soft text-fail",
  REVIEW: "bg-review-soft text-review",
  "N/A": "bg-na-soft text-na",
};

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span
      className={cx(
        "inline-flex min-w-14 justify-center rounded px-1.5 py-0.5 text-[11px] font-semibold tracking-wide",
        STATUS_STYLE[status],
      )}
    >
      {status}
    </span>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-high",
  medium: "text-medium",
  low: "text-low",
};

export function SeverityBadge({ severity }: { severity: Severity | null }) {
  if (!severity) return <span className="text-faint">–</span>;
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 text-xs font-medium capitalize",
        SEVERITY_STYLE[severity],
      )}
    >
      <span className="size-2 rounded-full bg-current" aria-hidden />
      {severity}
    </span>
  );
}

const CONTROL_STYLE: Record<ControlStatus, string> = {
  satisfied: "bg-pass-soft text-pass",
  "partially satisfied": "bg-review-soft text-review",
  "not satisfied": "bg-fail-soft text-fail",
  undetermined: "bg-review-soft text-review",
  "not applicable": "bg-na-soft text-na",
};

export function ControlBadge({ status }: { status: ControlStatus }) {
  return (
    <span className={cx("rounded px-1.5 py-0.5 text-[11px] font-semibold", CONTROL_STYLE[status])}>
      {status}
    </span>
  );
}

const JOB_STYLE: Record<JobState, string> = {
  queued: "bg-na-soft text-na",
  running: "bg-gold-soft text-gold",
  succeeded: "bg-pass-soft text-pass",
  failed: "bg-fail-soft text-fail",
  cancelled: "bg-na-soft text-na",
};

export function JobBadge({ state }: { state: JobState }) {
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold",
        JOB_STYLE[state],
      )}
    >
      {state === "running" && <Loader2 className="size-3 animate-spin" aria-hidden />}
      {state}
    </span>
  );
}

export function Card({
  title,
  action,
  children,
  className,
  bodyClass,
}: {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
}) {
  return (
    <section
      className={cx(
        "rounded-xl border border-line bg-surface shadow-[0_1px_2px_rgba(16,24,40,0.04)]",
        className,
      )}
    >
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          {action}
        </header>
      )}
      <div className={cx("p-5", bodyClass)}>{children}</div>
    </section>
  );
}

export function PageHeader({
  title,
  subtitle,
  actions,
  eyebrow,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  eyebrow?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1 text-xs font-medium text-muted">{eyebrow}</div>}
        <h1 className="truncate text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: ReactNode;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "pass" | "fail" | "review" | "gold";
}) {
  const colour = tone
    ? { pass: "text-pass", fail: "text-fail", review: "text-review", gold: "text-gold" }[tone]
    : "";
  return (
    <div className="rounded-xl border border-line bg-surface px-5 py-4">
      <div className="text-xs font-medium text-muted">{label}</div>
      <div className={cx("mt-1 text-3xl font-semibold tabular-nums tracking-tight", colour)}>
        {value}
      </div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Loading({ what = "Loading" }: { what?: string }) {
  return (
    <div className="flex items-center gap-2 p-8 text-sm text-muted" role="status">
      <Loader2 className="size-4 animate-spin" aria-hidden /> {what}…
    </div>
  );
}

export function ErrorBox({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div
      role="alert"
      className="flex items-start gap-2 rounded-lg border border-fail/30 bg-fail-soft px-4 py-3 text-sm text-fail"
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span>{message}</span>
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
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      {icon && <div className="text-faint">{icon}</div>}
      <div className="font-medium">{title}</div>
      {children && <div className="max-w-md text-sm text-muted">{children}</div>}
    </div>
  );
}

export function Button({
  children,
  variant = "secondary",
  className,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
}) {
  const styles = {
    primary:
      "bg-ink text-white hover:bg-ink-2 dark:bg-gold dark:text-ink dark:hover:brightness-110",
    secondary: "border border-line bg-surface hover:bg-surface-2",
    ghost: "hover:bg-surface-2",
    danger: "border border-line bg-surface text-fail hover:bg-fail-soft",
  }[variant];
  return (
    <button
      type="button"
      {...rest}
      className={cx(
        "inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        styles,
        className,
      )}
    >
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
  variant?: "primary" | "secondary";
}) {
  const styles =
    variant === "primary"
      ? "bg-ink text-white hover:bg-ink-2 dark:bg-gold dark:text-ink"
      : "border border-line bg-surface hover:bg-surface-2";
  return (
    <a
      href={href}
      download={download}
      className={cx(
        "inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition-colors",
        styles,
      )}
    >
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
      className="mb-4 flex gap-1 overflow-x-auto overflow-y-hidden border-b border-line"
    >
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          type="button"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={cx(
            "-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm font-medium transition-colors",
            value === t.id
              ? "border-gold text-text"
              : "border-transparent text-muted hover:text-text",
          )}
        >
          {t.label}
          {t.count !== undefined && (
            <span className="rounded-full bg-surface-2 px-1.5 text-[11px] tabular-nums text-muted">
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
        "rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors",
        active ? "border-gold bg-gold-soft text-text" : "border-line text-muted hover:text-text",
      )}
    >
      {children}
    </button>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cx("font-mono text-[12.5px]", className)}>{children}</code>;
}
