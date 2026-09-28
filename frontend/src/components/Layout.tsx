import { Monitor, Moon, Plus, ShieldCheck, Sun } from "lucide-react";
import { Link, NavLink, Outlet, useLocation } from "react-router";
import { useHealth } from "../api/hooks";
import { shortHash } from "../lib/format";
import { type ThemeChoice, useTheme } from "../lib/theme";
import { Lockup } from "./Brand";
import { cx } from "./ui";

const NAV = [
  { to: "/", label: "Overview", end: true },
  { to: "/audits", label: "Audits", end: false, also: ["/uploads", "/devices"] },
  { to: "/knowledge", label: "Knowledge base", end: false },
  { to: "/rules", label: "Rules", end: false },
];

export function Layout() {
  const health = useHealth();
  const { pathname } = useLocation();
  const onNewAudit = pathname.startsWith("/audits/new");
  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-30 border-b border-basalt-line bg-basalt text-on-basalt">
        <div className="mx-auto flex h-14 max-w-[1320px] items-center gap-8 px-6">
          <Link to="/" aria-label="Kasauti, overview" className="shrink-0 rounded-md">
            <Lockup />
          </Link>
          <nav className="flex h-full items-stretch gap-1" aria-label="Main">
            {NAV.map(({ to, label, end, also }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) => {
                  const active =
                    !onNewAudit && (isActive || (also ?? []).some((p) => pathname.startsWith(p)));
                  return cx(
                    "relative flex items-center px-3 text-[13.5px] font-medium transition-colors",
                    "after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full",
                    active
                      ? "text-white after:bg-brass"
                      : "text-on-basalt hover:text-white after:bg-transparent",
                  );
                }}
              >
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-4">
            <ThemeSwitch />
            <span
              className="hidden items-center gap-1.5 text-xs text-on-basalt md:inline-flex"
              title="Kasauti listens on this machine only and calls no cloud service. Uploaded files are audited and deleted."
            >
              <ShieldCheck className="size-3.5 text-pass" aria-hidden />
              Runs on this machine only
            </span>
            <Link
              to="/audits/new"
              className={cx(
                "inline-flex items-center gap-1.5 rounded-lg bg-brass px-3 py-1.5 text-[13px] font-semibold text-on-brass shadow-[inset_0_1px_0_rgba(255,255,255,0.25)] transition hover:brightness-110",
                onNewAudit && "ring-2 ring-brass/40 ring-offset-2 ring-offset-basalt",
              )}
            >
              <Plus className="size-4" strokeWidth={2.5} aria-hidden /> New audit
            </Link>
          </div>
        </div>
      </header>

      <main className="mx-auto w-full max-w-[1320px] flex-1 px-6 pb-12 pt-8">
        <Outlet />
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-[1320px] flex-wrap items-center gap-x-5 gap-y-1 px-6 py-4 text-xs text-faint">
          {health.data ? (
            <>
              <span>Kasauti {health.data.kasauti_version}</span>
              <span title={health.data.kb_version}>
                Knowledge base{" "}
                <span className="font-mono">{shortHash(health.data.kb_version, 10)}</span>
              </span>
              <span>{health.data.vendor_packs.length} vendor packs</span>
              <span>
                {health.data.frameworks.length} framework
                {health.data.frameworks.length === 1 ? "" : "s"}
              </span>
              <span>Database: {health.data.database}</span>
            </>
          ) : (
            <span className={health.isError ? "text-fail" : undefined}>
              {health.isError ? "The Kasauti server is not answering." : "Connecting…"}
            </span>
          )}
          <span className="ml-auto">No cloud calls · uploaded files are deleted after audit</span>
        </div>
      </footer>
    </div>
  );
}

const THEMES: { value: ThemeChoice; label: string; Icon: typeof Sun }[] = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "Match system", Icon: Monitor },
];

function ThemeSwitch() {
  const [choice, setChoice] = useTheme();
  return (
    <div
      role="radiogroup"
      aria-label="Colour theme"
      className="flex items-center rounded-lg border border-basalt-line p-0.5"
    >
      {THEMES.map(({ value, label, Icon }) => (
        <button
          key={value}
          type="button"
          role="radio"
          aria-checked={choice === value}
          aria-label={label}
          title={label}
          onClick={() => setChoice(value)}
          className={cx(
            "grid size-7 place-items-center rounded-md transition-colors",
            choice === value
              ? "bg-basalt-2 text-brass shadow-[inset_0_0_0_1px_var(--basalt-line)]"
              : "text-on-basalt hover:text-white",
          )}
        >
          <Icon className="size-3.5" aria-hidden />
        </button>
      ))}
    </div>
  );
}
