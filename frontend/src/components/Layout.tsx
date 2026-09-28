import {
  BookOpen,
  FlaskConical,
  History,
  LayoutDashboard,
  Lock,
  Plus,
  ScrollText,
} from "lucide-react";
import { NavLink, Outlet } from "react-router";
import { useHealth } from "../api/hooks";
import { shortHash } from "../lib/format";
import { cx } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/audits/new", label: "New audit", icon: Plus },
  { to: "/audits", label: "Audits", icon: History, end: true },
  { to: "/knowledge", label: "Knowledge base", icon: BookOpen },
  { to: "/rules", label: "Frameworks & rules", icon: ScrollText },
];

export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <svg viewBox="0 0 32 32" className="size-8" aria-hidden>
        <rect width="32" height="32" rx="7" fill="#1d2027" />
        <path d="M8 23.5 L23.5 8" stroke="#e0b04a" strokeWidth="3.2" strokeLinecap="round" />
        <path
          d="M11 25 L25 11"
          stroke="#b8871b"
          strokeWidth="1.4"
          strokeLinecap="round"
          opacity=".7"
        />
      </svg>
      <div className="leading-tight">
        <div className="font-semibold tracking-tight text-white">
          Kasauti <span className="font-normal text-[#e0b04a]">कसौटी</span>
        </div>
        <div className="text-[11px] text-ink-text/70">Network compliance auditor</div>
      </div>
    </div>
  );
}

export function Layout() {
  const health = useHealth();
  return (
    <div className="flex min-h-full">
      <aside className="w-60 shrink-0 bg-ink text-ink-text">
        <div className="sticky top-0 flex h-screen flex-col">
          <div className="px-5 pb-6 pt-5">
            <Logo />
          </div>
          <nav className="flex-1 space-y-0.5 px-3" aria-label="Main">
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  cx(
                    "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                    isActive
                      ? "bg-white/10 font-medium text-white"
                      : "hover:bg-white/5 hover:text-white",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon className={cx("size-4", isActive && "text-[#e0b04a]")} aria-hidden />
                    {label}
                  </>
                )}
              </NavLink>
            ))}
            <div
              className="flex cursor-not-allowed items-center gap-3 rounded-lg px-3 py-2 text-sm text-ink-text/45"
              title="The Training Studio, where unknown configuration lines are taught, comes next (TODO M2.62–M2.69)"
            >
              <FlaskConical className="size-4" aria-hidden />
              Training Studio
              <span className="ml-auto rounded bg-white/10 px-1.5 text-[10px] uppercase tracking-wide">
                next
              </span>
            </div>
          </nav>
          <div className="m-3 rounded-lg bg-white/5 p-3 text-[11px] leading-relaxed">
            <div className="mb-1.5 flex items-center gap-1.5 font-medium text-white">
              <Lock className="size-3" aria-hidden /> Loopback only · no cloud calls
            </div>
            {health.data ? (
              <dl className="grid grid-cols-[auto_1fr] gap-x-2 text-ink-text/75">
                <dt>Knowledge base</dt>
                <dd className="truncate font-mono" title={health.data.kb_version}>
                  {shortHash(health.data.kb_version, 10)}
                </dd>
                <dt>Vendor packs</dt>
                <dd>{health.data.vendor_packs.length}</dd>
                <dt>Frameworks</dt>
                <dd>{health.data.frameworks.length}</dd>
                <dt>Version</dt>
                <dd>{health.data.kasauti_version}</dd>
              </dl>
            ) : (
              <div className="text-ink-text/60">
                {health.isError ? "Server unreachable" : "Connecting…"}
              </div>
            )}
          </div>
        </div>
      </aside>
      <main className="min-w-0 flex-1">
        <div className="mx-auto max-w-7xl px-8 py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
