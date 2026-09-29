// Sign in and create an account (backend/kasauti/api/auth.py). One team, one workspace: every
// account sees the same fleet; its role says what it may change.

import { useQueryClient } from "@tanstack/react-query";
import { ArrowRight, KeyRound, LogIn, ShieldCheck, UserPlus } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router";
import { api } from "../api/client";
import { useAuthOptions, useMe } from "../api/hooks";
import type { Me } from "../api/types";
import { Lockup } from "../components/Brand";
import { Button, cx } from "../components/ui";

type Mode = "signin" | "signup";

const ROLE_TEXT: Record<Me["role"], string> = {
  viewer: "reads audits and reports",
  auditor: "uploads configurations and runs audits",
  trainer: "also teaches the Training Studio",
  approver: "also approves lessons that make a check pass",
  admin: "everything, and manages accounts",
};

export function Login() {
  const me = useMe();
  const options = useAuthOptions();
  const queries = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from ?? "/";
  const [mode, setMode] = useState<Mode>("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    document.title = `${mode === "signin" ? "Sign in" : "Create account"} · Kasauti`;
  }, [mode]);

  if (me.data) return <Navigate to={from} replace />;

  const enter = async (path: string, body: object) => {
    setBusy(true);
    setError(null);
    try {
      const who = await api.post<Me>(path, body);
      queries.clear(); // nothing cached from before belongs to this person
      queries.setQueryData(["me"], who);
      navigate(from, { replace: true });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (mode === "signin") void enter("/api/auth/login", { username, password });
    else void enter("/api/auth/signup", { username, name, password });
  };
  const min = options.data?.min_password ?? 15;
  const demo = options.data?.demo ?? [];
  const signupOpen = options.data?.signup ?? true;

  return (
    <div className="grid min-h-screen lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
      <aside className="relative hidden overflow-hidden bg-basalt px-12 py-10 text-on-basalt lg:flex lg:flex-col">
        <Lockup />
        <div className="my-auto max-w-md">
          <p className="text-[12px] font-semibold uppercase tracking-[0.14em] text-brass">
            Network compliance, proven line by line
          </p>
          <h1 className="mt-4 text-[34px] font-semibold leading-[1.15] tracking-[-0.02em] text-white">
            Is every device on the network configured securely?
          </h1>
          <p className="mt-4 text-[15px] leading-relaxed">
            Kasauti reads router, switch and firewall configurations from many brands and checks
            them against NIST SP 800-53, DISA STIG and ISO/IEC 27001.
          </p>
          <ul className="mt-8 space-y-3.5 text-[14px]">
            {[
              "Every finding points to the exact lines of the configuration",
              "Fixes are proven by auditing a corrected copy again",
              "A brand it has never seen is taught, and a second person approves",
            ].map((t) => (
              <li key={t} className="flex gap-3">
                <span className="mt-2 h-px w-4 shrink-0 bg-brass" aria-hidden />
                {t}
              </li>
            ))}
          </ul>
        </div>
        <p className="inline-flex items-center gap-1.5 text-xs">
          <ShieldCheck className="size-3.5 text-pass" aria-hidden />
          Works offline · no cloud calls
        </p>
      </aside>

      <main className="flex items-center justify-center bg-canvas px-4 py-10">
        <div className="w-full max-w-[420px]">
          <div className="mb-8 lg:hidden">
            <div className="inline-flex rounded-xl bg-basalt px-3 py-2">
              <Lockup />
            </div>
          </div>
          <h2 className="text-[24px] font-semibold tracking-[-0.015em]">
            {mode === "signin" ? "Sign in" : "Create your account"}
          </h2>
          <p className="mt-1 text-[14px] text-muted">
            {mode === "signin"
              ? "Your team's audits, findings and fixes are waiting."
              : "You join the team as an auditor: you can upload configurations and run audits."}
          </p>

          {signupOpen && (
            <div
              role="tablist"
              aria-label="Sign in or create an account"
              className="mt-6 grid grid-cols-2 rounded-lg border border-line bg-surface-2 p-1"
            >
              {(
                [
                  ["signin", "Sign in", LogIn],
                  ["signup", "Create account", UserPlus],
                ] as const
              ).map(([m, label, Icon]) => (
                <button
                  key={m}
                  type="button"
                  role="tab"
                  aria-selected={mode === m}
                  onClick={() => {
                    setMode(m);
                    setError(null);
                  }}
                  className={cx(
                    "inline-flex h-8 items-center justify-center gap-1.5 rounded-md text-[13px] font-medium transition-colors",
                    mode === m
                      ? "bg-surface text-text shadow-[0_1px_2px_rgba(0,0,0,0.08)]"
                      : "text-muted hover:text-text",
                  )}
                >
                  <Icon className="size-3.5" aria-hidden />
                  {label}
                </button>
              ))}
            </div>
          )}

          <form onSubmit={submit} className="mt-6 space-y-4" noValidate>
            {mode === "signup" && (
              <Field label="Your name">
                <input
                  className="field h-10"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                  maxLength={80}
                  required
                />
              </Field>
            )}
            <Field
              label="Username"
              hint={mode === "signup" ? "Lower-case letters, digits, . _ or -" : undefined}
            >
              <input
                className="field h-10"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                maxLength={32}
                required
              />
            </Field>
            <Field
              label="Password"
              hint={
                mode === "signup"
                  ? `At least ${min} characters. A phrase of a few words is easiest.`
                  : undefined
              }
            >
              <input
                className="field h-10"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={mode === "signin" ? "current-password" : "new-password"}
                maxLength={128}
                required
              />
            </Field>
            {error && (
              <p role="alert" className="rounded-lg bg-fail-soft px-3 py-2 text-[13px] text-fail">
                {error}
              </p>
            )}
            <Button
              type="submit"
              variant="primary"
              className="h-10 w-full"
              disabled={busy || !username || !password || (mode === "signup" && !name)}
            >
              {mode === "signin" ? "Sign in" : "Create account and sign in"}
              <ArrowRight />
            </Button>
          </form>

          {mode === "signin" && demo.length > 0 && (
            <section
              aria-labelledby="demo-accounts"
              className="mt-8 rounded-xl border border-line bg-surface"
            >
              <header className="flex items-center gap-2 border-b border-line px-4 py-3">
                <KeyRound className="size-4 text-brass-ink" aria-hidden />
                <h3 id="demo-accounts" className="text-[13.5px] font-semibold">
                  Demo accounts
                </h3>
                <span className="ml-auto text-[11.5px] text-faint">for this demonstration</span>
              </header>
              <ul className="divide-y divide-line">
                {demo.map((d) => (
                  <li key={d.username} className="flex items-center gap-3 px-4 py-3">
                    <span className="grid size-8 shrink-0 place-items-center rounded-full bg-basalt text-[13px] font-semibold text-brass">
                      {d.name.slice(0, 1)}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-[13.5px] font-medium" title={ROLE_TEXT[d.role]}>
                        {d.name} <span className="font-normal text-muted">· {d.role}</span>
                      </div>
                      <div className="mt-0.5 font-mono text-[12px] text-muted">
                        {d.username} / {d.password}
                      </div>
                    </div>
                    <Button
                      disabled={busy}
                      onClick={() => {
                        setUsername(d.username);
                        setPassword(d.password);
                        void enter("/api/auth/login", {
                          username: d.username,
                          password: d.password,
                        });
                      }}
                    >
                      Sign in
                    </Button>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </main>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block text-[13px] font-medium">
      {label}
      <div className="mt-1.5">{children}</div>
      {hint && <span className="mt-1 block text-[12px] font-normal text-faint">{hint}</span>}
    </label>
  );
}
