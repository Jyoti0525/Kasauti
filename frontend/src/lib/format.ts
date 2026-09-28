export function pct(value: number | null | undefined, digits = 1): string {
  return value === null || value === undefined ? "–" : `${value.toFixed(digits)}%`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

export function when(iso: string | null | undefined): string {
  if (!iso) return "–";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    day: "numeric",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "–";
  const s = Math.max(0, Math.round((now - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function shortHash(h: string | null | undefined, n = 12): string {
  return h ? h.slice(0, n) : "–";
}

const ACRONYMS = new Set([
  "aaa",
  "acl",
  "aws",
  "http",
  "https",
  "ip",
  "ntp",
  "os",
  "snmp",
  "ssh",
  "vpc",
]);

/** `os_version` → "OS Version", `aaa` → "AAA". */
export function titleCase(s: string): string {
  return s
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((w) =>
      ACRONYMS.has(w.toLowerCase()) ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1),
    )
    .join(" ");
}

/** A fact's value as text. */
export function show(value: unknown): string {
  if (value === null || value === undefined) return "–";
  if (Array.isArray(value)) return value.length ? value.map(show).join(", ") : "(none)";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
