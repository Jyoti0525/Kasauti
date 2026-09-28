import { useId } from "react";

/** The streak an assayer rubs across the touchstone, drawn as a tick: tested, and shown to hold.
 * It thickens where the stroke bears down and thins where it lifts, as a streak of gold does. */
const STREAK =
  "M17.3 32.4C18.3 31.6 19.5 31.8 20.4 32.6L27.2 38.4L45.9 18.9C46.9 17.9 48.5 18 49.3 19.1C49.9 19.9 49.8 21 49.2 21.8L30.4 46.4C29.1 48.1 26.6 48.3 25 46.8L16.8 36.1C16 35 16.2 33.3 17.3 32.4Z";

/** The touchstone: a flat slab of basalt, worn smooth and a little out of square. */
const STONE =
  "M13.6 7.4C23.4 2.9 43.1 2.6 53.2 8.1C60.1 11.9 61.6 22.6 61.2 34.8C60.8 48.9 54.9 58.6 39.6 60.3C26.9 61.7 11.8 60.4 6.1 51.9C2.2 46.1 2.1 29.6 3.6 21.4C4.6 15.3 8.2 9.9 13.6 7.4Z";

/** The Kasauti mark: a basalt touchstone and a brass streak. */
export function Mark({ className = "size-8", title }: { className?: string; title?: string }) {
  const raw = useId().replace(/[^A-Za-z0-9]/g, "");
  const stone = `${raw}stone`;
  const gold = `${raw}gold`;
  const sheen = `${raw}sheen`;
  return (
    <svg
      viewBox="0 0 64 64"
      className={className}
      role={title ? "img" : undefined}
      aria-hidden={title ? undefined : true}
    >
      {title && <title>{title}</title>}
      <defs>
        <linearGradient id={stone} x1="8" y1="4" x2="56" y2="62" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#343c42" />
          <stop offset="0.55" stopColor="#1a1f23" />
          <stop offset="1" stopColor="#0b0d0f" />
        </linearGradient>
        <linearGradient id={gold} x1="17" y1="47" x2="50" y2="18" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#9c6f1c" />
          <stop offset="0.45" stopColor="#d9a93f" />
          <stop offset="0.8" stopColor="#f0cf7d" />
          <stop offset="1" stopColor="#fae7ad" />
        </linearGradient>
        <radialGradient id={sheen} cx="18" cy="10" r="34" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#ffffff" stopOpacity="0.14" />
          <stop offset="1" stopColor="#ffffff" stopOpacity="0" />
        </radialGradient>
      </defs>
      <path d={STONE} fill={`url(#${stone})`} />
      <path d={STONE} fill={`url(#${sheen})`} />
      <path d={STONE} fill="none" stroke="#ffffff" strokeOpacity="0.1" strokeWidth="1" />
      {/* earlier assays: fainter streaks already rubbed on the stone */}
      <path
        d="M37.5 51.5L53.6 31.2M44.2 54.1L55.4 40.2"
        fill="none"
        stroke={`url(#${gold})`}
        strokeLinecap="round"
        strokeOpacity="0.28"
        strokeWidth="2.4"
      />
      <path d={STREAK} fill={`url(#${gold})`} />
      {/* the lit edge of the streak, where the gold catches the light */}
      <path
        d="M20.6 33.4L27.2 39.1L46.4 19.6"
        fill="none"
        stroke="#fff6d8"
        strokeOpacity="0.55"
        strokeWidth="0.9"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** The mark and the name, as the header shows them. */
export function Lockup({ className }: { className?: string }) {
  return (
    <span className={className ?? "flex items-center gap-2.5"}>
      <Mark className="size-8" />
      <span className="text-[17px] font-semibold tracking-[-0.015em] text-white">Kasauti</span>
    </span>
  );
}
