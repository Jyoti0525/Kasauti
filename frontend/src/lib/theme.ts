import { useCallback, useEffect, useState } from "react";

/** The viewer's colour theme: their own choice, or whatever the operating system prefers. */
export type ThemeChoice = "system" | "light" | "dark";

const KEY = "kasauti-theme";
const DARK = "(prefers-color-scheme: dark)";

function saved(): ThemeChoice {
  try {
    const v = localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function apply(choice: ThemeChoice) {
  const dark = choice === "dark" || (choice === "system" && matchMedia(DARK).matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

/** The current choice and a setter; public/theme.js has already applied it before first paint. */
export function useTheme(): [ThemeChoice, (next: ThemeChoice) => void] {
  const [choice, setChoice] = useState<ThemeChoice>(saved);

  useEffect(() => {
    apply(choice);
    if (choice !== "system") return;
    const media = matchMedia(DARK);
    const follow = () => apply("system");
    media.addEventListener("change", follow);
    return () => media.removeEventListener("change", follow);
  }, [choice]);

  const set = useCallback((next: ThemeChoice) => {
    try {
      if (next === "system") localStorage.removeItem(KEY);
      else localStorage.setItem(KEY, next);
    } catch {
      // Storage blocked: the choice still holds for this visit.
    }
    setChoice(next);
  }, []);

  return [choice, set];
}
