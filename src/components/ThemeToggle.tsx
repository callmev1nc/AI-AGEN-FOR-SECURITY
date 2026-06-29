"use client";

import { useSyncExternalStore } from "react";

/**
 * Light/dark theme toggle. Default is dark (no data-theme attr). The chosen
 * theme is persisted to localStorage and applied via an inline script in the
 * root layout (no flash on load). Dark is the default, so this is additive.
 *
 * The active theme is read with useSyncExternalStore (no setState-in-effect):
 * getServerSnapshot returns "dark" to match the SSR/inline-script default, and
 * the client snapshot reads the live data-theme attribute after hydration,
 * which avoids a hydration mismatch.
 */

const subscribeNoop = () => () => {};

function getClientTheme(): "dark" | "light" {
  return document.documentElement.dataset.theme === "light" ? "light" : "dark";
}

export default function ThemeToggle() {
  const theme = useSyncExternalStore(subscribeNoop, getClientTheme, () => "dark");

  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    if (next === "light") {
      document.documentElement.dataset.theme = "light";
    } else {
      delete document.documentElement.dataset.theme;
    }
    try {
      localStorage.setItem("theme", next);
    } catch {
      /* ignore (private mode etc.) */
    }
  }

  return (
    <button
      onClick={toggle}
      title={theme === "dark" ? "Switch to light" : "Switch to dark"}
      aria-label="Toggle color theme"
      className="rounded-lg p-1.5 text-[var(--text-muted)] transition-colors hover:bg-[var(--bg-card)] hover:text-[var(--text-primary)]"
    >
      {theme === "dark" ? (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32l1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32l1.41-1.41" />
        </svg>
      ) : (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z" />
        </svg>
      )}
    </button>
  );
}
