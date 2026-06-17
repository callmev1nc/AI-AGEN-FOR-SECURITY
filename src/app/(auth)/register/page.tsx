"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { createClient } from "@/lib/supabase/client";

export default function RegisterPage() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [passwordError, setPasswordError] = useState("");

  function getPasswordStrength(pw: string): { level: "weak" | "medium" | "strong"; score: number } {
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[a-z]/.test(pw)) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^a-zA-Z0-9]/.test(pw)) score++;
    if (score <= 2) return { level: "weak", score: 0 };
    if (score <= 4) return { level: "medium", score: 1 };
    return { level: "strong", score: 2 };
  }

  function validatePassword(pw: string): string {
    if (pw.length < 8) return "Minimum 8 characters";
    if (!/[a-z]/.test(pw)) return "Must include a lowercase letter";
    if (!/[A-Z]/.test(pw)) return "Must include an uppercase letter";
    if (!/[0-9]/.test(pw)) return "Must include a number";
    return "";
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    const pwErr = validatePassword(password);
    if (pwErr) {
      setPasswordError(pwErr);
      setLoading(false);
      return;
    }

    const supabase = createClient();
    const { error: authError } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { name },
      },
    });

    if (authError) {
      setError(authError.message);
      setLoading(false);
      return;
    }

    router.push("/dashboard");
    router.refresh();
  }

  return (
    <div className="w-full max-w-sm animate-fade-in-up">
      {/* Logo */}
      <div className="mb-8 text-center">
        <div className="mx-auto mb-4 flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--accent)]">
          <svg
            width="20"
            height="20"
            viewBox="0 0 16 16"
            fill="none"
            className="text-black"
          >
            <path
              d="M8 1L2 4.5V11.5L8 15L14 11.5V4.5L8 1Z"
              stroke="currentColor"
              strokeWidth="1.5"
              fill="none"
            />
            <path
              d="M8 1V15M2 4.5L8 8L14 4.5"
              stroke="currentColor"
              strokeWidth="1.5"
            />
          </svg>
        </div>
        <h1
          className="text-xl font-bold tracking-tight"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          Create your account
        </h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Start scanning for vulnerabilities in seconds.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="rounded-lg border border-[var(--critical)]/30 bg-[var(--critical-dim)] px-4 py-3 text-sm text-[var(--critical)]">
            {error}
          </div>
        )}

        <div>
          <label htmlFor="name" className="mb-1.5 block text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider">
            Full name
          </label>
          <input
            id="name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-4 py-2.5 text-sm text-white placeholder:text-[var(--text-muted)] outline-none transition-colors focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent-dim)]"
            placeholder="John Doe"
          />
        </div>

        <div>
          <label htmlFor="email" className="mb-1.5 block text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider">
            Email
          </label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-4 py-2.5 text-sm text-white placeholder:text-[var(--text-muted)] outline-none transition-colors focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent-dim)]"
            placeholder="you@company.com"
          />
        </div>

        <div>
          <label htmlFor="password" className="mb-1.5 block text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider">
            Password
          </label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
              setPasswordError("");
            }}
            required
            className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-4 py-2.5 text-sm text-white placeholder:text-[var(--text-muted)] outline-none transition-colors focus:border-[var(--accent)] focus:ring-1 focus:ring-[var(--accent-dim)]"
            placeholder="Minimum 8 characters"
          />
          {password && (
            <div className="mt-2">
              <div className="flex gap-1">
                {["weak", "medium", "strong"].map((level) => {
                  const strength = getPasswordStrength(password);
                  const active = strength.level === level ||
                    (level === "weak" && strength.level === "medium") ||
                    (level === "weak" && strength.level === "strong") ||
                    (level === "medium" && strength.level === "strong");
                  const filled = level === "weak" ? strength.score >= 0 : level === "medium" ? strength.score >= 1 : strength.score >= 2;
                  const color =
                    strength.level === "weak"
                      ? "bg-[var(--critical)]"
                      : strength.level === "medium"
                      ? "bg-[#f59e0b]"
                      : "bg-[var(--accent)]";
                  return (
                    <div
                      key={level}
                      className={`h-1 flex-1 rounded-full transition-colors ${filled ? color : "bg-[var(--border)]"}`}
                    />
                  );
                })}
              </div>
              <p
                className={`mt-1 text-xs ${
                  getPasswordStrength(password).level === "weak"
                    ? "text-[var(--critical)]"
                    : getPasswordStrength(password).level === "medium"
                    ? "text-[#f59e0b]"
                    : "text-[var(--accent)]"
                }`}
              >
                {getPasswordStrength(password).level === "weak" && "Weak — add uppercase, number, or special char"}
                {getPasswordStrength(password).level === "medium" && "Medium — getting better"}
                {getPasswordStrength(password).level === "strong" && "Strong password"}
              </p>
            </div>
          )}
          {passwordError && (
            <p className="mt-1 text-xs text-[var(--critical)]">{passwordError}</p>
          )}
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-lg bg-[var(--accent)] py-2.5 text-sm font-semibold text-black transition-all hover:brightness-110 disabled:opacity-50"
        >
          {loading ? "Creating account..." : "Create account"}
        </button>
      </form>

      <p className="mt-4 text-center text-xs text-[var(--text-muted)]">
        By creating an account, you agree to our Terms of Service and Privacy Policy.
      </p>

      <div className="mt-4 text-center">
        <p className="text-sm text-[var(--text-muted)]">
          Already have an account?{" "}
          <Link
            href="/login"
            className="text-[var(--accent)] hover:underline"
          >
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
