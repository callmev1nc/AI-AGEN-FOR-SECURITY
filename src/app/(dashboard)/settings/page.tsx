export default function SettingsPage() {
  return (
    <div className="animate-fade-in-up mx-auto max-w-2xl space-y-8">
      <div>
        <h1
          className="text-2xl font-bold tracking-tight"
          style={{ fontFamily: "var(--font-jetbrains)" }}
        >
          Settings
        </h1>
        <p className="mt-1 text-sm text-[var(--text-secondary)]">
          Manage your account and preferences.
        </p>
      </div>

      {/* Profile */}
      <div className="card-base p-6 space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Profile
        </h2>
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider">
              Name
            </label>
            <input
              type="text"
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-4 py-2.5 text-sm text-white placeholder:text-[var(--text-muted)] outline-none transition-colors focus:border-[var(--accent)]"
              placeholder="Your name"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wider">
              Email
            </label>
            <input
              type="email"
              className="w-full rounded-lg border border-[var(--border)] bg-[var(--bg-card)] px-4 py-2.5 text-sm text-white placeholder:text-[var(--text-muted)] outline-none transition-colors focus:border-[var(--accent)]"
              placeholder="you@company.com"
            />
          </div>
        </div>
        <button className="rounded-lg bg-[var(--accent)] px-4 py-2 text-sm font-semibold text-black transition-all hover:brightness-110">
          Save Changes
        </button>
      </div>

      {/* API Keys */}
      <div className="card-base p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
            API Keys
          </h2>
          <button className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition-colors hover:border-[var(--accent-dim)] hover:text-white">
            Generate New Key
          </button>
        </div>
        <p className="text-sm text-[var(--text-secondary)]">
          Use API keys to run scans programmatically.
        </p>
        <div className="rounded-lg border border-[var(--border)] bg-[#0a0e14] p-4 font-[family-name:var(--font-jetbrains)] text-xs text-[var(--text-muted)]">
          No API keys generated yet.
        </div>
      </div>

      {/* Billing (placeholder) */}
      <div className="card-base p-6 space-y-4">
        <h2 className="text-sm font-medium uppercase tracking-wider text-[var(--text-muted)]">
          Billing
        </h2>
        <div className="flex items-center justify-between rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
          <div>
            <div className="text-sm font-medium">Free Plan</div>
            <div className="text-xs text-[var(--text-muted)]">
              5 scans per month
            </div>
          </div>
          <span className="rounded-lg border border-[var(--accent-dim)] bg-[var(--accent-dim)] px-3 py-1 text-xs font-medium text-[var(--accent)]">
            Current Plan
          </span>
        </div>
        <p className="text-xs text-[var(--text-muted)]">
          Upgrading to Pro or Enterprise will be available soon.
        </p>
      </div>
    </div>
  );
}
