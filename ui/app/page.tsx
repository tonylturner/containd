const phases = [
  {
    title: "Phase 0",
    status: "in-progress",
    summary: "Scaffolding, health endpoints, build/test harnesses",
  },
  {
    title: "Phase 1",
    status: "up-next",
    summary: "L3/L4 stateful firewall with single-interface capture + policy APIs",
  },
  {
    title: "Phase 2",
    status: "queued",
    summary: "Multi-interface, multi-zone enforcement and topology UI",
  },
];

export default function Home() {
  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100">
      <div className="pointer-events-none absolute inset-0 opacity-30">
        <div className="grid-overlay h-full w-full" />
      </div>
      <main className="relative mx-auto max-w-5xl px-6 py-16">
        <p className="text-sm uppercase tracking-[0.3em] text-mint">
          ICS-native firewall
        </p>
        <h1 className="mt-4 text-5xl font-bold leading-tight text-white">
          containd
        </h1>
        <p className="mt-4 max-w-2xl text-lg text-slate-200">
          Open-source NGFW and IDS/IPS built for industrial control systems.
          Management plane ships with an API, modern UI, and SSH CLI; the data
          plane focuses on deterministic performance, DPI, and ICS-aware rules.
        </p>

        <div className="mt-10 grid gap-6 md:grid-cols-2">
          <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
            <div className="flex items-center justify-between">
              <h3 className="text-xl font-semibold">Management Plane</h3>
              <span className="rounded-full bg-mint/20 px-3 py-1 text-sm text-mint">
                API / UI / SSH
              </span>
            </div>
            <p className="mt-3 text-sm text-slate-200">
              Gin-based API exposed at <code>/api/v1</code>; serves the Next.js
              UI build and will host the appliance-style CLI over SSH.
            </p>
            <div className="mt-4 rounded-lg border border-white/10 bg-black/30 p-4 text-sm text-slate-100">
              <p className="font-mono text-xs uppercase tracking-wide text-amber">
                Health endpoints
              </p>
              <ul className="mt-2 space-y-1 font-mono text-xs text-slate-200">
                <li>GET http://localhost:8080/api/v1/health</li>
                <li>Default addr: env <code>NGFW_MGMT_ADDR</code></li>
              </ul>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-white/5 p-6 shadow-lg backdrop-blur">
            <div className="flex items-center justify-between">
              <h3 className="text-xl font-semibold">Data Plane</h3>
              <span className="rounded-full bg-amber/20 px-3 py-1 text-sm text-amber">
                Engine
              </span>
            </div>
            <p className="mt-3 text-sm text-slate-200">
              Stub server ready to host capture workers, flow tracking, and
              enforcement. Ships with a simple health endpoint for now.
            </p>
            <div className="mt-4 rounded-lg border border-white/10 bg-black/30 p-4 text-sm text-slate-100">
              <p className="font-mono text-xs uppercase tracking-wide text-amber">
                Health endpoints
              </p>
              <ul className="mt-2 space-y-1 font-mono text-xs text-slate-200">
                <li>GET http://localhost:8081/health</li>
                <li>Default addr: env <code>NGFW_ENGINE_ADDR</code></li>
              </ul>
            </div>
          </div>
        </div>

        <section className="mt-12 rounded-2xl border border-white/10 bg-gradient-to-r from-white/5 via-white/0 to-mint/10 p-6 shadow-inner">
          <header className="flex items-center justify-between gap-4">
            <div>
              <p className="text-sm uppercase tracking-[0.2em] text-slate-300">
                Delivery roadmap
              </p>
              <h2 className="text-2xl font-semibold text-white">
                Implementation phases
              </h2>
            </div>
            <span className="rounded-full bg-white/10 px-3 py-1 text-xs uppercase tracking-wide text-slate-200">
              Based on agents.md
            </span>
          </header>
          <div className="mt-6 grid gap-4 md:grid-cols-3">
            {phases.map((phase) => (
              <div
                key={phase.title}
                className="rounded-xl border border-white/10 bg-black/30 p-4"
              >
                <div className="flex items-center justify-between text-sm">
                  <span className="font-semibold text-white">{phase.title}</span>
                  <span className="rounded-full bg-white/10 px-2 py-0.5 text-xs uppercase tracking-wide text-slate-200">
                    {phase.status}
                  </span>
                </div>
                <p className="mt-2 text-sm text-slate-200">{phase.summary}</p>
              </div>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
