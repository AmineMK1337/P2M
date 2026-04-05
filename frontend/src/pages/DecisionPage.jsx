import { AnimatePresence, motion } from "framer-motion";

function DecisionPage({ state }) {
  const blocked = state.decision.action === "block";
  const blockedIps = state.defense.blocked_ips || [];

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
      <section className="glass-panel rounded-2xl p-4 xl:col-span-2">
        <h2 className="font-display text-lg font-semibold">Final Decision</h2>
        <div
          className={`mt-4 rounded-2xl border p-6 text-center ${
            blocked ? "border-rose-400/55 bg-rose-500/10" : "border-emerald-300/50 bg-emerald-500/10"
          }`}
        >
          <p className="font-mono text-xs uppercase tracking-widest text-slate-300">Action</p>
          <p className={`metric-value mt-2 text-6xl ${blocked ? "text-neon-danger" : "text-neon-ok"}`}>
            {state.decision.action.toUpperCase()}
          </p>
        </div>

        <div className="mt-4 rounded-xl border border-slate-700/70 bg-slate-900/45 p-3">
          <p className="font-mono text-xs text-slate-400">last blocked ip</p>
          <p className="mt-1 font-mono text-sm text-slate-200">{state.defense.last_blocked_ip}</p>
          <p className="mt-2 text-xs text-slate-400">total blocked: {state.defense.total}</p>
        </div>
      </section>

      <section className="glass-panel rounded-2xl p-4 xl:col-span-3">
        <h2 className="mb-3 font-display text-lg font-semibold">Defense Actions</h2>

        <div className="mb-4 space-y-2">
          <AnimatePresence>
            {blockedIps.slice(0, 10).map((ip) => (
              <motion.div
                key={ip}
                layout
                initial={{ opacity: 0, x: 14 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -14 }}
                className="rounded-lg border border-rose-400/35 bg-rose-500/10 px-3 py-2 font-mono text-sm text-rose-100"
              >
                {ip}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>

        <div className="rounded-xl border border-slate-700/70 bg-slate-900/45 p-3">
          <p className="mb-2 font-mono text-xs uppercase tracking-wider text-slate-400">Latest Logs</p>
          <ul className="space-y-1">
            {(state.logs || []).slice(0, 8).map((line, idx) => (
              <li key={`${line}-${idx}`} className="font-mono text-xs text-slate-300">
                {line}
              </li>
            ))}
          </ul>
        </div>
      </section>
    </div>
  );
}

export default DecisionPage;
