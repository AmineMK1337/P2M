import { AnimatePresence, motion } from "framer-motion";

function DecisionPanel({ decision, logs }) {
  const blocked = decision.state === "BLOCK";

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="panel p-4 md:p-5"
    >
      <header className="mb-4 flex items-center justify-between">
        <h2 className="font-display text-lg font-semibold text-slate-100">Decision</h2>
        <span className="font-mono text-xs text-slate-400">{decision.agent || "policy engine"}</span>
      </header>

      <div
        className={`mb-4 rounded-2xl border p-5 text-center ${
          blocked
            ? "border-danger/60 bg-danger/10 shadow-alert animate-pulseAlert"
            : "border-emerald-400/45 bg-emerald-400/10"
        }`}
      >
        <p className="font-mono text-xs uppercase tracking-widest text-slate-300">Final Action</p>
        <p className={`mt-2 font-display text-5xl font-bold ${blocked ? "text-danger" : "text-emerald-300"}`}>
          {decision.state}
        </p>
      </div>

      <div className="mb-4 rounded-xl border border-slate-700/60 bg-slate-900/70 p-3">
        <p className="font-mono text-xs uppercase tracking-wider text-slate-400">Mitigation Status</p>
        <p className={`mt-2 font-display text-2xl font-semibold ${decision.mitigated ? "text-accent" : "text-amber-300"}`}>
          {(decision.mitigationStatus || "pending").toUpperCase()}
        </p>
      </div>

      <div className="mb-4 rounded-xl border border-slate-700/60 bg-slate-900/70 p-3">
        <p className="mb-2 font-mono text-xs uppercase tracking-wider text-slate-400">Blocked IPs</p>
        <div className="space-y-2">
          <AnimatePresence>
            {decision.blockedIps.map((ip) => (
              <motion.div
                key={ip}
                layout
                initial={{ opacity: 0, x: 24 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -24 }}
                className="rounded-lg border border-danger/35 bg-danger/10 px-3 py-2 font-mono text-sm text-rose-100"
              >
                {ip}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>

      <div className="mb-4 rounded-xl border border-slate-700/60 bg-slate-900/70 p-3">
        <p className="mb-2 font-mono text-xs uppercase tracking-wider text-slate-400">Mitigation Actions</p>
        <ul className="space-y-2">
          {(decision.actions || []).slice(0, 4).map((action, idx) => (
            <li key={`${action}-${idx}`} className="font-mono text-xs text-slate-300">
              {action}
            </li>
          ))}
        </ul>
      </div>

      <div className="rounded-xl border border-slate-700/60 bg-slate-900/70 p-3">
        <p className="mb-2 font-mono text-xs uppercase tracking-wider text-slate-400">Latest Events</p>
        <ul className="space-y-2">
          {logs.slice(0, 5).map((event, idx) => (
            <li key={`${event}-${idx}`} className="font-mono text-xs text-slate-300">
              {event}
            </li>
          ))}
        </ul>
      </div>
    </motion.section>
  );
}

export default DecisionPanel;
