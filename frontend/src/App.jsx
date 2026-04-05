import { useMemo } from "react";
import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  ResponsiveContainer,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip
} from "recharts";
import AnimatedBackground from "./components/AnimatedBackground";
import StatCard from "./components/StatCard";
import PipelineFlow from "./components/PipelineFlow";
import { useSystemState } from "./hooks/useSystemState";

function App() {
  const { state, loading, source, lastUpdated } = useSystemState(2500);

  const underAttack = useMemo(() => state?.ml?.prediction === "attack", [state]);

  const connections = useMemo(
    () =>
      (state?.traffic?.connections || []).slice(0, 6).map((conn, idx) => ({
        id: conn.id || `${conn.ip || conn.src_ip || "unknown"}-${idx}`,
        ip: conn.ip || conn.src_ip || "unknown",
        protocol: conn.protocol || "TCP"
      })),
    [state]
  );

  const featureSnapshot = useMemo(() => (state?.features?.items || []).slice(0, 4), [state]);
  const mlChart = useMemo(() => (state?.ml?.history || []).slice(-22), [state]);
  const blockedIps = useMemo(() => (state?.defense?.blocked_ips || []).slice(0, 6), [state]);

  return (
    <div className="h-screen overflow-hidden text-slate-100">
      <AnimatedBackground danger={underAttack} />

      <div className="relative z-10 mx-auto h-screen max-w-[1700px] px-3 py-3 md:px-4 md:py-4">
        <div className="grid h-full grid-rows-[auto_auto_auto_minmax(0,1fr)] gap-3 md:gap-3.5">
        <motion.header
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-panel flex flex-col gap-2 rounded-2xl p-3 md:flex-row md:items-center md:justify-between"
        >
          <div>
            <h1 className="font-display text-lg font-semibold tracking-wide md:text-2xl">ANDS Dashboard</h1>
            <p className="font-mono text-[11px] text-slate-400 md:text-xs">
              {"Traffic -> Capture -> Features -> ML -> Decision -> Defense"}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={`status-pill ${underAttack ? "status-danger" : "status-ok"}`}>
              {underAttack ? "UNDER ATTACK" : "ACTIVE"}
            </span>
            <span className="status-pill status-warn">source: {source}</span>
            <span className="status-pill">{loading ? "syncing..." : `updated ${lastUpdated}`}</span>
          </div>
        </motion.header>

        <section className="grid grid-cols-2 gap-2.5 lg:grid-cols-4">
          <StatCard title="packets/sec" value={state.traffic.pps} hint="Live ingress traffic" tone={underAttack ? "warn" : "info"} />
          <StatCard title="flows extracted" value={state.features.flows} hint="Feature engine output" tone="ok" />
          <StatCard
            title="attacks detected"
            value={state.ml.prediction === "attack" ? 1 : 0}
            hint={`${Math.round(state.ml.confidence * 100)}% confidence`}
            tone={underAttack ? "danger" : "ok"}
          />
          <StatCard title="blocked IPs" value={state.defense.total} hint={`Last: ${state.defense.last_blocked_ip}`} tone={state.defense.total ? "danger" : "info"} />
        </section>

        <section>
          <PipelineFlow state={state} />
        </section>

        <section className="grid min-h-0 grid-cols-1 gap-3 xl:grid-cols-3">
          <motion.article initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="glass-panel min-h-0 rounded-2xl p-3">
            <h2 className="font-display text-base font-semibold">Traffic + Features</h2>
            <div className="mt-2 max-h-36 overflow-auto rounded-xl border border-slate-700/70">
              <table className="w-full border-collapse font-mono text-xs">
                <thead className="bg-slate-900/65 text-slate-300">
                  <tr>
                    <th className="px-2 py-2 text-left">IP</th>
                    <th className="px-2 py-2 text-left">Protocol</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.map((row) => (
                    <tr key={row.id} className="border-t border-slate-700/60 text-slate-200">
                      <td className="px-2 py-2">{row.ip}</td>
                      <td className="px-2 py-2">{row.protocol}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="mt-2 space-y-1.5 overflow-auto">
              {featureSnapshot.map((item) => (
                <div
                  key={item.key}
                  className={`rounded-lg border px-2.5 py-1.5 text-xs ${item.changed ? "border-cyan-300/50 bg-cyan-500/10" : "border-slate-700/70 bg-slate-900/50"}`}
                >
                  <p className="font-mono text-[11px] text-slate-400">{item.label}</p>
                  <p className="metric-value text-neon-info">
                    {item.value}
                    <span className="ml-1 text-xs text-slate-400">{item.unit}</span>
                  </p>
                </div>
              ))}
            </div>
          </motion.article>

          <motion.article initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="glass-panel min-h-0 rounded-2xl p-3">
            <h2 className="font-display text-base font-semibold">ML Detection</h2>
            <div className="mt-2 rounded-xl border border-slate-700/70 bg-slate-900/50 p-2.5">
              <p className={`metric-value text-3xl ${underAttack ? "text-neon-danger" : "text-neon-ok"}`}>
                {state.ml.prediction.toUpperCase()}
              </p>
              <p className="mt-0.5 text-xs text-slate-300">{state.ml.attackType}</p>
              <div className="mt-2 h-2 rounded-full bg-slate-800">
                <motion.div
                  className={`h-full rounded-full ${underAttack ? "bg-rose-400" : "bg-emerald-400"}`}
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.round(state.ml.confidence * 100)}%` }}
                />
              </div>
            </div>

            <div className="mt-2 h-32 rounded-xl border border-slate-700/70 bg-slate-900/50 p-1.5">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={mlChart}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.16)" />
                  <XAxis dataKey="t" stroke="#94a3b8" tick={{ fontSize: 11 }} />
                  <YAxis domain={[0, 1]} stroke="#94a3b8" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0b1220",
                      border: "1px solid rgba(148, 163, 184, 0.3)",
                      borderRadius: 10
                    }}
                  />
                  <Line type="monotone" dataKey="v" stroke={underAttack ? "#ff5d73" : "#1ed6a6"} strokeWidth={2.4} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </motion.article>

          <motion.article initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="glass-panel min-h-0 rounded-2xl p-3">
            <h2 className="font-display text-base font-semibold">Decision + Defense</h2>
            <div
              className={`mt-2 rounded-2xl border p-3 text-center ${
                state.decision.action === "block" ? "border-rose-400/55 bg-rose-500/10" : "border-emerald-400/50 bg-emerald-500/10"
              }`}
            >
              <p className="font-mono text-xs uppercase tracking-widest text-slate-300">Final action</p>
              <p className={`metric-value mt-1.5 text-4xl ${state.decision.action === "block" ? "text-neon-danger" : "text-neon-ok"}`}>
                {state.decision.action.toUpperCase()}
              </p>
            </div>

            <div className="mt-2 max-h-40 overflow-auto rounded-xl border border-slate-700/70 bg-slate-900/50 p-2.5">
              <p className="mb-2 font-mono text-xs uppercase tracking-wider text-slate-400">Blocked IP list</p>
              <div className="space-y-1.5">
                {blockedIps.map((ip) => (
                  <motion.div
                    key={ip}
                    layout
                    initial={{ opacity: 0, x: 10 }}
                    animate={{ opacity: 1, x: 0 }}
                    className="rounded-lg border border-rose-400/35 bg-rose-500/10 px-2.5 py-1.5 font-mono text-xs text-rose-100"
                  >
                    {ip}
                  </motion.div>
                ))}
                {!blockedIps.length && <p className="font-mono text-xs text-slate-400">No blocked IPs yet</p>}
              </div>
            </div>
          </motion.article>
        </section>
        </div>
      </div>
    </div>
  );
}

export default App;
