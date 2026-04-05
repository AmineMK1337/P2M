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

function DetectionPage({ state }) {
  const attack = state.ml.prediction === "attack";
  const confidence = Math.round((state.ml.confidence || 0) * 100);
  const chartData = (state.ml.history || []).slice(-24);

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
      <section className={`glass-panel rounded-2xl p-4 xl:col-span-2 ${attack ? "ring-1 ring-rose-400/45" : ""}`}>
        <h2 className="font-display text-lg font-semibold">Model Decision</h2>
        <p className={`metric-value mt-3 text-5xl ${attack ? "text-neon-danger" : "text-neon-ok"}`}>
          {state.ml.prediction.toUpperCase()}
        </p>
        <p className="mt-2 font-mono text-sm text-slate-300">{state.ml.attackType}</p>

        <div className="mt-4 h-2 rounded-full bg-slate-800">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${confidence}%` }}
            className={`h-full rounded-full ${attack ? "bg-rose-400" : "bg-emerald-400"}`}
          />
        </div>
        <p className="mt-2 text-xs text-slate-400">confidence {confidence}%</p>

        <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
          <div className="rounded-lg border border-slate-700/70 bg-slate-900/50 p-2">
            <p className="font-mono text-slate-400">model</p>
            <p className="mt-1 text-neon-info">{Math.round((state.ml.modelConfidence || 0) * 100)}%</p>
          </div>
          <div className="rounded-lg border border-slate-700/70 bg-slate-900/50 p-2">
            <p className="font-mono text-slate-400">siem</p>
            <p className="mt-1 text-amber-300">{Math.round((state.ml.siemConfidence || 0) * 100)}%</p>
          </div>
        </div>
      </section>

      <section className="glass-panel rounded-2xl p-4 xl:col-span-3">
        <h2 className="mb-3 font-display text-lg font-semibold">Prediction Timeline</h2>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.18)" />
              <XAxis dataKey="t" stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <YAxis domain={[0, 1]} stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0b1220",
                  border: "1px solid rgba(148, 163, 184, 0.3)",
                  borderRadius: 10
                }}
              />
              <Line type="monotone" dataKey="v" stroke={attack ? "#ff5d73" : "#1ed6a6"} strokeWidth={2.5} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="mt-3 rounded-xl border border-slate-700/70 bg-slate-900/45 p-3 text-sm text-slate-300">
          {state.ml.reasoning}
        </div>
      </section>
    </div>
  );
}

export default DetectionPage;
