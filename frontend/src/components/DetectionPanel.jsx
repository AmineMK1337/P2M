import { motion } from "framer-motion";
import {
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  CartesianGrid
} from "recharts";

function DetectionPanel({ prediction, history }) {
  const isAttack = prediction.isAttack || prediction.label === "Attack";
  const confidencePercent = Math.round((prediction.confidence || 0) * 100);
  const modelPercent = Math.round((prediction.modelConfidence || 0) * 100);
  const siemPercent = Math.round((prediction.siemConfidence || 0) * 100);

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className={`panel p-4 md:p-5 ${isAttack ? "ring-1 ring-danger/35" : ""}`}
    >
      <header className="mb-4 flex items-center justify-between">
        <h2 className="font-display text-lg font-semibold text-slate-100">ML Detection</h2>
        <span
          className={`rounded-md px-2 py-1 font-mono text-xs ${
            isAttack
              ? "bg-danger/15 text-danger border border-danger/45"
              : "bg-emerald-400/10 text-emerald-300 border border-emerald-400/30"
          }`}
        >
          {prediction.attackType}
        </span>
      </header>

      <div className="mb-4 grid grid-cols-1 gap-3 rounded-xl border border-slate-700/60 bg-slate-900/70 p-4 sm:grid-cols-2">
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">Prediction Label</p>
          <p className={`mt-2 font-display text-3xl font-bold ${isAttack ? "text-danger" : "text-accent"}`}>
            {prediction.label.toUpperCase()}
          </p>
        </div>
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">Confidence</p>
          <p className="mt-2 font-display text-3xl font-bold text-slate-100">{confidencePercent}%</p>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-800">
            <motion.div
              className={`h-full ${isAttack ? "bg-danger" : "bg-accent"}`}
              initial={{ width: 0 }}
              animate={{ width: `${confidencePercent}%` }}
            />
          </div>
        </div>
      </div>

      <div className="mb-4 grid grid-cols-1 gap-3 rounded-xl border border-slate-700/60 bg-slate-900/70 p-4 md:grid-cols-3">
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">Model Signal</p>
          <p className="mt-1 font-display text-xl font-semibold text-slate-100">{modelPercent}%</p>
        </div>
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">SIEM Signal</p>
          <p className="mt-1 font-display text-xl font-semibold text-slate-100">{siemPercent}%</p>
          <p className="font-mono text-[11px] text-slate-400">alerts: {prediction.siemAlertCount}</p>
        </div>
        <div>
          <p className="font-mono text-xs uppercase tracking-wider text-slate-400">Decision Source</p>
          <p className="mt-1 font-display text-xl font-semibold text-slate-100">{prediction.decisionSource}</p>
          <p className="font-mono text-[11px] text-slate-400">severity: {prediction.severity}</p>
        </div>
      </div>

      <div className="mb-4 rounded-xl border border-slate-700/60 bg-slate-900/70 p-3">
        <p className="font-mono text-xs uppercase tracking-wider text-slate-400">Reasoning</p>
        <p className="mt-2 text-sm text-slate-200">{prediction.reasoning}</p>
      </div>

      <div className="h-48 rounded-xl border border-slate-700/60 bg-slate-900/70 p-2">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={history}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.15)" />
            <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 11 }} />
            <YAxis domain={[0, "auto"]} stroke="#94a3b8" tick={{ fontSize: 11 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: "#0b1220",
                border: "1px solid rgba(148, 163, 184, 0.3)",
                borderRadius: "10px"
              }}
            />
            <Line type="monotone" dataKey="score" stroke={isAttack ? "#ff4d6d" : "#21d4a7"} strokeWidth={2.5} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </motion.section>
  );
}

export default DetectionPanel;
