import { motion } from "framer-motion";

function StatCard({ title, value, hint, tone = "info" }) {
  const toneClass =
    tone === "danger"
      ? "text-neon-danger"
      : tone === "warn"
        ? "text-amber-300"
        : tone === "ok"
          ? "text-neon-ok"
          : "text-neon-info";

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-panel rounded-2xl p-4"
    >
      <p className="font-mono text-xs uppercase tracking-wider text-slate-400">{title}</p>
      <p className={`metric-value mt-2 text-3xl ${toneClass}`}>{value}</p>
      <p className="mt-2 text-xs text-slate-400">{hint}</p>
    </motion.div>
  );
}

export default StatCard;
