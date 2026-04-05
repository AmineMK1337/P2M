import { motion } from "framer-motion";

function statusClass(state) {
  if (state === "danger") return "border-rose-400/55 bg-rose-500/10 text-rose-100 animate-pulse";
  if (state === "warn") return "border-amber-300/55 bg-amber-400/10 text-amber-100";
  return "border-cyan-300/45 bg-cyan-400/10 text-cyan-100";
}

function StageCard({ title, subtitle, value, state = "ok", icon = "*" }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={`glass-panel rounded-2xl border p-3 ${statusClass(state)}`}
    >
      <p className="font-mono text-[11px] uppercase tracking-wider opacity-80">
        <span className="mr-1">{icon}</span>
        {title}
      </p>
      <p className="mt-1 text-sm opacity-90">{subtitle}</p>
      <p className="metric-value mt-2 text-xl">{value}</p>
    </motion.div>
  );
}

export default StageCard;
