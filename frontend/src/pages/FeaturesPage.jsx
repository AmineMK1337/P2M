import { motion } from "framer-motion";

function FeaturesPage({ state }) {
  const items = state.features.items || [];

  return (
    <div className="space-y-4">
      <section className="glass-panel rounded-2xl p-4">
        <div className="flex items-center justify-between">
          <h2 className="font-display text-lg font-semibold">Extracted Flow Features</h2>
          <span className="status-pill status-ok">{state.features.flows} flow records</span>
        </div>
      </section>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {items.map((item, idx) => (
          <motion.div
            key={item.key}
            layout
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.03 }}
            className={`glass-panel rounded-2xl p-4 ${item.changed ? "ring-1 ring-cyan-300/50" : ""}`}
          >
            <p className="font-mono text-xs uppercase tracking-wider text-slate-400">{item.label}</p>
            <p className="metric-value mt-2 text-2xl text-neon-info">
              {item.value}
              <span className="ml-1 text-sm text-slate-400">{item.unit}</span>
            </p>
            <p className="mt-2 text-xs text-slate-400">{item.changed ? "updated" : "stable"}</p>
          </motion.div>
        ))}
      </div>
    </div>
  );
}

export default FeaturesPage;
