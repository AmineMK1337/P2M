import { motion } from "framer-motion";

function FeatureCard({ label, value, unit, index, changed }) {
  return (
    <motion.div
      layout
      initial={{ opacity: 0, x: -8 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.05 }}
      className={`rounded-xl border p-3 ${
        changed ? "border-accent/60 bg-accent/10" : "border-slate-700/60 bg-slate-900/70"
      }`}
    >
      <p className="font-mono text-xs uppercase tracking-wider text-slate-400">{label}</p>
      <motion.p
        key={`${label}-${value}`}
        initial={{ scale: 0.94, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        className="mt-2 font-display text-2xl font-semibold text-slate-100"
      >
        {value}
        <span className="ml-1 text-sm text-slate-400">{unit}</span>
      </motion.p>
    </motion.div>
  );
}

function FeaturesPanel({ data }) {
  const items = data.items || [];

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="panel p-4 md:p-5"
    >
      <header className="mb-4 flex items-center justify-between">
        <h2 className="font-display text-lg font-semibold text-slate-100">Feature Extraction</h2>
        <span className="rounded-md border border-accent/35 bg-accent/10 px-2 py-1 font-mono text-xs text-accent">
          {items.length} extracted
        </span>
      </header>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {items.map((item, index) => (
          <FeatureCard key={item.label} {...item} index={index} />
        ))}
      </div>
    </motion.section>
  );
}

export default FeaturesPanel;
