import { motion, AnimatePresence } from "framer-motion";
import { useEffect, useRef, useState } from "react";

const BOUNDS = {
  model_high_confidence:  [0.75, 0.95],
  model_trust_floor:      [0.35, 0.65],
  siem_corroboration_min: [0.55, 0.90],
};

function ThresholdBar({ label, value, bounds }) {
  const [lo, hi] = bounds;
  const pct = Math.round(((value - lo) / (hi - lo)) * 100);
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono text-[11px] text-slate-400">{label}</span>
        <span className="font-mono text-xs font-semibold text-slate-200">
          {value.toFixed(2)}
        </span>
      </div>
      <div className="relative h-1.5 rounded-full bg-slate-800 overflow-hidden">
        <motion.div
          className="absolute left-0 top-0 h-full rounded-full bg-cyan-400"
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
        />
      </div>
      <div className="flex justify-between mt-0.5">
        <span className="font-mono text-[10px] text-slate-600">{lo}</span>
        <span className="font-mono text-[10px] text-slate-600">{hi}</span>
      </div>
    </div>
  );
}

function PulseDot({ active }) {
  return (
    <span className="relative flex h-2.5 w-2.5">
      {active && (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-60" />
      )}
      <span
        className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
          active ? "bg-cyan-400" : "bg-slate-600"
        }`}
      />
    </span>
  );
}

function RLThresholdPanel({ rl }) {
  const prevRef = useRef(rl);
  const [justUpdated, setJustUpdated] = useState(false);

  useEffect(() => {
    const prev = prevRef.current;
    if (
      prev.cycle_count !== rl.cycle_count ||
      prev.model_high_confidence !== rl.model_high_confidence ||
      prev.model_trust_floor !== rl.model_trust_floor ||
      prev.siem_corroboration_min !== rl.siem_corroboration_min
    ) {
      setJustUpdated(true);
      const t = setTimeout(() => setJustUpdated(false), 3000);
      prevRef.current = rl;
      return () => clearTimeout(t);
    }
    prevRef.current = rl;
  }, [rl]);

  const lastUpdatedLabel = rl.last_run_at
    ? new Date(rl.last_run_at).toLocaleTimeString()
    : "not yet";

  const rewardColor =
    rl.last_reward > 0
      ? "text-emerald-400"
      : rl.last_reward < 0
      ? "text-rose-400"
      : "text-slate-400";

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className={`panel p-4 md:p-5 ${justUpdated ? "ring-1 ring-cyan-400/40" : ""}`}
    >
      <header className="mb-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <PulseDot active={justUpdated} />
          <h2 className="font-display text-lg font-semibold text-slate-100">
            RL Threshold Optimizer
          </h2>
        </div>
        <span className="rounded-md border border-cyan-400/30 bg-cyan-400/10 px-2 py-1 font-mono text-xs text-cyan-300">
          cycle #{rl.cycle_count}
        </span>
      </header>

      {/* Threshold bars */}
      <div className="mb-4 space-y-3 rounded-xl border border-slate-700/60 bg-slate-900/70 p-4">
        <ThresholdBar
          label="model_high_confidence"
          value={rl.model_high_confidence}
          bounds={BOUNDS.model_high_confidence}
        />
        <ThresholdBar
          label="model_trust_floor"
          value={rl.model_trust_floor}
          bounds={BOUNDS.model_trust_floor}
        />
        <ThresholdBar
          label="siem_corroboration_min"
          value={rl.siem_corroboration_min}
          bounds={BOUNDS.siem_corroboration_min}
        />
        <div className="flex items-center justify-between pt-1">
          <span className="font-mono text-[11px] text-slate-400">
            suspicious_escalate_count
          </span>
          <div className="flex gap-1">
            {[2, 3, 4, 5, 6].map((n) => (
              <span
                key={n}
                className={`h-2 w-2 rounded-full ${
                  n <= rl.suspicious_escalate_count
                    ? "bg-amber-400"
                    : "bg-slate-700"
                }`}
              />
            ))}
            <span className="ml-1 font-mono text-xs font-semibold text-slate-200">
              {rl.suspicious_escalate_count}
            </span>
          </div>
        </div>
      </div>

      {/* Last cycle info */}
      <AnimatePresence>
        {justUpdated && (
          <motion.div
            key="update-flash"
            initial={{ opacity: 0, scale: 0.97 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0 }}
            className="mb-3 rounded-xl border border-cyan-400/30 bg-cyan-400/8 p-3"
          >
            <p className="font-mono text-xs text-cyan-300">
              ⟳ Thresholds updated
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      <div className="grid grid-cols-2 gap-2 rounded-xl border border-slate-700/60 bg-slate-900/70 p-3 text-xs">
        <div>
          <p className="font-mono text-slate-400">Last action</p>
          <p className="mt-1 font-mono text-slate-200 break-all">{rl.last_action}</p>
        </div>
        <div>
          <p className="font-mono text-slate-400">Reward</p>
          <p className={`mt-1 font-mono font-semibold ${rewardColor}`}>
            {rl.last_reward > 0 ? "+" : ""}{rl.last_reward.toFixed(2)}
          </p>
        </div>
        <div className="col-span-2">
          <p className="font-mono text-slate-400">Last cycle</p>
          <p className="mt-1 font-mono text-slate-300">{lastUpdatedLabel}</p>
        </div>
      </div>
    </motion.section>
  );
}

export default RLThresholdPanel;
