import { motion } from "framer-motion";
import PipelineFlow from "../components/PipelineFlow";
import StatCard from "../components/StatCard";
import LogFeedPanel from "../components/LogFeedPanel";

function OverviewPage({ state }) {
  const attack = state.ml.prediction === "attack";

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Packets / sec" value={state.traffic.pps} hint="Live ingress rate" tone={attack ? "warn" : "info"} />
        <StatCard title="Flows Extracted" value={state.features.flows} hint="Feature rows processed" tone="ok" />
        <StatCard
          title="Attacks Detected"
          value={state.ml.prediction === "attack" ? 1 : 0}
          hint={`${Math.round(state.ml.confidence * 100)}% confidence`}
          tone={attack ? "danger" : "ok"}
        />
        <StatCard title="Blocked IPs" value={state.defense.total} hint={`Last: ${state.defense.last_blocked_ip}`} tone={state.defense.total ? "danger" : "info"} />
      </div>

      <PipelineFlow state={state} />

      <div className="grid min-h-0 grid-cols-1 gap-4 lg:grid-cols-[1fr_3fr]">
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-panel rounded-2xl p-4 flex flex-col h-full"
        >
          <div className="flex items-center justify-between">
            <h2 className="font-display text-lg font-semibold">System Status</h2>
            <span className={`status-pill ${attack ? "status-danger" : "status-ok"}`}>{state.status}</span>
          </div>
          <p className="mt-3 text-sm text-slate-300 font-mono flex-1">{state.ml.reasoning}</p>
        </motion.section>

        <section className="h-[280px] lg:h-[320px]">
          <LogFeedPanel logs={state.logs} />
        </section>
      </div>
    </div>
  );
}

export default OverviewPage;
