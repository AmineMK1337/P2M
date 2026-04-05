import { motion } from "framer-motion";
import StageCard from "./StageCard";

function levelForValue(value) {
  const text = String(value || "").toLowerCase();
  if (text.includes("attack") || text.includes("block")) return "danger";
  if (text.includes("warn") || text.includes("pending")) return "warn";
  return "ok";
}

function PipelineFlow({ state }) {
  const stages = [
    {
      title: "Traffic",
      icon: "[T]",
      subtitle: "live packets",
      value: `${state.traffic.pps} pps`
    },
    {
      title: "Capture",
      icon: "[C]",
      subtitle: state.capture.source,
      value: `${state.capture.pcaps} pcaps (${state.capture.status})`
    },
    {
      title: "Features",
      icon: "[F]",
      subtitle: "flow extraction",
      value: `${state.features.flows} flows`
    },
    {
      title: "ML",
      icon: "[M]",
      subtitle: state.ml.attackType,
      value: `${state.ml.prediction.toUpperCase()} ${Math.round(state.ml.confidence * 100)}%`
    },
    {
      title: "Decision",
      icon: "[D]",
      subtitle: state.decision.source,
      value: state.decision.action.toUpperCase()
    },
    {
      title: "Defense",
      icon: "[S]",
      subtitle: "mitigation",
      value: `${state.defense.total} blocked`
    }
  ];

  const attackFlow = state.ml.prediction === "attack" || state.decision.action === "block";

  return (
    <div className="glass-panel relative overflow-hidden rounded-2xl p-4 md:p-5">
      <div className="absolute left-0 right-0 top-1/2 hidden h-[2px] -translate-y-1/2 bg-slate-700/70 lg:block" />

      {Array.from({ length: 6 }).map((_, idx) => (
        <motion.span
          key={`flow-dot-${idx}`}
          className={`absolute top-1/2 hidden h-2 w-2 -translate-y-1/2 rounded-full lg:block ${
            attackFlow ? "bg-rose-300" : "bg-cyan-200"
          }`}
          initial={{ left: "-2%", opacity: 0 }}
          animate={{ left: "102%", opacity: [0, 1, 1, 0] }}
          transition={{ duration: 4.2, repeat: Infinity, delay: idx * 0.62, ease: "linear" }}
        />
      ))}

      <div className="relative grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
        {stages.map((stage, index) => (
          <StageCard
            key={stage.title}
            title={stage.title}
            icon={stage.icon}
            subtitle={stage.subtitle}
            value={stage.value}
            state={
              attackFlow && (stage.title === "ML" || stage.title === "Decision")
                ? "danger"
                : levelForValue(stage.value)
            }
            index={index}
          />
        ))}
      </div>
    </div>
  );
}

export default PipelineFlow;
