import { useState, useMemo } from "react";
import { Routes, Route } from "react-router-dom";
import { motion } from "framer-motion";
import AnimatedBackground from "./components/AnimatedBackground";
import Sidebar from "./components/Sidebar";
import OverviewPage from "./pages/OverviewPage";
import TrafficPage from "./pages/TrafficPage";
import FeaturesPage from "./pages/FeaturesPage";
import DetectionPage from "./pages/DetectionPage";
import DecisionPage from "./pages/DecisionPage";
import { useSystemState } from "./hooks/useSystemState";

function App() {
  const { state, loading, source, lastUpdated } = useSystemState(2500);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const underAttack = useMemo(() => state?.ml?.prediction === "attack", [state]);

  return (
    <div className="flex h-screen overflow-hidden text-slate-100 selection:bg-cyan-500/30">
      <AnimatedBackground danger={underAttack} />

      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed(!sidebarCollapsed)} />

      <main className="relative z-10 flex flex-1 flex-col overflow-hidden px-3 py-3 md:px-4 md:py-4">
        <motion.header
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          className="glass-panel flex flex-col gap-2 rounded-2xl p-3 md:flex-row md:items-center md:justify-between mb-4 shrink-0"
        >
          <div>
            <h1 className="font-display text-lg font-semibold tracking-wide md:text-2xl text-slate-100">
              ANDS Dashboard
            </h1>
            <p className="font-mono text-[11px] text-slate-400 md:text-xs">
              {"Traffic -> Capture -> Features -> ML -> Decision -> Defense"}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={`status-pill ${underAttack ? "status-danger animate-pulse border-rose-500/60 shadow-[0_0_15px_rgba(244,63,94,0.3)]" : "status-ok"}`}>
              {underAttack ? "UNDER ATTACK" : "ACTIVE"}
            </span>
            <span className="status-pill status-warn">source: {source}</span>
            <span className="status-pill">{loading ? "syncing..." : `updated ${lastUpdated}`}</span>
          </div>
        </motion.header>

        <div className="flex-1 overflow-auto custom-scrollbar">
          <div className="max-w-[1700px] mx-auto pb-6">
            <Routes>
              <Route path="/" element={<OverviewPage state={state} />} />
              <Route path="/traffic" element={<TrafficPage state={state} />} />
              <Route path="/features" element={<FeaturesPage state={state} />} />
              <Route path="/detection" element={<DetectionPage state={state} />} />
              <Route path="/decision" element={<DecisionPage state={state} />} />
            </Routes>
          </div>
        </div>
      </main>
    </div>
  );
}

export default App;
