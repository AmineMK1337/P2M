import { useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";

function LogFeedPanel({ logs }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogStyle = (text) => {
    const lower = text.toLowerCase();
    if (lower.includes("block") || lower.includes("failed")) {
      return "text-rose-400 font-medium";
    }
    if (lower.includes("attack") || lower.includes("intrusion") || lower.includes("mitigat")) {
      return "text-amber-400";
    }
    if (lower.includes("benign") || lower.includes("ok") || lower.includes("success")) {
      return "text-emerald-400";
    }
    return "text-slate-300";
  };

  return (
    <motion.article 
      initial={{ opacity: 0, y: 8 }} 
      animate={{ opacity: 1, y: 0 }} 
      className="glass-panel flex flex-col min-h-0 rounded-2xl p-3 h-full"
    >
      <div className="flex items-center justify-between mb-2">
        <h2 className="font-display text-base font-semibold">Mitigation Agent & System Logs</h2>
        <div className="flex items-center gap-1.5">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
          </span>
          <span className="font-mono text-xs text-cyan-400 uppercase tracking-wider">Live Feed</span>
        </div>
      </div>
      
      <div 
        ref={scrollRef}
        className="flex-1 overflow-auto rounded-xl border border-slate-700/70 bg-slate-900/50 p-2.5 font-mono text-[11px] md:text-xs tracking-tight leading-relaxed space-y-1.5"
      >
        <AnimatePresence initial={false}>
          {logs && logs.length > 0 ? (
            logs.map((log, index) => (
              <motion.div
                key={`${index}-${log}`}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className={`py-1 border-b border-slate-800/50 last:border-0 ${getLogStyle(log)}`}
              >
                <div className="flex gap-2">
                  <span className="text-slate-500 shrink-0 select-none">&gt;</span>
                  <span className="break-words">{log}</span>
                </div>
              </motion.div>
            ))
          ) : (
            <p className="text-slate-500 italic mt-2">Waiting for telemetry...</p>
          )}
        </AnimatePresence>
      </div>
    </motion.article>
  );
}

export default LogFeedPanel;
