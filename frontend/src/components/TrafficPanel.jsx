import { motion } from "framer-motion";

function TrafficPanel({ data }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      className="panel p-4 md:p-5"
    >
      <header className="mb-4 flex items-center justify-between">
        <h2 className="font-display text-lg font-semibold text-slate-100">Live Traffic</h2>
        <span className="rounded-md border border-cyan-400/30 bg-cyan-400/10 px-2 py-1 font-mono text-xs text-cyan-200">
          {data.flowSource} - 2s poll
        </span>
      </header>

      <div className="mb-4 rounded-xl border border-slate-700/60 bg-slate-900/70 p-4">
        <p className="font-mono text-xs uppercase tracking-widest text-slate-400">Packets / second</p>
        <motion.p
          key={data.packetsPerSecond}
          initial={{ y: 10, opacity: 0 }}
          animate={{ y: 0, opacity: 1 }}
          className="mt-2 font-display text-4xl font-bold text-accent"
        >
          {data.packetsPerSecond.toLocaleString()}
        </motion.p>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-700/60">
        <table className="w-full border-collapse font-mono text-xs md:text-sm">
          <thead className="bg-slate-900/80 text-slate-300">
            <tr>
              <th className="px-3 py-2 text-left">Source IP</th>
              <th className="px-3 py-2 text-left">Destination</th>
              <th className="px-3 py-2 text-left">Port</th>
              <th className="px-3 py-2 text-left">Protocol</th>
            </tr>
          </thead>
          <tbody>
            {data.connections.map((conn) => (
              <tr key={conn.id || `${conn.ip}-${conn.port}`} className="border-t border-slate-700/60 text-slate-200">
                <td className="px-3 py-2">{conn.ip}</td>
                <td className="px-3 py-2">{conn.target || "-"}</td>
                <td className="px-3 py-2">{conn.port}</td>
                <td className="px-3 py-2">{conn.protocol}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.section>
  );
}

export default TrafficPanel;
