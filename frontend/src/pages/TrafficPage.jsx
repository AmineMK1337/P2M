import { motion } from "framer-motion";
import {
  LineChart,
  Line,
  ResponsiveContainer,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip
} from "recharts";

function normalizeConnections(rows) {
  return (rows || []).slice(0, 12).map((conn, idx) => ({
    id: conn.id || `${conn.ip || conn.src_ip || "unknown"}-${idx}`,
    ip: conn.ip || conn.src_ip || "unknown",
    target: conn.target || conn.dst_ip || "unknown",
    port: conn.port || conn.dst_port || "-",
    protocol: conn.protocol || "TCP"
  }));
}

function TrafficPage({ state }) {
  const chartData = (state.traffic.history || []).slice(-24);
  const connections = normalizeConnections(state.traffic.connections);

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-5">
      <section className="glass-panel rounded-2xl p-4 xl:col-span-3">
        <header className="mb-3 flex items-center justify-between">
          <h2 className="font-display text-lg font-semibold">Live Packets/sec</h2>
          <span className="status-pill status-warn">Capture: {state.capture.status}</span>
        </header>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.18)" />
              <XAxis dataKey="t" stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <YAxis stroke="#94a3b8" tick={{ fontSize: 11 }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0b1220",
                  border: "1px solid rgba(148, 163, 184, 0.3)",
                  borderRadius: 10
                }}
              />
              <Line type="monotone" dataKey="v" stroke="#3bc4ff" strokeWidth={2.4} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      <motion.section
        initial={{ opacity: 0, x: 8 }}
        animate={{ opacity: 1, x: 0 }}
        className="glass-panel rounded-2xl p-4 xl:col-span-2"
      >
        <h2 className="mb-3 font-display text-lg font-semibold">Incoming Connections</h2>
        <div className="max-h-72 overflow-auto rounded-xl border border-slate-700/70">
          <table className="w-full border-collapse font-mono text-xs md:text-sm">
            <thead className="bg-slate-900/70 text-slate-300">
              <tr>
                <th className="px-2 py-2 text-left">Source</th>
                <th className="px-2 py-2 text-left">Destination</th>
                <th className="px-2 py-2 text-left">Port</th>
                <th className="px-2 py-2 text-left">Proto</th>
              </tr>
            </thead>
            <tbody>
              {connections.map((row) => (
                <tr key={row.id} className="border-t border-slate-700/60 text-slate-200">
                  <td className="px-2 py-2">{row.ip}</td>
                  <td className="px-2 py-2">{row.target}</td>
                  <td className="px-2 py-2">{row.port}</td>
                  <td className="px-2 py-2">{row.protocol}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.section>
    </div>
  );
}

export default TrafficPage;
