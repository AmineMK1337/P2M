import { motion } from "framer-motion";

const NODES = [
  { left: "8%", top: "14%" },
  { left: "24%", top: "30%" },
  { left: "42%", top: "18%" },
  { left: "63%", top: "26%" },
  { left: "79%", top: "14%" },
  { left: "14%", top: "62%" },
  { left: "35%", top: "74%" },
  { left: "60%", top: "66%" },
  { left: "82%", top: "72%" }
];

const EDGES = [
  [0, 1],
  [1, 2],
  [2, 3],
  [3, 4],
  [1, 5],
  [2, 6],
  [3, 7],
  [4, 8],
  [5, 6],
  [6, 7],
  [7, 8]
];

function AnimatedBackground({ danger = false }) {
  const edgeColor = danger ? "rgba(255, 93, 115, 0.18)" : "rgba(59, 196, 255, 0.18)";
  const nodeColor = danger ? "#ff5d73" : "#1ed6a6";

  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <div className="grid-overlay" />

      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 1000 600" preserveAspectRatio="none">
        {EDGES.map(([a, b], idx) => (
          <line
            key={`${a}-${b}-${idx}`}
            x1={parseFloat(NODES[a].left) * 10}
            y1={parseFloat(NODES[a].top) * 6}
            x2={parseFloat(NODES[b].left) * 10}
            y2={parseFloat(NODES[b].top) * 6}
            stroke={edgeColor}
            strokeWidth="1.2"
          />
        ))}
      </svg>

      {NODES.map((node, idx) => (
        <motion.span
          key={`node-${idx}`}
          className="absolute block h-2.5 w-2.5 rounded-full"
          style={{ left: node.left, top: node.top, backgroundColor: nodeColor }}
          animate={{ opacity: [0.25, 0.9, 0.25], scale: [0.95, 1.2, 0.95] }}
          transition={{ duration: 3.2 + idx * 0.27, repeat: Infinity }}
        />
      ))}

      {Array.from({ length: 18 }).map((_, idx) => (
        <motion.span
          key={`particle-${idx}`}
          className={`absolute h-1.5 w-1.5 rounded-full ${danger ? "bg-rose-300/60" : "bg-cyan-200/60"}`}
          style={{ left: `${3 + idx * 5.2}%`, top: `${15 + (idx % 7) * 10}%` }}
          animate={{ y: [0, -18, 0], x: [0, idx % 2 ? 12 : -12, 0], opacity: [0.2, 0.85, 0.2] }}
          transition={{ duration: 8 + idx * 0.25, repeat: Infinity }}
        />
      ))}
    </div>
  );
}

export default AnimatedBackground;
