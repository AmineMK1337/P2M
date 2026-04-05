import { NavLink } from "react-router-dom";
import { motion } from "framer-motion";

const NAV_ITEMS = [
  { to: "/", label: "Overview", short: "OV" },
  { to: "/traffic", label: "Traffic", short: "TR" },
  { to: "/features", label: "Features", short: "FT" },
  { to: "/detection", label: "Detection", short: "ML" },
  { to: "/decision", label: "Decision", short: "DF" }
];

function Sidebar({ collapsed, onToggle }) {
  return (
    <motion.aside
      animate={{ width: collapsed ? 88 : 246 }}
      transition={{ type: "spring", stiffness: 160, damping: 20 }}
      className="glass-panel m-3 hidden flex-col rounded-2xl p-3 md:flex"
    >
      <button
        type="button"
        onClick={onToggle}
        className="mb-3 rounded-lg border border-slate-700/70 bg-slate-900/55 px-3 py-2 text-left font-mono text-xs text-slate-200"
      >
        {collapsed ? "Expand" : "Collapse"}
      </button>

      <div className="space-y-2">
        {NAV_ITEMS.map((item) => (
          <NavLink key={item.to} to={item.to} end={item.to === "/"}>
            {({ isActive }) => (
              <motion.div
                whileHover={{ x: 3 }}
                className={`rounded-xl border px-3 py-3 ${
                  isActive
                    ? "border-cyan-300/50 bg-cyan-400/15 text-cyan-100"
                    : "border-slate-700/70 bg-slate-900/45 text-slate-300"
                }`}
              >
                <p className="font-mono text-[11px] tracking-wider">{collapsed ? item.short : item.label}</p>
              </motion.div>
            )}
          </NavLink>
        ))}
      </div>

      <div className="mt-auto rounded-xl border border-slate-700/70 bg-slate-900/45 p-3">
        <p className="font-mono text-[11px] text-slate-400">ANDS Control Plane</p>
      </div>
    </motion.aside>
  );
}

export default Sidebar;
