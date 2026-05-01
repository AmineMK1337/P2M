import { createMockSystemState } from "../data/mockData";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function asArray(value) {
  if (Array.isArray(value)) return value;
  if (value == null) return [];
  return [value];
}

function pick(obj, keys, fallback = undefined) {
  for (const key of keys) {
    if (obj && obj[key] !== undefined && obj[key] !== null) return obj[key];
  }
  return fallback;
}

function parseIp(text) {
  const match = String(text || "").match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return match ? match[0] : null;
}

async function fetchJSON(endpoint) {
  const response = await fetch(`${API_BASE}${endpoint}`);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  return await response.json();
}

export async function fetchDashboard() {
  return fetchJSON("/api/dashboard");
}

export async function fetchSystem() {
  return fetchJSON("/api/system");
}

export async function fetchLogs() {
  return fetchJSON("/api/logs");
}

export async function fetchAgentsStatus() {
  return fetchJSON("/api/agents/status");
}

function normalize(dashboard, system, logs) {
  const traffic = dashboard.traffic || {};
  const capture = system.capture || {};
  const features = dashboard.features || {};
  const detection = dashboard.detection || {};
  const decision = dashboard.decision || {};
  const defense = dashboard.defense || {};

  const featureItems = asArray(features.items || []).map((f, idx) => ({
    key: String(f.key || `feature_${idx}`),
    label: String(f.label || f.key || `Feature ${idx + 1}`),
    value: f.value ?? "-",
    unit: f.unit || "",
    changed: Boolean(f.changed)
  }));

  const blockedIps = Array.from(
    new Set([
      ...asArray(defense.blocked_ips),
      parseIp(defense.last_blocked_ip)
    ].filter(Boolean))
  );

  const predictionText = String(detection.prediction || "normal").toLowerCase();
  const isAttack =
    predictionText.includes("attack") ||
    predictionText.includes("intrusion") ||
    predictionText.includes("ddos") ||
    predictionText.includes("scan");

  const confidenceRaw = toNumber(detection.confidence || (isAttack ? 0.8 : 0.2), isAttack ? 0.8 : 0.2);
  const confidence = confidenceRaw > 1 ? confidenceRaw / 100 : confidenceRaw;

  const action = String(decision.action || (isAttack ? "block" : "allow")).toLowerCase();

  return {
    timestamp: new Date().toISOString(),
    status: isAttack ? "UNDER ATTACK" : "ACTIVE",
    traffic: {
      pps: toNumber(traffic.pps, 0),
      connections: asArray(traffic.connections),
      history: asArray(traffic.history)
    },
    capture: {
      pcaps: toNumber(capture.pcaps, 0),
      status: String(capture.status || "running"),
      source: String(capture.source || "cicflowmeter")
    },
    features: {
      flows: toNumber(features.flows, featureItems.length),
      items: featureItems,
      raw: features
    },
    ml: {
      prediction: isAttack ? "attack" : "normal",
      confidence,
      modelConfidence: toNumber(detection.model_confidence, confidence),
      siemConfidence: toNumber(detection.siem_confidence, 0),
      attackType: String(detection.attack_type || (isAttack ? "Intrusion" : "BENIGN")),
      reasoning: String(detection.reasoning || "No reasoning text provided."),
      history: asArray(detection.history)
    },
    decision: {
      action: action.includes("block") ? "block" : "allow",
      source: String(decision.source || "policy"),
      confidence: toNumber(decision.confidence, confidence)
    },
    defense: {
      last_blocked_ip: String(defense.last_blocked_ip || blockedIps[0] || "none"),
      total: toNumber(defense.total, blockedIps.length),
      blocked_ips: blockedIps,
      actions: asArray(defense.actions || [])
    },
    mitigation: dashboard.mitigation || {},
    systemMetrics: {
      cpu: system.cpu || 0,
      ram: system.ram || 0,
      network: system.network || { bytes_sent: 0, bytes_recv: 0 }
    },
    logs: asArray(logs.logs || []).slice(0, 20).reverse()
  };
}

export async function fetchSystemState(previousState = null) {
  try {
    const [dashboard, system, logs] = await Promise.all([
      fetchDashboard(),
      fetchSystem(),
      fetchLogs()
    ]);

    const state = normalize(dashboard, system, logs);

    return {
      state,
      source: "api-grouped"
    };
  } catch (err) {
    console.warn("API fetch failed, falling back to mock state:", err.message);
    return {
      state: createMockSystemState(previousState),
      source: "mock-fallback"
    };
  }
}
