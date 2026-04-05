import { createMockSystemState } from "../data/mockData";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "";
const LOG_ENDPOINT = import.meta.env.VITE_LOG_ENDPOINT || "/api/logs";

const CANDIDATES = {
  traffic: ["/api/traffic", "/traffic", "/api/system/traffic"],
  features: ["/api/features", "/features", "/api/system/features"],
  detection: ["/api/predictions", "/api/detection", "/api/classification"],
  decision: ["/api/decisions", "/api/defense", "/api/mitigation"],
  snapshot: ["/api/system_state", "/api/state", "/api/dashboard"]
};

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

function timeoutFetch(url, mode = "json", timeoutMs = 1500) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);

  return fetch(url, { signal: controller.signal })
    .then((res) => {
      if (!res.ok) throw new Error(String(res.status));
      return mode === "text" ? res.text() : res.json();
    })
    .finally(() => clearTimeout(id));
}

async function firstAvailable(paths, mode = "json") {
  for (const path of paths) {
    try {
      return await timeoutFetch(`${API_BASE}${path}`, mode);
    } catch {
      continue;
    }
  }
  return null;
}

function parseLogText(logText) {
  const lines = String(logText || "")
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean)
    .slice(-80);

  let attacks = 0;
  let ppsHint = 0;
  const blocked = [];

  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.includes("attack") || lower.includes("intrusion")) attacks += 1;

    const ppsMatch = line.match(/(\d+)\s*(pps|packets\/s|packets per second)/i);
    if (ppsMatch) ppsHint = toNumber(ppsMatch[1], ppsHint);

    if (lower.includes("block") || lower.includes("iptables") || lower.includes("mitigat")) {
      const ip = parseIp(line);
      if (ip) blocked.push(ip);
    }
  }

  return {
    logs: lines.slice(-12).reverse(),
    attacks,
    ppsHint,
    blockedIps: Array.from(new Set(blocked)).slice(0, 12)
  };
}

function normalize(raw) {
  const traffic = raw.traffic || {};
  const capture = raw.capture || {};
  const features = raw.features || {};
  const detection = raw.detection || raw.ml || raw.prediction || {};
  const decision = raw.decision || {};
  const defense = raw.defense || {};

  const featureItems = asArray(features.items || features.list || []).map((f, idx) => ({
    key: String(f.key || f.name || f.feature || `feature_${idx}`),
    label: String(f.label || f.key || f.name || f.feature || `Feature ${idx + 1}`),
    value: f.value ?? f.val ?? f.metric ?? "-",
    unit: f.unit || "",
    changed: Boolean(f.changed)
  }));

  const blockedIps = Array.from(
    new Set([
      ...asArray(defense.blocked_ips),
      ...asArray(defense.blockedIps),
      ...asArray(decision.blocked_ips),
      ...asArray(decision.blockedIps),
      parseIp(defense.last_blocked_ip),
      parseIp(defense.lastBlockedIp),
      parseIp(decision.last_blocked_ip),
      parseIp(decision.lastBlockedIp)
    ].filter(Boolean))
  );

  const predictionText = String(
    pick(detection, ["prediction", "label", "attack_type", "attackType"], "normal")
  ).toLowerCase();
  const isAttack =
    detection.is_attack === true ||
    detection.isAttack === true ||
    predictionText.includes("attack") ||
    predictionText.includes("intrusion") ||
    predictionText.includes("ddos") ||
    predictionText.includes("scan");

  const confidenceRaw = toNumber(
    pick(detection, ["confidence", "model_confidence", "score"], isAttack ? 0.8 : 0.2),
    isAttack ? 0.8 : 0.2
  );
  const confidence = confidenceRaw > 1 ? confidenceRaw / 100 : confidenceRaw;

  const action = String(pick(decision, ["action", "state"], isAttack ? "block" : "allow")).toLowerCase();

  return {
    timestamp: new Date().toISOString(),
    status: isAttack ? "UNDER ATTACK" : "ACTIVE",
    traffic: {
      pps: toNumber(pick(traffic, ["pps", "packets_per_second", "packetsPerSecond"], 0), 0),
      connections: asArray(pick(traffic, ["connections", "incoming", "rows"], [])),
      history: asArray(traffic.history)
    },
    capture: {
      pcaps: toNumber(pick(capture, ["pcaps", "pcap_count", "count"], 0), 0),
      status: String(pick(capture, ["status", "state"], "running")),
      source: String(pick(capture, ["source", "engine"], "cicflowmeter"))
    },
    features: {
      flows: toNumber(pick(features, ["flows", "flow_count", "count"], featureItems.length), featureItems.length),
      items: featureItems,
      raw: features.raw || features
    },
    ml: {
      prediction: isAttack ? "attack" : "normal",
      confidence,
      modelConfidence: toNumber(pick(detection, ["model_confidence", "modelConfidence"], confidence), confidence),
      siemConfidence: toNumber(pick(detection, ["siem_confidence", "siemConfidence"], 0), 0),
      attackType: String(pick(detection, ["attack_type", "attackType", "label"], isAttack ? "Intrusion" : "BENIGN")),
      reasoning: String(pick(detection, ["reasoning", "explanation"], "No reasoning text provided by source.")),
      history: asArray(detection.history)
    },
    decision: {
      action: action.includes("block") ? "block" : "allow",
      source: String(pick(decision, ["source", "decision_source"], "policy")),
      confidence: toNumber(pick(decision, ["confidence"], confidence), confidence)
    },
    defense: {
      last_blocked_ip: String(pick(defense, ["last_blocked_ip", "lastBlockedIp"], blockedIps[0] || "none")),
      total: toNumber(pick(defense, ["total", "blocked_total", "count"], blockedIps.length), blockedIps.length),
      blocked_ips: blockedIps,
      actions: asArray(pick(defense, ["actions", "mitigation_actions"], decision.actions || []))
    },
    logs: asArray(raw.logs || raw.events).slice(0, 20)
  };
}

function integrateLogInsights(state, logData) {
  const next = { ...state };

  if (!next.traffic.pps && logData.ppsHint) {
    next.traffic.pps = logData.ppsHint;
  }

  const mergedBlocked = Array.from(new Set([...next.defense.blocked_ips, ...logData.blockedIps]));
  next.defense.blocked_ips = mergedBlocked;
  next.defense.total = Math.max(next.defense.total, mergedBlocked.length);
  next.defense.last_blocked_ip = mergedBlocked[0] || next.defense.last_blocked_ip;

  if (logData.attacks > 0 && next.ml.prediction === "normal") {
    next.ml.prediction = "attack";
    next.ml.confidence = Math.max(next.ml.confidence, 0.63);
    next.status = "UNDER ATTACK";
    next.decision.action = next.decision.action === "allow" ? "block" : next.decision.action;
  }

  if (!next.logs.length) {
    next.logs = logData.logs;
  }

  return next;
}

export async function fetchSystemState(previousState = null) {
  const snapshot = await firstAvailable(CANDIDATES.snapshot, "json");
  const traffic = await firstAvailable(CANDIDATES.traffic, "json");
  const features = await firstAvailable(CANDIDATES.features, "json");
  const detection = await firstAvailable(CANDIDATES.detection, "json");
  const decision = await firstAvailable(CANDIDATES.decision, "json");
  const logText = await firstAvailable([LOG_ENDPOINT], "text");

  if (!snapshot && !traffic && !features && !detection && !decision && !logText) {
    return { state: createMockSystemState(previousState), source: "mock" };
  }

  const base = normalize(
    snapshot || {
      traffic,
      features,
      detection,
      decision,
      defense: decision,
      logs: []
    }
  );

  const integrated = logText ? integrateLogInsights(base, parseLogText(logText)) : base;

  return {
    state: integrated,
    source: snapshot ? "rest-snapshot" : "rest-modular"
  };
}
