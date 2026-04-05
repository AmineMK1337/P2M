let tick = 0;
let blockedIps = ["192.168.10.72"];
let totalBlocked = 1;

const PROTOCOLS = ["TCP", "UDP", "ICMP"];
const ATTACK_TYPES = ["DDoS", "PortScan", "BruteForce", "WebAttack", "Intrusion"];

function randomIp() {
  return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

function randomPort() {
  return Math.floor(Math.random() * 64511) + 1024;
}

function randomProtocol() {
  return PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)];
}

function maybeAttack() {
  return Math.random() > 0.76;
}

function buildHistory(prev = [], value = 0) {
  const next = [...prev, { t: new Date().toLocaleTimeString(), v: Number(value.toFixed(3)) }];
  return next.slice(-24);
}

function randomConnection() {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    ip: randomIp(),
    target: randomIp(),
    port: randomPort(),
    protocol: randomProtocol()
  };
}

export function createMockSystemState(previousState = null) {
  tick += 1;

  const attack = maybeAttack();
  const attackType = attack ? ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)] : "BENIGN";
  const confidence = attack
    ? 0.65 + Math.random() * 0.33
    : 0.08 + Math.random() * 0.37;

  const pps = Math.round(420 + Math.random() * 1250 + (attack ? 720 : 0));
  const flows = Math.round(35 + Math.random() * 130 + (attack ? 55 : 0));
  const captureCount = Math.max(1, Math.round(tick / 3));

  const decisionAction = attack && confidence > 0.62 ? "block" : "allow";
  let newBlocked = null;

  if (decisionAction === "block" && Math.random() > 0.35) {
    newBlocked = randomIp();
    blockedIps = [newBlocked, ...blockedIps.filter((ip) => ip !== newBlocked)].slice(0, 14);
    totalBlocked += 1;
  }

  const featureItems = [
    {
      key: "Flow Duration",
      label: "Flow Duration",
      value: Math.round(180 + Math.random() * 1200),
      unit: "ms",
      changed: false
    },
    {
      key: "Flow Packets/s",
      label: "Flow Packets/s",
      value: Math.round(60 + Math.random() * 260 + (attack ? 120 : 0)),
      unit: "/s",
      changed: false
    },
    {
      key: "Flow Bytes/s",
      label: "Flow Bytes/s",
      value: Math.round(4000 + Math.random() * 15000 + (attack ? 9000 : 0)),
      unit: "/s",
      changed: false
    },
    {
      key: "SYN Flag Count",
      label: "SYN Flag Count",
      value: Math.round(Math.random() * (attack ? 70 : 18)),
      unit: "count",
      changed: false
    },
    {
      key: "Average Packet Size",
      label: "Average Packet Size",
      value: Math.round(220 + Math.random() * 870),
      unit: "bytes",
      changed: false
    },
    {
      key: "Destination Port",
      label: "Destination Port",
      value: randomPort(),
      unit: "",
      changed: false
    }
  ];

  const previousTrafficHistory = previousState?.traffic?.history || [];
  const previousMlHistory = previousState?.ml?.history || [];

  const trafficHistory = buildHistory(previousTrafficHistory, pps);
  const mlScore = attack ? confidence : Math.max(0.05, 1 - confidence);
  const mlHistory = buildHistory(previousMlHistory, mlScore);

  const sourceIp = randomIp();

  const logs = [
    `[Traffic] ${pps} packets/s observed`,
    `[Capture] CICFlowMeter ${captureCount > 0 ? "running" : "idle"}`,
    `[Features] ${flows} flows extracted`,
    `[Detection] ${attack ? "attack" : "normal"} ${attackType} (${Math.round(confidence * 100)}%)`,
    `[Decision] ${decisionAction.toUpperCase()}`,
    decisionAction === "block"
      ? `[Defense] block_ip(${newBlocked || sourceIp}) applied`
      : "[Defense] monitor_only"
  ];

  return {
    timestamp: new Date().toISOString(),
    status: attack ? "UNDER ATTACK" : "ACTIVE",
    traffic: {
      pps,
      connections: [
        { id: `primary-${tick}`, ip: sourceIp, target: randomIp(), port: randomPort(), protocol: randomProtocol() },
        ...Array.from({ length: 8 }, () => randomConnection())
      ],
      history: trafficHistory
    },
    capture: {
      pcaps: captureCount,
      status: "running",
      source: "cicflowmeter"
    },
    features: {
      flows,
      items: featureItems,
      raw: Object.fromEntries(featureItems.map((item) => [item.key, item.value]))
    },
    ml: {
      prediction: attack ? "attack" : "normal",
      confidence,
      modelConfidence: Math.max(0, confidence - 0.07),
      siemConfidence: attack ? Math.max(0, confidence - 0.15) : 0,
      attackType,
      reasoning: attack
        ? `Anomaly score crossed threshold and historical correlation supports ${attackType} classification.`
        : "Current flow behavior remains under anomaly threshold with no corroborated threat signal.",
      history: mlHistory
    },
    decision: {
      action: decisionAction,
      source: attack ? "model+siem" : "model",
      confidence
    },
    defense: {
      last_blocked_ip: blockedIps[0] || "none",
      total: totalBlocked,
      blocked_ips: blockedIps,
      actions:
        decisionAction === "block"
          ? [`block_ip(${blockedIps[0]})`, `alert_soc(${blockedIps[0]})`]
          : ["monitor_only"]
    },
    logs
  };
}
