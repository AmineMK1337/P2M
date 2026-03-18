# ANDS — Project Instructions

## What is ANDS?

ANDS (Adaptive Network Defense System) is an AI-powered cybersecurity platform designed to
automatically detect, classify, and mitigate cyberattacks in real time. It replaces traditional
static, signature-based defenses with a dynamic pipeline that combines machine learning,
historical context, and automated response.

The system is a research and engineering project developed as part of an academic curriculum,
targeting a simulated lab environment. It is not a commercial product.

---

## Problem it solves

Traditional intrusion detection systems rely on fixed rules and known attack signatures.
They fail against novel attack patterns, generate too many false positives, and require
constant manual tuning. ANDS addresses this by:

- Using a trained ML model to classify network traffic behaviorally, not by signature
- Cross-referencing every detection against historical alert data from Kibana to reduce false positives
- Automatically applying network-level mitigations without human intervention

---

## Lab Environment

The system runs against a controlled two-machine simulation:

- **Attacker:** Kali Linux VM — generates attacks using tools like `hping3`, `nmap`, `hydra`, and `slowloris`
- **Victim:** Ubuntu VM — receives traffic, runs CICFlowMeter for feature extraction, and is the target of mitigations (iptables rules)

Network traffic flows from Kali -> Ubuntu. The Ubuntu machine is where all agents run.

---

## How it works — the pipeline

```
Network traffic (Kali -> Ubuntu)
        ↓
CICFlowMeter extracts ~80 features per flow (packet lengths, flags, duration, rates…)
        ↓
Fused Detection + Classification Agent
  · ML model:   "Is this an attack? If yes, what type?"
  · Kibana:     "Have we seen this IP doing this attack type recently?"
  · Fusion:     Combine both signals -> final confidence score
        ↓
  If attack confirmed -> ClassificationResult passed to Agent 3
        ↓
DDoS Prevention Agent
  · If attack type is DDoS -> block source IP via iptables on Ubuntu VM
```

---

## The agents

### Fused Detection + Classification Agent

The core of the system. Takes a raw network flow as input and produces a verdict.

It works in two steps internally:

1. A trained machine learning model classifies the flow and outputs an attack type and confidence score
2. Kibana is queried for recent alerts matching the same source IP and attack type — if history exists, it corroborates (or overrides) the model's confidence

The final decision is made by a simple rule: trust whichever source (model or Kibana history) has higher confidence. No LLM is involved — this is intentional. The pipeline must be fast, deterministic, and work without a running language model.

### DDoS Prevention Agent

Receives confirmed attack classifications. Currently focused on DDoS mitigation only.
When a DDoS is confirmed, it blocks the source IP on the Ubuntu VM using firewall rules.
It must be idempotent — applying the same block twice should have no effect.

---

## Kibana's role

Kibana (backed by Elasticsearch) serves as the system's memory. Every classification result —
attack or benign — is written back to Kibana. This means:

- The longer the system runs, the better it gets at recognizing repeat offenders
- A low-confidence model prediction can be elevated if Kibana shows the same IP has been flagged before
- A high-confidence model prediction can stand alone if no history exists yet

The Kibana query matches on **both source IP and attack type** within a configurable time window (default: last 10 minutes). Recency matters — alerts from the last 2 minutes are weighted more heavily.

---

## Data

The ML model was trained on the **Improved CIC-IDS2017 and CSE-CIC-IDS2018 datasets** — large,
labeled network intrusion datasets containing both normal traffic and attacks including DDoS,
port scanning, brute force, web attacks, botnets, and infiltration attempts.

Feature extraction is done by **CICFlowMeter**, which converts raw packet captures into
structured CSV rows with ~80 numeric features (flow duration, packet length statistics,
inter-arrival times, TCP flag counts, etc.).

---

## Design principles

- **No LLM in the hot path.** The detection and classification pipeline must work without a language model running. LLM integration is reserved for optional explainability features only.
- **Adapter pattern for all external systems.** Kibana, iptables, and the flow input source are all accessed through swappable interfaces. This makes it easy to replace the stub with a real system without touching agent logic.
- **Callbacks as the only bridge between agents.** Agents do not import each other. The only way data moves between them is through a callback function passed at initialization.
- **Dataclasses for all structured data.** Every input, intermediate, and output object has a typed schema defined in `shared/schemas.py`. No plain dicts passed between components.
- **Determinism over flexibility.** Fusion rules are fixed and explicit. The system should behave predictably under the same inputs every time.

---

## Scope and limitations

- The system currently targets a **two-machine simulated environment**, not production networks
- Mitigation is limited to **IP blocking via iptables** — no rate limiting or traffic shaping yet
- The ML model is a **supervised classifier** — it can only identify attack types it was trained on. Zero-day detection is not in scope for the current version.
- The Kibana integration requires Elasticsearch to be running and indexed — a stub is provided for development without a live cluster

---

## What comes next

- Completing Agent 3 (DDoS Prevention Agent) with full iptables integration
- Setting up CICFlowMeter on the Ubuntu VM for live traffic capture
- Running end-to-end tests with real attacks from Kali
- Evaluating detection latency and false positive rate across attack types
