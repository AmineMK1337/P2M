# Adaptive Network Defense System (ANDS)

> **P2M — Mastère Professionnel en Sécurité des Systèmes et Réseaux**  
> Université de Carthage — École Supérieure des Communications de Tunis (SUP'COM)

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Objectives](#2-objectives)
3. [System Architecture](#3-system-architecture)
4. [Datasets](#4-datasets)
5. [Component Deep-Dives](#5-component-deep-dives)
   - 5.1 [Classification Agent](#51-classification-agent)
   - 5.2 [Verification Agent](#52-verification-agent)
   - 5.3 [Mitigation Agent](#53-mitigation-agent)
   - 5.4 [RL Policy Optimizer](#54-rl-policy-optimizer)
   - 5.5 [Policy Engine](#55-policy-engine)
   - 5.6 [LLM Reasoning Engine (ZySec)](#56-llm-reasoning-engine-zysec)
   - 5.7 [Elasticsearch / Kibana Integration](#57-elasticsearch--kibana-integration)
   - 5.8 [FastAPI Backend & React Dashboard](#58-fastapi-backend--react-dashboard)
6. [Model Evaluation & Metrics](#6-model-evaluation--metrics)
   - 6.1 [PCA Anomaly Detector (Deployed Model)](#61-pca-anomaly-detector-deployed-model)
   - 6.2 [Supervised Classifiers (Comparison Study)](#62-supervised-classifiers-comparison-study)
   - 6.3 [Evaluation Script](#63-evaluation-script)
7. [Decision Pipeline — 4 Stages](#7-decision-pipeline--4-stages)
8. [Technologies Stack](#8-technologies-stack)
9. [Project Status](#9-project-status)
10. [Quick Start (Full Stack)](#10-quick-start-full-stack)
11. [Running the CLI](#11-running-the-cli)
12. [Running Tests](#12-running-tests)
13. [Known Issues & Limitations](#13-known-issues--limitations)

---

## 1. Project Overview

The **Adaptive Network Defense System (ANDS)** is an AI-powered cybersecurity platform that automatically detects, classifies, and mitigates cyberattacks in real time. It replaces traditional static, signature-based defenses with dynamic behavioral analysis, multi-signal decision fusion, and an autonomous reinforcement-learning feedback loop that continuously adapts its own detection thresholds.

ANDS implements a **Multi-Agent System (MAS)** in which specialized agents cooperate along a strict pipeline:

```
Network Traffic
      │
      ▼
┌─────────────────────┐
│  CICFlowMeter       │  Extracts 80+ statistical features per flow
└────────┬────────────┘
         │  FlowRecord (CSV)
         ▼
┌─────────────────────┐
│  Classification     │  PCA anomaly detection + ZySec LLM reasoning
│  Agent              │  + SIEM fusion + Verification
└────────┬────────────┘
         │  ClassificationResult
         ▼
┌─────────────────────┐
│  Mitigation Agent   │  Deterministic executor — iptables / netsh
└────────┬────────────┘
         │  MitigationResult
         ▼
┌─────────────────────┐
│  Elasticsearch /    │  Persistent audit trail, alert history,
│  Kibana             │  Q-learning feedback source
└─────────────────────┘
         ↑
┌─────────────────────┐
│  RL Policy          │  Q-learning optimizer running every 5 min
│  Optimizer          │  Adjusts 4 detection thresholds dynamically
└─────────────────────┘
```

---

## 2. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Extract 80+ statistical features from live network traffic using CICFlowMeter | ✅ Done |
| 2 | Detect and classify attack types using a trained PCA anomaly model | ✅ Done |
| 3 | Reduce false positives by fusing ML confidence with SIEM historical data | ✅ Done |
| 4 | Verify attack decisions against per-IP historical reputation | ✅ Done |
| 5 | Generate human-readable reasoning for every decision using a local LLM (ZySec) | ✅ Done |
| 6 | Apply proportional automated mitigation (block, rate-limit, isolate, quarantine) | ✅ Done |
| 7 | Adapt detection thresholds autonomously using Q-learning | ✅ Done |
| 8 | Expose all real-time data via FastAPI and a React monitoring dashboard | ✅ Done |
| 9 | Persist a full audit trail to Elasticsearch (evidence-before-mitigation) | ✅ Done |

---

## 3. System Architecture

ANDS is composed of **two primary agents**, a **learning layer**, and a **persistence layer** governed by a formal decision policy derived from NIST SP 800-61r2.

```
┌──────────────────────────────────────────────────────────────────┐
│                        ANDS Platform                             │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │               Classification Agent                          │ │
│  │                                                             │ │
│  │   PCAIntrusionModel → FusionEngine → ReasoningEngine        │ │
│  │          ↓                                ↓                 │ │
│  │   SuspiciousStateTracker          ZySec / Ollama LLM        │ │
│  │          ↓                                ↓                 │ │
│  │              VerificationAgent (Stage 2)                    │ │
│  │              AttackTypeModifier  (Stage 3)                  │ │
│  └────────────────────────┬────────────────────────────────────┘ │
│                           │ ClassificationResult                  │
│  ┌────────────────────────▼────────────────────────────────────┐ │
│  │               Mitigation Agent                              │ │
│  │                                                             │ │
│  │   strategy_map.py → tools.py (block_ip / rate_limit / ...)  │ │
│  └────────────────────────┬────────────────────────────────────┘ │
│                           │                                       │
│  ┌────────────────────────▼────────────────────────────────────┐ │
│  │        Elasticsearch / Kibana  (3 indices)                  │ │
│  │   ands-alerts │ network_live_flows │ confirmed_attack_history│ │
│  └────────────────────────┬────────────────────────────────────┘ │
│                           │  metrics every 30 min                │
│  ┌────────────────────────▼────────────────────────────────────┐ │
│  │        RL Policy Optimizer (Q-learning, background)         │ │
│  │    Adjusts: model_high_confidence, model_trust_floor,       │ │
│  │             siem_corroboration_min, suspicious_escalate_count│ │
│  └────────────────────────┬────────────────────────────────────┘ │
│                           │ writes config/incident_policy.yaml   │
│  ┌────────────────────────▼────────────────────────────────────┐ │
│  │        Policy Engine (thread-safe YAML cache)               │ │
│  │        All agents read thresholds from here at runtime      │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## 4. Datasets

ANDS is trained and evaluated on improved versions of two well-known network intrusion benchmark datasets.

| Dataset | Period | Attack Types | Size |
|---|---|---|---|
| **CICIDS2017** (improved) | Mon–Fri, 2017 | DoS, DDoS, PortScan, BruteForce, Web Attack, Infiltration, Botnet | ~15 GB |
| **CSE-CIC-IDS2018** (improved) | Feb–Mar, 2018 | DoS Hulk, DoS Slowloris, BruteForce, Infiltration, SQL Injection, Botnet | ~22 GB |

Raw files are **not included** in this repository (~37 GB total).

**Download:** [Improved CICIDS2017 and CSE-CIC-IDS2018 on Kaggle](https://www.kaggle.com/datasets/ernie55ernie/improved-cicids2017-and-csecicids2018)

Place extracted CSVs under:
```
data/raw/CICIDS2017_improved/
data/raw/CSECICIDS2018_improved/
```

The trained model artifact is already included at:
```
deployments/models/pca_intrusion_detector.joblib
deployments/models/pca_intrusion_detector.attack_type_centroids.json
```

---

## 5. Component Deep-Dives

### 5.1 Classification Agent

**File:** `src/agents/classification_agent/agent.py`

The Classification Agent is the core detection engine. It processes one `FlowRecord` at a time through four sequential internal stages.

#### PCAIntrusionModel

- Loads `deployments/models/pca_intrusion_detector.joblib`, which bundles a `StandardScaler`, a trained `PCA` transformer, a reconstruction-error threshold, and multi-class attack-type metadata.
- **Anomaly detection:** scales and PCA-projects each flow, reconstructs it, and computes the mean squared reconstruction error. A score above the threshold signals an anomaly (attack).
- **Attack-type classification:** uses three fallback layers in order:
  1. A bundled multi-class model (`attack_type_model`) if present in the bundle.
  2. Nearest centroid matching against `attack_type_centroids` stored in the bundle or a sidecar JSON file.
  3. A `Label` column from the input CSV row if available.
- **Model bundle keys:** `scaler`, `pca`, `threshold`, `feature_columns`, `attack_type_centroids`, `attack_classes`, `attack_type_source`, `attack_type_feature_space`.

#### FusionEngine

- Implements the **Stage 1 decision table** from `policy.md` / NIST SP 800-61r2 §3.2.2.
- Combines `model_confidence` and `siem_confidence + siem_alert_count` to produce `(fused_confidence, decision_source, is_suspicious)`.
- All four thresholds (`model_high_confidence`, `model_trust_floor`, `siem_corroboration_min`, `siem_alert_count_min`) are read live from the `PolicyEngine` so RL updates propagate instantly.

| model_confidence | siem_confidence | siem_alert_count | Decision |
|---|---|---|---|
| < 0.50 | any | any | **BENIGN** (below trust floor) |
| ≥ 0.86 | any | any | **ATTACK** (model_only) |
| 0.65 – 0.85 | ≥ 0.70 | ≥ 2 | **ATTACK** (model+siem) |
| 0.65 – 0.85 | < 0.70 | any | **SUSPICIOUS** |
| 0.50 – 0.64 | ≥ 0.80 | ≥ 3 | **ATTACK** (siem_override) |
| 0.50 – 0.64 | < 0.80 | < 3 | **SUSPICIOUS** |

#### SuspiciousStateTracker

- Tracks per-IP SUSPICIOUS decisions within a rolling time window (default: 10 minutes).
- When a source IP accumulates `escalate_if_count` (default: 3) SUSPICIOUS decisions in the window, it triggers automatic re-evaluation with `siem_alert_count + 3`, potentially escalating to ATTACK.
- Implements NIST §3.2.6 — pattern-based incident prioritization.

---

### 5.2 Verification Agent

**File:** `src/agents/classification_agent/verification_agent.py`

Sits between Stage 1 (FusionEngine) and Stage 3 (attack-type modifier). Only runs when Stage 1 produces an ATTACK decision.

#### Score Formula

```
verification_score = 0.4 × ip_history_score
                   + 0.4 × same_attack_type_score
                   + 0.2 × recent_recurrence_score
```

Where each sub-score is normalized against saturation thresholds:
- `ip_history_score`: saturates at 10 confirmed past attacks from the IP.
- `same_attack_type_score`: saturates at 5 past attacks of the same type.
- `recent_recurrence_score`: saturates at 3 attacks in the last 7 days.

#### Severity Tiers

| verification_score | Verdict | Severity | Permitted Actions |
|---|---|---|---|
| > 0.80 | Confirmed Historically Consistent | **HIGH** | block_ip, null_route, isolate, quarantine |
| 0.50 – 0.80 | Suspicious, Partial History | **MEDIUM** | rate_limit, throttle (block downgraded) |
| 0.20 – 0.49 | Newly Observed / Low Evidence | **LOW** | log_for_investigation + alert_soc only |
| < 0.20 | Unknown IP / No History | **INFO** | monitor_closely only |

The agent extends `ClassificationResult.reasoning` with a human-readable verification summary and stamps `verification_score`, `verification_verdict`, and `decision_source` on the result.

---

### 5.3 Mitigation Agent

**File:** `src/agents/mitigation_agent/agent.py`  
**Tools:** `src/agents/mitigation_agent/tools/tools.py`  
**Strategy map:** `src/agents/mitigation_agent/strategy_map.py`

#### Design Philosophy

The Mitigation Agent is **fully deterministic** — no LLM in the hot path. The same attack type and confidence always produce the same tool sequence. This guarantees sub-second response time and predictable behavior in a live environment.

#### Strategy Map

| Attack Type | Standard Tools | High-Confidence Override (≥ 0.85) |
|---|---|---|
| DDoS | rate_limit_ip → block_ip → null_route_ip → alert_soc | block_ip → null_route_ip → alert_soc |
| PortScan | block_ip → alert_soc | — |
| BruteForce | throttle_connections → block_ip → alert_soc | — |
| Botnet | block_ip → quarantine_host → alert_soc | — |
| Web Attack | block_ip → alert_soc | — |
| Infiltration | isolate_host → block_ip → alert_soc | — |
| Intrusion (generic) | block_ip → alert_soc | — |

#### Mitigation Tools

| Tool | Linux | Windows |
|---|---|---|
| `block_ip` | `iptables -I INPUT -s <ip> -j DROP` | `netsh advfirewall firewall add rule` |
| `rate_limit_ip` | `iptables hashlimit` | Falls back to block_ip |
| `null_route_ip` | `ip route add blackhole <ip>/32` | Falls back to block_ip |
| `throttle_connections` | `iptables recent module` | Falls back to block_ip |
| `quarantine_host` | Stub — marks for VLAN quarantine | Stub |
| `isolate_host` | `iptables DROP INPUT + OUTPUT` | `netsh` inbound + outbound rules |
| `alert_soc` | Logs + optional Wazuh webhook POST | Same |

All tools are idempotent (block_ip skips duplicate calls), require user confirmation unless `AUTO_MITIGATE=true` or a non-interactive shell is detected, and append every action to a session-scoped audit log readable by the API.

---

### 5.4 RL Policy Optimizer

**File:** `src/learning/rl_policy_optimizer.py`  
**Scheduler:** `src/learning/optimizer_scheduler.py`

The optimizer runs as a **background daemon** (via `OptimizerScheduler`) and executes one Q-learning cycle every 5 minutes.

#### What It Optimizes

Four decision thresholds in `config/incident_policy.yaml`:

| Parameter | Safe Range | Effect |
|---|---|---|
| `model_high_confidence` | [0.75, 0.95] | Raise → fewer model-only attacks; lower → more aggressive detection |
| `model_trust_floor` | [0.35, 0.65] | Raise → discard more low-confidence model outputs |
| `siem_corroboration_min` | [0.55, 0.90] | Raise → require stronger SIEM evidence in medium-confidence band |
| `suspicious_escalate_count` | [2, 6] | Raise → more SUSPICIOUS hits required before escalation |

#### Q-Learning Setup

- **State:** 5-dimensional discrete vector binned from operational metrics (suspicious_rate, fp_rate, fn_rate, avg_model_confidence, avg_siem_confidence) — each binned into low/med/high (243 possible states).
- **Actions:** 9 — increment/decrement each of the 4 thresholds by ±0.01 (or ±1 for integer), plus a no-op.
- **Reward function:** `5·TP − 8·FP − 10·FN − 4·wrong_mitigation + 3·mitigation_success − 2·analyst_override`
- **Hyperparameters:** α=0.10, γ=0.90, ε=0.10 (ε-greedy exploration)
- **Q-table:** persisted to `logs/rl_qtable.json` between restarts.
- **Metrics source:** Elasticsearch (`ands-alerts` + `confirmed_attack_history` indices). Falls back to `logs/rl_decisions.jsonl` when ES is unavailable.

#### YAML Write

The optimizer patches only the four RL-managed keys in the YAML using an atomic temp-file + `os.replace()` to prevent corruption during concurrent access. All other policy keys (webhook URLs, retention periods, etc.) are left untouched.

---

### 5.5 Policy Engine

**File:** `src/core/policy_engine.py`

Thread-safe, live-reloadable YAML configuration cache. All agents read their thresholds from the single shared `PolicyEngine` instance injected at startup. When the RL optimizer writes a new YAML, it calls `policy.reload()` — the next agent decision picks up the new values without restarting the process.

Exposed properties: `model_trust_floor`, `model_high_confidence`, `siem_corroboration_min`, `siem_alert_count_min`, `suspicious_escalate_count`, `confirmed_threshold`, `suspicious_threshold`, `low_evidence_threshold`.

---

### 5.6 LLM Reasoning Engine (ZySec)

**File:** `src/agents/classification_agent/agent.py` → `ReasoningEngine`  
**LLM Client:** `src/llms/llm_client.py`

Every classification decision — attack, suspicious, or benign — is accompanied by a human-readable reasoning text generated by the **ZySec-7B** security LLM running locally via Ollama.

#### Two LLM Calls per Flow

1. **`assess_model_confidence`** — asks ZySec to calibrate a confidence score (0.0–1.0) from the anomaly score / threshold ratio. Replaces a fixed heuristic formula.
2. **`generate_reasoning`** — asks ZySec to produce a 2–3 sentence explanation and a list of recommended actions for the decision.

#### Output Parsing

ZySec sometimes returns prose instead of strict JSON. The parser:
1. Attempts JSON extraction (`{"confidence": ...}` / `{"reasoning": ..., "actions": [...]}`).
2. Falls back to extracting the first 3 sentences of prose as the reasoning text.
3. Falls back to a deterministic heuristic reasoning string if ZySec is unavailable or crashes.

#### Provider Configuration

The `build_llm_client()` factory in `src/llms/llm_client.py` supports three providers via `LLM_PROVIDER` env var:

| Provider | Models | Notes |
|---|---|---|
| `ollama` | ZySec-7B (default), llama3.1, any Ollama model | **Primary — local, no API key** |
| `anthropic` | claude-haiku-4-5 (default) | Requires `ANTHROPIC_API_KEY` |
| `openai` | gpt-4o-mini (default) | Requires `OPENAI_API_KEY` |

**This project uses `ollama` with ZySec-7B as the primary provider.** The other providers are fallback options only.

---

### 5.7 Elasticsearch / Kibana Integration

**File:** `src/agents/classification_agent/kibana_adapter.py`

Three Elasticsearch indices are maintained:

| Index | Content | Used For |
|---|---|---|
| `network_live_flows` | Every flow result (benign + attack) | Traffic monitoring dashboard, flow history |
| `ands-alerts` | Attacks + suspicious decisions | SIEM corroboration queries, RL metrics |
| `confirmed_attack_history` | Confirmed attacks only with incident IDs | Verification Agent IP reputation, RL reward |

#### Evidence Write Order (NIST §3.3.2)

The classification agent writes to Elasticsearch **before** calling the mitigation agent, preserving original evidence even if network state changes during containment:

```
1. push_flow()              → network_live_flows      (every flow)
2. push_confirmed_attack()  → confirmed_attack_history (attacks only)
3. push_alert()             → ands-alerts             (attacks + suspicious)
4. on_attack()              → MitigationAgent.mitigate()
```

A `StubKibanaAdapter` (in-memory) is available for testing without an Elasticsearch instance.

---

### 5.8 FastAPI Backend & React Dashboard

**Backend:** `src/api.py` — FastAPI server on port 8000  
**Frontend:** `frontend/` — React 18 + Vite + Tailwind CSS + Recharts + Framer Motion

#### API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/traffic` | Live PPS, connection list, history |
| `GET /api/predictions` | Latest detection result, confidence, reasoning |
| `GET /api/decisions` | Current mitigation action and source |
| `GET /api/defense` | Blocked IPs list, mitigation status |
| `GET /api/features` | Processed flow features |
| `GET /api/rl` | RL optimizer state: current thresholds, last action, reward, cycle count |
| `POST /api/run` | Trigger a classification run on a CSV file |

#### Dashboard Pages

| Page | Content |
|---|---|
| Overview | System status, pipeline flow visualization, live metrics |
| Traffic | Packets per second, connection table, traffic history chart |
| Detection | Prediction result, attack type, confidence gauge, reasoning text |
| Features | Extracted flow features table |
| Decisions | Mitigation actions, RL threshold panel with live threshold values and last reward |

---

## 6. Model Evaluation & Metrics

### 6.1 PCA Anomaly Detector (Deployed Model)

**Source:** `notebooks/cleaning-tsne-and-pca-intrusion-detection.ipynb`  
**Dataset:** CSE-CIC-IDS2018 (improved) — trained on benign traffic only (unsupervised anomaly detection)

#### Model Configuration

| Parameter | Value |
|---|---|
| Architecture | PCA Reconstruction Error (anomaly detector) |
| Scaler | RobustScaler |
| Number of principal components (`n_components`) | **64** |
| Anomaly score | Sum of squared reconstruction errors: `Σ(x − PCA⁻¹(PCA(x)))²` |
| Decision threshold | **0.0227** (set at the 95th percentile of benign reconstruction errors on validation set) |
| Classification rule | score < threshold → **BENIGN** (label +1) / score ≥ threshold → **ATTACK** (label −1) |

#### Threshold Selection Method

The threshold was chosen by sweeping 100 evenly-spaced candidate values over the range of reconstruction error scores and selecting the one that maximizes **F1-score** on the validation set, using the `precision_recall_curve` + `auc` approach. The framework also computed the threshold that maximizes accuracy and the one that maximizes precision separately, allowing trade-off analysis.

#### Overall Binary Performance (All Attack Types)

| Metric | Value |
|---|---|
| **Precision** | 0.7826 |
| **Recall** | **0.9973** |
| **F1-score** | **0.8770** |
| **AU-Precision-Recall (AUPRC)** | 0.9215 |
| **AUROC** | 0.9261 |

> **Interpretation:** The PCA anomaly detector achieves near-perfect recall (99.7%) — it misses almost no real attack. The lower precision (78.3%) reflects false positives from benign flows whose reconstruction error happens to exceed the threshold; these are filtered downstream by the FusionEngine and VerificationAgent.

#### Per Attack-Type Detection Performance

| Attack Type | Precision | Recall | F1 | AUROC | AUPRC |
|---|---|---|---|---|---|
| All attacks (aggregate) | 0.783 | **0.997** | 0.877 | 0.926 | 0.922 |
| DoS Slowloris + Slowhttptest | 0.038 | 0.994 | 0.074 | 0.948 | 0.144 |
| FTP-Patator | 0.028 | **1.000** | 0.054 | 0.978 | 0.145 |
| SSH-Patator | 0.021 | 0.998 | 0.041 | 0.957 | 0.062 |
| DoS Slowloris (standalone) | 0.027 | **1.000** | 0.052 | 0.940 | 0.092 |
| DoS Slowhttptest (standalone) | — | — | — | 0.965 | 0.073 |

> **Note on per-type low precision:** The PCA model is trained unsupervised on benign data only. For attack types with statistical overlap with benign traffic (e.g., DoS Slowloris mimics normal slow HTTP), the model flags a large portion of benign flows as anomalous, driving precision down. Recall stays high because reconstruction errors for true attack flows are reliably large. The multi-signal FusionEngine (SIEM corroboration + VerificationAgent) compensates for this in the full pipeline.

---

### 6.2 Supervised Classifiers (Comparison Study)

**Source:** `notebooks/model.ipynb`  
**Dataset:** CSE-CIC-IDS2018 (improved) — 8-class supervised classification  
**Test split:** 442,565 samples

#### Label Encoding

| Encoded Label | Attack Class | Test Samples |
|---|---|---|
| 0 | Benign | 362,430 |
| 1 | Bot | 42,711 |
| 2 | Brute Force – Web | 38 |
| 3 | Brute Force – XSS | 21 |
| 4 | FTP-BruteForce | 19 |
| 5 | Infiltration | 9,142 |
| 6 | SQL Injection | 10 |
| 7 | SSH-Bruteforce | 28,194 |

#### Best Model — Voting Classifier (RF + DT + AdaBoost)

| Metric | Value |
|---|---|
| **Overall Accuracy** | **0.9808** |
| Macro-avg Precision | 0.94 |
| Macro-avg Recall | 0.83 |
| Macro-avg F1 | 0.86 |
| Weighted-avg Precision | 0.98 |
| Weighted-avg Recall | 0.98 |
| Weighted-avg F1 | 0.98 |

#### Per-Class Performance (Voting Classifier — Best Run)

| Class | Label | Precision | Recall | F1 | Support |
|---|---|---|---|---|---|
| 0 | Benign | 0.98 | 1.00 | 0.99 | 362,430 |
| 1 | Bot | 1.00 | 1.00 | 1.00 | 42,711 |
| 2 | Brute Force – Web | 1.00 | 1.00 | 1.00 | 38 |
| 3 | Brute Force – XSS | 1.00 | 0.90 | 0.95 | 21 |
| 4 | FTP-BruteForce | 0.90 | 1.00 | 0.95 | 19 |
| 5 | Infiltration | 0.62 | 0.18 | **0.27** | 9,142 |
| 6 | SQL Injection | 1.00 | 0.70 | 0.82 | 10 |
| 7 | SSH-Bruteforce | 1.00 | 1.00 | 1.00 | 28,194 |

> **Key insight:** Infiltration is the hardest class — recall of 0.18 means 82% of infiltration flows are missed. This class has the highest statistical similarity to benign traffic (slow, low-volume lateral movement). The poor per-class F1 (0.27) pulls the macro-average F1 down to 0.86 despite the high weighted average (0.98). This motivates the SIEM corroboration and VerificationAgent stages in the pipeline — historical IP reputation data can catch infiltration attempts that the model misses.

#### Comparison of Evaluated Models

| Model | Accuracy | Notes |
|---|---|---|
| Voting Classifier (RF + DT + AdaBoost) | **0.9808** | Best overall — deployed architecture |
| Random Forest | 0.9807 | Near-identical to voting |
| AdaBoost | 0.9799 | Slightly lower on minority classes |
| Decision Tree | 0.9797 | Baseline comparison |

#### Metric Definitions

| Metric | Formula | What it measures |
|---|---|---|
| **Accuracy** | (TP + TN) / total | Overall fraction of correct predictions |
| **Precision** | TP / (TP + FP) | Of all predicted attacks, how many were real |
| **Recall (Sensitivity)** | TP / (TP + FN) | Of all real attacks, how many were detected |
| **F1-score** | 2 × P × R / (P + R) | Harmonic mean of precision and recall |
| **AUROC** | Area under ROC curve | Ability to distinguish attack vs benign across all thresholds |
| **AUPRC** | Area under Precision-Recall curve | More informative than AUROC for imbalanced datasets |
| **Confusion Matrix** | TP / FP / TN / FN counts | Full breakdown of prediction outcomes |

---

### 6.3 Evaluation Script

To re-evaluate the deployed PCA model on any labelled CSV dataset:

```powershell
# Evaluate on test CSV (fast, ~seconds)
& ".\.venv\Scripts\python.exe" scripts/evaluate_pca_model.py --data data/test/test.csv

# Evaluate on one full dataset day (~minutes, 50k rows/chunk streaming)
& ".\.venv\Scripts\python.exe" scripts/evaluate_pca_model.py --data data/raw/CICIDS2017_improved/friday.csv

# Evaluate on all raw files in a directory
& ".\.venv\Scripts\python.exe" scripts/evaluate_pca_model.py --data data/raw/CICIDS2017_improved/

# Limit number of files evaluated
& ".\.venv\Scripts\python.exe" scripts/evaluate_pca_model.py --data data/raw/ --max-files 3
```

**Output includes:** total rows, confusion matrix (TP / FP / TN / FN), Accuracy, Precision, Recall, F1, and per-attack-type detection rate.

---

## 7. Decision Pipeline — 4 Stages

Every network flow is processed through four sequential stages, grounded in NIST SP 800-61r2.

```
Stage 1: FusionEngine
  ├── model_confidence < trust_floor           → BENIGN (discard)
  ├── model_confidence ≥ high_confidence       → ATTACK (model_only)
  ├── medium band + SIEM ≥ min + count ≥ min  → ATTACK (model+siem)
  ├── low band + strong SIEM                  → ATTACK (siem_override)
  └── otherwise                               → SUSPICIOUS (monitor only)

Stage 2: VerificationAgent  [only if ATTACK]
  ├── score > 0.80  → HIGH severity    — all containment tools permitted
  ├── score 0.50–0.80 → MEDIUM severity — block_ip downgraded to rate_limit
  ├── score 0.20–0.49 → LOW severity   — log + alert_soc only
  └── score < 0.20  → INFO severity   — monitor_closely only

Stage 3: Attack-Type Modifier  [only if ATTACK]
  ├── DDoS + high confidence → skip rate_limit, go to null_route
  ├── PortScan               → cap at block_ip (no isolation)
  ├── BruteForce             → always add throttle_connections
  ├── Botnet (MEDIUM+)       → always add quarantine_host
  ├── Infiltration (MEDIUM+) → always add isolate_host
  └── Web Attack             → always add alert_soc

Stage 4: Audit Trail  [every flow]
  ├── 1. push_flow()             → network_live_flows
  ├── 2. push_confirmed_attack() → confirmed_attack_history
  ├── 3. push_alert()            → ands-alerts
  └── 4. MitigationAgent.mitigate()
```

The `decision_source` field on every `ClassificationResult` is set to one of: `model_only`, `model+siem`, `siem_override`, `verification_confirmed`, `verification_downgraded`, `insufficient_evidence`.

---

## 7. Technologies Stack

| Layer | Technology |
|---|---|
| **Language** | Python 3.11+ |
| **ML / Detection** | scikit-learn (PCA, StandardScaler), joblib, numpy, pandas |
| **LLM Reasoning** | ZySec-7B via Ollama, LangChain Ollama integration |
| **Agent Framework** | LangGraph, LangChain Core |
| **API** | FastAPI, Uvicorn, Pydantic |
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts, Framer Motion |
| **SIEM / Persistence** | Elasticsearch 8.17, Kibana (via Docker) |
| **Reinforcement Learning** | Custom Q-learning (tabular, ε-greedy) |
| **Flow Extraction** | CICFlowMeter (Java, 80+ features) |
| **Firewall / Mitigation** | iptables (Linux), netsh advfirewall (Windows) |
| **Infrastructure** | Docker Compose (Elasticsearch + Kibana) |
| **Testing** | pytest (30+ tests across all agents) |

---

## 8. Project Status

| Component | Status | Notes |
|---|---|---|
| PCA model training | ✅ Complete | Bundle deployed at `deployments/models/` |
| Attack type centroids | ✅ Complete | Sidecar JSON + bundle |
| Classification Agent (4-stage) | ✅ Complete | FusionEngine, VerificationAgent, ReasoningEngine, Modifier |
| ZySec LLM integration | ✅ Complete | With prose-tolerant parsing and heuristic fallback |
| Mitigation Agent | ✅ Complete | 7 tools, strategy map, deterministic executor |
| RL Policy Optimizer | ✅ Complete | Q-learning, 9 actions, ES + local log fallback |
| PolicyEngine (live-reload) | ✅ Complete | Thread-safe YAML cache |
| Elasticsearch / Kibana | ✅ Complete | 3 indices, full adapter + stub |
| FastAPI backend | ✅ Complete | 7 endpoints, RL state exposed |
| React dashboard | ✅ Complete | 5 pages including RL threshold panel |
| Unit tests | ✅ Complete | 30+ tests (classification, mitigation, RL, model) |
| ACL rule lifecycle (TTL/unblock) | ⚠️ Pending | `block_duration_minutes` config exists but expiry not enforced |
| SOC webhook (Wazuh) | ⚠️ Stub | `alert_soc` logs locally; webhook POST commented out |
| VLAN quarantine | ⚠️ Stub | `quarantine_host` logs intent; requires SDN controller |

---

## 9. Quick Start (Full Stack)

### Prerequisites

- Python 3.11 (recommended; 3.14 has pip compatibility issues with some packages)
- Docker Desktop (for Elasticsearch + Kibana)
- Node.js 18+ (for the React dashboard)
- Ollama with ZySec model (for LLM reasoning — optional, fallback reasoning works without it)

### Step 1 — Environment Configuration

Create a `.env` file in the project root:

```env
# LLM Provider — use local ZySec via Ollama
LLM_PROVIDER=ollama
LLM_MODEL=hf.co/ZySec-AI/ZySec-7B-GGUF:latest
OLLAMA_BASE_URL=http://localhost:11434

# SIEM Backend (Elasticsearch)
USE_SIEM_HISTORY=True
KIBANA_HOST=http://localhost:9200
KIBANA_INDEX=ands-alerts
KIBANA_VERIFY_CERTS=0

# Mitigation Auto-Pilot (set True to skip confirmation prompts)
AUTO_MITIGATE=False
```

### Step 2 — Start Elasticsearch & Kibana

```powershell
docker compose up -d
# Wait ~10 seconds, then verify:
curl http://localhost:9200/
```

### Step 3 — Python Environment & Backend

```powershell
python -m venv .venv
& ".\.venv\Scripts\Activate.ps1"
pip install -r requirements.txt

# Start FastAPI backend
& ".\.venv\Scripts\python.exe" -m uvicorn src.api:app --reload --port 8000
```

### Step 4 — React Dashboard

```powershell
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

### Step 5 — (Optional) Start ZySec via Ollama

```powershell
ollama pull hf.co/ZySec-AI/ZySec-7B-GGUF:latest
ollama serve
```

> **Note:** ZySec inference is CPU-bound — expect ~3 min per flow on a CPU-only machine. The system falls back to deterministic heuristic reasoning automatically if Ollama is unreachable.

---

## 10. Running the CLI

### CSV Mode (offline evaluation)

```powershell
# Run classification pipeline on a CSV file
& ".\.venv\Scripts\python.exe" -m src.main --mode csv --csv data/test/test.csv

# Run on a full dataset file
& ".\.venv\Scripts\python.exe" -m src.main --mode csv --csv data/raw/CICIDS2017_improved/friday.csv
```

### CICFlowMeter Watch Mode (live traffic)

```powershell
# Watch a directory for new CICFlowMeter output CSVs
& ".\.venv\Scripts\python.exe" -m src.main --mode cicflowmeter --watch data/cicflowmeter_out
```

### Evaluate Model Performance

```powershell
# Evaluate PCA model on a labelled dataset and print per-class metrics
& ".\.venv\Scripts\python.exe" scripts/evaluate_pca_model.py --data data/test/test.csv

# Evaluate on all raw files in a directory
& ".\.venv\Scripts\python.exe" scripts/evaluate_pca_model.py --data data/raw/CICIDS2017_improved/
```

### Regenerate Attack-Type Centroids

```powershell
& ".\.venv\Scripts\python.exe" scripts/build_attack_type_centroids.py --model deployments/models/pca_intrusion_detector.joblib
```

---

## 11. Running Tests

```powershell
# Run full test suite
& ".\.venv\Scripts\python.exe" -m pytest tests/ -v

# Run by component
& ".\.venv\Scripts\python.exe" -m pytest tests/test_intrusion_classification_agent.py -v  # 16 tests
& ".\.venv\Scripts\python.exe" -m pytest tests/test_mitigation_agent.py -v                # 10 tests
& ".\.venv\Scripts\python.exe" -m pytest tests/test_rl_optimizer.py -v                    # 3+ tests
& ".\.venv\Scripts\python.exe" -m pytest tests/models/ -v                                 # 3 tests

# Save output to log
& ".\.venv\Scripts\python.exe" -m pytest tests/ -v -s > logs/test_output.txt
```

**Expected result:** all tests pass, exit code 0.

---

## 12. Known Issues & Limitations

### `siem_corroboration_min: 0.` in config

`config/incident_policy.yaml` currently has `siem_corroboration_min: 0.` (zero). The FusionEngine hardcoded default is `0.70`. With this at zero, any SIEM alert regardless of its confidence satisfies the corroboration threshold, effectively disabling the SIEM gate for medium-confidence detections. **This should be corrected to `0.70`.**

### ACL Rule Expiry Not Implemented

The `block_duration_minutes: 60` and `unblock_after_minutes: 1440` values in `config/incident_policy.yaml` are parsed but never enforced. Firewall rules written by `block_ip` and `isolate_host` accumulate indefinitely until the OS is rebooted or rules are manually removed. An `ACLRule` dataclass with TTL tracking and an `unblock_ip` tool are the planned fix.

### ZySec Performance on CPU

ZySec-7B running on CPU via Ollama takes approximately 3 minutes per flow for reasoning generation. For batch evaluation runs, the heuristic fallback is used by default (set `LLM_PROVIDER=` empty or comment out the Ollama config). GPU acceleration would reduce this to seconds.

### Python 3.14 Compatibility

Some packages in `requirements.txt` (notably `elasticsearch-mcp-server`) do not yet support Python 3.14. Use Python 3.11 or 3.12 for full compatibility.

### `quarantine_host` is a Stub

Moving a host to a quarantine VLAN requires an SDN controller (OpenFlow, Cisco ACI) or a managed switch API. The current implementation logs the intent and marks the `MitigationResult` as successful without issuing a real VLAN move. This is scoped as a future extension.

---

*ANDS — Adaptive Network Defense System | SUP'COM P2M | 2025*
