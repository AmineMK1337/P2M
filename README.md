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
     - 5.1.1 [ML Model Pipeline](#511-ml-model-pipeline)
     - 5.1.2 [Elasticsearch / Kibana (SIEM Memory)](#512-elasticsearch--kibana-siem-memory)
     - 5.1.3 [Threshold Optimizer (Q-Learning)](#513-threshold-optimizer-q-learning)
   - 5.2 [Mitigation Agent](#52-mitigation-agent)
   - 5.3 [FastAPI Backend & React Dashboard](#53-fastapi-backend--react-dashboard)
6. [Model Evaluation & Metrics](#6-model-evaluation--metrics)
   - 6.1 [PCA Anomaly Detector (Deployed Model)](#61-pca-anomaly-detector-deployed-model)
   - 6.2 [Supervised Classifiers (Comparison Study)](#62-supervised-classifiers-comparison-study)
   - 6.3 [Evaluation Script](#63-evaluation-script)
7. [Decision Pipeline — 3 Stages](#7-decision-pipeline--3-stages)
8. [Technologies Stack](#8-technologies-stack)
9. [Project Status](#9-project-status)
10. [Quick Start (Full Stack)](#10-quick-start-full-stack)
11. [Running the CLI](#11-running-the-cli)
12. [Running Tests](#12-running-tests)
13. [Known Issues & Limitations](#13-known-issues--limitations)

---

## 1. Project Overview

The **Adaptive Network Defense System (ANDS)** is an AI-powered cybersecurity platform that automatically detects, classifies, and mitigates cyberattacks in real time. It replaces traditional static, signature-based defenses with dynamic behavioral analysis, multi-signal decision fusion, and an autonomous reinforcement-learning feedback loop that continuously adapts its own detection thresholds.

ANDS implements a **two-agent system** where the Classification Agent handles the full detection and decision loop (including SIEM memory and adaptive threshold optimization), and the Mitigation Agent executes the response:

```
Network Traffic
      │
      ▼
┌─────────────────────┐
│  CICFlowMeter       │  Extracts 80+ statistical features per flow
└────────┬────────────┘
         │  FlowRecord (CSV)
         ▼
┌──────────────────────────────────────────────────────┐
│              Classification Agent                    │
│                                                      │
│  ┌──────────────┐   ┌──────────────┐                 │
│  │   ML Model   │   │  Elasticsearch│                │
│  │  (PCA + ZySec│──▶│  / Kibana MCP│                │
│  │   reasoning) │   │  (SIEM memory│                │
│  └──────┬───────┘   └──────────────┘                 │
│         │  FusionEngine (ML confidence + SIEM data)  │
│         ▼                                            │
│  ┌──────────────────────────────────┐                │
│  │  Threshold Optimizer (Q-learning)│                │
│  │  Adapts 4 thresholds every 5 min │                │
│  └──────────────────────────────────┘                │
│         │  ClassificationResult                      │
└─────────┼────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────┐
│  Mitigation Agent   │  Deterministic executor — iptables / netsh
└─────────────────────┘
```

---

## 2. Objectives

| # | Objective | Status |
|---|---|---|
| 1 | Extract 80+ statistical features from live network traffic using CICFlowMeter | ✅ Done |
| 2 | Detect and classify attack types using a trained PCA anomaly model | ✅ Done |
| 3 | Reduce false positives by fusing ML confidence with SIEM historical data | ✅ Done |
| 4 | Generate human-readable reasoning for every decision using a local LLM (ZySec) | ✅ Done |
| 5 | Apply proportional automated mitigation (block, rate-limit, isolate, quarantine) | ✅ Done |
| 6 | Adapt detection thresholds autonomously using Q-learning | ✅ Done |
| 7 | Expose all real-time data via FastAPI and a React monitoring dashboard | ✅ Done |
| 8 | Persist a full audit trail to Elasticsearch (evidence-before-mitigation) | ✅ Done |

---

## 3. System Architecture

ANDS is composed of **two agents**. The Classification Agent owns the full detection loop — ML model, SIEM memory (Elasticsearch/Kibana), and adaptive threshold optimizer all live inside it. The Mitigation Agent is a lean deterministic executor that receives a `ClassificationResult` and fires the appropriate response tools.

```
┌──────────────────────────────────────────────────────────────────────┐
│                          ANDS Platform                               │
│                                                                      │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │                   Classification Agent                        │   │
│  │                                                               │   │
│  │  ┌─────────────────────────┐   ┌───────────────────────────┐ │   │
│  │  │      ML Model           │   │  Elasticsearch / Kibana   │ │   │
│  │  │  ┌───────────────────┐  │   │  ┌─────────────────────┐  │ │   │
│  │  │  │  PCAIntrusionModel│  │◀──▶│  │  ands-alerts        │  │ │   │
│  │  │  │  (anomaly scorer) │  │   │  │  network_live_flows  │  │ │   │
│  │  │  └────────┬──────────┘  │   │  │  confirmed_attacks   │  │ │   │
│  │  │           │ score       │   │  └─────────────────────┘  │ │   │
│  │  │  ┌────────▼──────────┐  │   │  MCP server — push/query  │ │   │
│  │  │  │   FusionEngine    │◀─┼───┤  alerts for corroboration │ │   │
│  │  │  │ (ML + SIEM fusion)│  │   └───────────────────────────┘ │   │
│  │  │  └────────┬──────────┘  │                                  │   │
│  │  │           │             │   ┌───────────────────────────┐  │   │
│  │  │  ┌────────▼──────────┐  │   │  Threshold Optimizer      │  │   │
│  │  │  │  ReasoningEngine  │  │   │  (Q-learning, background) │  │   │
│  │  │  │  ZySec / Ollama   │  │   │  Adapts 4 policy values   │  │   │
│  │  │  └────────┬──────────┘  │   │  every 5 min via ES data  │  │   │
│  │  │           │             │   │  → writes incident_policy │  │   │
│  │  │  ┌────────▼──────────┐  │   │    .yaml atomically       │  │   │
│  │  │  │AttackTypeModifier │  │   └───────────────────────────┘  │   │
│  │  │  └───────────────────┘  │                                  │   │
│  │  └─────────────────────────┘                                  │   │
│  └──────────────────────────────┬────────────────────────────────┘   │
│                                 │ ClassificationResult                │
│  ┌──────────────────────────────▼────────────────────────────────┐   │
│  │                    Mitigation Agent                           │   │
│  │   strategy_map → tools (block_ip / rate_limit / isolate / …) │   │
│  └───────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
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

The Classification Agent is the core of ANDS. It owns three internal sub-systems — the ML model pipeline, the Elasticsearch/Kibana SIEM memory, and the adaptive threshold optimizer — and processes every `FlowRecord` through three sequential decision stages before handing a `ClassificationResult` to the Mitigation Agent.

---

#### 5.1.1 ML Model Pipeline

##### PCAIntrusionModel

- Loads `deployments/models/pca_intrusion_detector.joblib`, which bundles a `RobustScaler`, a trained `PCA` transformer, a reconstruction-error threshold, and multi-class attack-type metadata.
- **Anomaly detection:** scales and PCA-projects each flow (64 principal components), reconstructs it, and computes the sum of squared reconstruction errors. A score above threshold **0.0227** signals an anomaly (attack).
- **Attack-type classification** uses three fallback layers in order:
  1. A bundled multi-class model (`attack_type_model`) if present.
  2. Nearest centroid matching against `attack_type_centroids` (sidecar JSON).
  3. A `Label` column from the input CSV row if available.
- **Model bundle keys:** `scaler`, `pca`, `threshold`, `feature_columns`, `attack_type_centroids`, `attack_classes`.

##### FusionEngine

Combines the ML anomaly score with historical alert data retrieved from Elasticsearch to produce a fused confidence and a final decision:

| model_confidence | ES alert confidence | ES alert count | Decision |
|---|---|---|---|
| < 0.50 | any | any | **BENIGN** (below trust floor) |
| ≥ 0.86 | any | any | **ATTACK** (model_only) |
| 0.65 – 0.85 | ≥ 0.70 | ≥ 2 | **ATTACK** (model+siem) |
| 0.65 – 0.85 | < 0.70 | any | **SUSPICIOUS** |
| 0.50 – 0.64 | ≥ 0.80 | ≥ 3 | **ATTACK** (siem_override) |
| 0.50 – 0.64 | < 0.80 | < 3 | **SUSPICIOUS** |

All four thresholds are read live from the Policy Engine so optimizer updates take effect immediately.

##### SuspiciousStateTracker

Tracks per-IP SUSPICIOUS decisions within a rolling 10-minute window. When the same IP accumulates `escalate_if_count` (default: 3) SUSPICIOUS hits, it triggers automatic re-evaluation — implementing NIST §3.2.6 pattern-based escalation.

##### ReasoningEngine (ZySec LLM)

Every decision is explained by **ZySec-7B**, a security-specialized LLM running locally via Ollama (`src/llms/llm_client.py`):

1. **`assess_model_confidence`** — asks ZySec to calibrate a 0–1 confidence score from the anomaly score / threshold ratio.
2. **`generate_reasoning`** — asks ZySec for a 2–3 sentence explanation and a list of recommended response actions.

ZySec sometimes returns prose instead of strict JSON. The parser first attempts JSON extraction, then falls back to the first 3 sentences of prose, then to a deterministic heuristic string — so the pipeline never blocks.

| Provider | Model | Notes |
|---|---|---|
| `ollama` | `ZySec-7B` (default) | **Primary — local, no API key required** |
| `anthropic` | claude-haiku-4-5 | Fallback — requires `ANTHROPIC_API_KEY` |
| `openai` | gpt-4o-mini | Fallback — requires `OPENAI_API_KEY` |

---

#### 5.1.2 Elasticsearch / Kibana (SIEM Memory)

**File:** `src/agents/classification_agent/kibana_adapter.py`

Elasticsearch serves as the Classification Agent's persistent memory. Three indices are maintained:

| Index | Content | Used By |
|---|---|---|
| `network_live_flows` | Every flow result (benign + attack) | Dashboard traffic view |
| `ands-alerts` | Attacks + suspicious decisions | FusionEngine corroboration queries, RL metrics |
| `confirmed_attack_history` | Confirmed attacks with incident IDs | RL reward signal |

The agent writes to Elasticsearch **before** calling the Mitigation Agent (evidence-before-action, NIST §3.3.2):

```
1. push_flow()              → network_live_flows       (every flow)
2. push_confirmed_attack()  → confirmed_attack_history  (attacks only)
3. push_alert()             → ands-alerts              (attacks + suspicious)
4. on_attack()              → MitigationAgent.mitigate()
```

A `StubKibanaAdapter` (in-memory) is used during testing without a live Elasticsearch instance.

---

#### 5.1.3 Threshold Optimizer (Q-Learning)

**Files:** `src/learning/rl_policy_optimizer.py`, `src/learning/optimizer_scheduler.py`, `src/core/policy_engine.py`

The optimizer runs as a **background thread** inside the Classification Agent and executes one Q-learning cycle every 5 minutes, continuously tuning detection sensitivity based on real operational feedback from Elasticsearch.

##### What It Optimizes

| Parameter | Safe Range | Effect |
|---|---|---|
| `model_high_confidence` | [0.75, 0.95] | Raise → fewer model-only attack decisions |
| `model_trust_floor` | [0.35, 0.65] | Raise → discard more low-confidence model outputs |
| `siem_corroboration_min` | [0.55, 0.90] | Raise → require stronger ES alert evidence |
| `suspicious_escalate_count` | [2, 6] | Raise → more SUSPICIOUS hits before escalation |

##### Q-Learning Setup

- **State:** 5 metrics (suspicious_rate, fp_rate, fn_rate, avg_model_confidence, avg_alert_confidence) each binned into 3 levels → 243 possible states.
- **Actions:** 9 — ±0.01 on each of the 4 thresholds, plus no-op.
- **Reward:** `5·TP − 8·FP − 10·FN − 4·wrong_mitigation + 3·mitigation_success`
- **Hyperparameters:** α=0.10, γ=0.90, ε=0.10 (ε-greedy)
- **Q-table:** persisted to `logs/rl_qtable.json` across restarts.

Updated thresholds are written atomically to `config/incident_policy.yaml` (temp-file + `os.replace()`), then the **Policy Engine** (`src/core/policy_engine.py`) reloads the YAML in a thread-safe cache — the next FusionEngine call picks up the new values without any restart.

---

### 5.2 Mitigation Agent

**File:** `src/agents/mitigation_agent/agent.py`  
**Tools:** `src/agents/mitigation_agent/tools/tools.py`  
**Strategy map:** `src/agents/mitigation_agent/strategy_map.py`

The Mitigation Agent is **fully deterministic** — no LLM in the hot path. The same attack type and confidence always produce the same tool sequence, guaranteeing sub-second response time.

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

All tools are idempotent, require confirmation unless `AUTO_MITIGATE=true`, and append every action to a session-scoped audit log exposed by the API.

---

### 5.3 FastAPI Backend & React Dashboard

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

> **Interpretation:** The PCA anomaly detector achieves near-perfect recall (99.7%) — it misses almost no real attack. The lower precision (78.3%) reflects false positives from benign flows whose reconstruction error happens to exceed the threshold; these are filtered downstream by the FusionEngine (SIEM corroboration gate).

#### Per Attack-Type Detection Performance

| Attack Type | Precision | Recall | F1 | AUROC | AUPRC |
|---|---|---|---|---|---|
| All attacks (aggregate) | 0.783 | **0.997** | 0.877 | 0.926 | 0.922 |
| DoS Slowloris + Slowhttptest | 0.038 | 0.994 | 0.074 | 0.948 | 0.144 |
| FTP-Patator | 0.028 | **1.000** | 0.054 | 0.978 | 0.145 |
| SSH-Patator | 0.021 | 0.998 | 0.041 | 0.957 | 0.062 |
| DoS Slowloris (standalone) | 0.027 | **1.000** | 0.052 | 0.940 | 0.092 |
| DoS Slowhttptest (standalone) | — | — | — | 0.965 | 0.073 |

> **Note on per-type low precision:** The PCA model is trained unsupervised on benign data only. For attack types with statistical overlap with benign traffic (e.g., DoS Slowloris mimics normal slow HTTP), the model flags a large portion of benign flows as anomalous, driving precision down. Recall stays high because reconstruction errors for true attack flows are reliably large. The multi-signal FusionEngine (SIEM corroboration via Elasticsearch) compensates for this in the full pipeline.

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

Stage 2: Attack-Type Modifier  [only if ATTACK]
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

The `decision_source` field on every `ClassificationResult` is set to one of: `model_only`, `model+siem`, `siem_override`, `insufficient_evidence`.

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
| Classification Agent (3-stage) | ✅ Complete | FusionEngine, ReasoningEngine (ZySec), AttackTypeModifier |
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