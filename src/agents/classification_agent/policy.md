# ANDS Agent Decision Policy

**Based on:** NIST SP 800-61r2 — Computer Security Incident Handling Guide  
**Applies to:** Classification Agent, Verification Agent, Mitigation Agent  
**Version:** 1.0

---

## 1. Purpose

This document defines the formal decision policy governing how ANDS agents
combine Machine Learning (ML) model output with SIEM historical data to
classify network traffic and select a mitigation response.

The policy is grounded in NIST SP 800-61r2, which establishes that **no
single indicator should trigger a high-impact response in isolation**. The ML
model acts as the first detection layer. SIEM history acts as corroborating
evidence. Only their combination, validated by historical IP reputation,
justifies aggressive containment actions such as IP blocking or host isolation.

---

## 2. Core Principle

> *"An incident response capability is therefore necessary for rapidly
> detecting incidents, minimizing loss and destruction, mitigating the
> weaknesses that were exploited, and restoring IT services."*
> — NIST SP 800-61r2, Executive Summary

Applied to ANDS, this means:

- **Detect fast** — the ML model classifies every flow in real time.
- **Minimize false positives** — SIEM history and IP reputation validate the
  model before any firewall action is taken.
- **Escalate proportionally** — the severity of the response matches the
  strength of the combined evidence.
- **Always leave an audit trail** — every decision is tagged with a
  `decision_source` value and persisted to Elasticsearch.

---

## 3. Input Signals

Every agent decision is based on exactly three input signals:

| Signal | Produced By | Range | Description |
|---|---|---|---|
| `model_confidence` | `PCAIntrusionModel` | 0.0 – 1.0 | Certainty of the ML anomaly detector. Values above 0.85 indicate a strong behavioral deviation from normal traffic. |
| `siem_confidence` | `FusionEngine` via `KibanaAdapter` | 0.0 – 1.0 | Weighted average confidence of recent corroborating SIEM alerts for the same source IP and attack type within the configured time window. |
| `verification_score` | `VerificationAgent` | 0.0 – 1.0 | Composite historical IP reputation score: `0.4 × ip_history + 0.4 × same_attack_type_recurrence + 0.2 × recent_recurrence`. |

No single signal is sufficient on its own. The policy below defines how all
three are combined through four sequential decision stages.

---

## 4. Decision Stages

The agent processes every flow through four sequential stages. Each stage
can only be reached if the previous stage produced an ATTACK decision.

```
Stage 1 → Stage 2 → Stage 3 → Stage 4
Fusion     Verification  Attack-Type   Audit Trail
Engine     Gate          Modifier
```

---

### Stage 1 — Initial Classification (FusionEngine)

The first question is whether the flow is an attack at all, and how
confident the combined ML + SIEM evidence is.

| Model Output | `model_confidence` | `siem_confidence` | `siem_alert_count` | Decision |
|---|---|---|---|---|
| BENIGN | any | any | any | **BENIGN** |
| ATTACK | ≥ 0.85 | any | any | **ATTACK** |
| ATTACK | 0.65 – 0.84 | ≥ 0.70 | ≥ 2 | **ATTACK** |
| ATTACK | 0.65 – 0.84 | < 0.70 | any | **SUSPICIOUS** |
| ATTACK | 0.50 – 0.64 | ≥ 0.80 | ≥ 3 | **ATTACK** |
| ATTACK | 0.50 – 0.64 | < 0.80 | < 3 | **SUSPICIOUS** |
| ATTACK | < 0.50 | any | any | **BENIGN** |

**Notes:**

- `model_confidence < 0.50` is treated as BENIGN regardless of SIEM.
  The model is below the minimum trust floor and its output is discarded.
- `SUSPICIOUS` is an intermediate state introduced by this policy. It means
  the evidence is insufficient to act but the flow must be monitored. No
  firewall rules are applied. A low-priority alert is pushed to Kibana.
- A model output of ≥ 0.85 bypasses SIEM requirements entirely. At that
  confidence level, behavioral deviation alone is sufficient to escalate.

---

### Stage 2 — Verification Gate (VerificationAgent)

If Stage 1 produces ATTACK, the `VerificationAgent` queries
`confirmed_attack_history` for the source IP and computes a
`verification_score`. This score determines the severity tier and the
set of mitigation actions permitted.

| `verification_score` | Verdict | Severity | Permitted Mitigation Actions |
|---|---|---|---|
| > 0.80 | Confirmed Historically Consistent Attack | **HIGH** | `block_ip`, `null_route_ip`, `isolate_host`, `quarantine_host`, `alert_soc` |
| 0.50 – 0.80 | Suspicious Attack with Partial History | **MEDIUM** | `rate_limit_ip`, `throttle_connections`, `alert_soc` |
| 0.20 – 0.49 | Newly Observed Attack / Low Historical Evidence | **LOW** | `log_for_investigation`, `alert_soc` |
| < 0.20 | Unknown IP / No History | **INFO** | `monitor_closely` only — no firewall action |

**Notes:**

- At MEDIUM severity, `block_ip` is not permitted. If the ML model or
  strategy map requests it, the agent automatically downgrades it to
  `rate_limit_ip`.
- At LOW and INFO severity, no firewall rules are written. The flow is
  logged and the SOC is notified for human review.
- This gate directly implements NIST §3.3.1: *"Choosing a Containment
  Strategy"* — aggressive containment is only applied when evidence is strong.

---

### Stage 3 — Attack-Type Modifier

After the verification gate establishes a severity tier, attack-specific
rules are applied on top. These rules can escalate or constrain the actions
selected in Stage 2.

| Attack Type | Rule |
|---|---|
| `DDoS` | If `model_confidence ≥ 0.85`, skip `rate_limit_ip` and go directly to `null_route_ip`. DDoS at high confidence requires immediate traffic black-holing. |
| `PortScan` | Cap permitted actions at `block_ip` regardless of verification score. Port scanning has low damage potential and does not warrant isolation. |
| `BruteForce` | Always include `throttle_connections` even at LOW severity. Connection throttling is low-risk and directly counters the attack mechanism. |
| `Botnet` | Always include `quarantine_host` at MEDIUM or above. Botnet membership implies lateral movement risk; the host must be segmented immediately. |
| `Infiltration` | Always include `isolate_host` at MEDIUM or above. NIST treats internal threats as highest priority due to access to sensitive resources. |
| `WebAttack` | Always include `alert_soc` at every severity level. Web attacks require human review to assess application-layer impact. |

---

### Stage 4 — Audit Trail

Every flow that reaches a final decision — BENIGN, SUSPICIOUS, or ATTACK —
must be tagged and persisted. This implements NIST §3.4.1 (Lessons Learned)
and §3.4.3 (Evidence Retention).

#### `decision_source` Vocabulary

The `decision_source` field on every `ClassificationResult` must be set to
exactly one of the following values:

| Value | Meaning |
|---|---|
| `model_only` | Stage 1 triggered by `model_confidence ≥ 0.85` without SIEM corroboration |
| `model+siem` | Both model and SIEM met their respective thresholds |
| `siem_override` | SIEM confidence elevated a weak model prediction to ATTACK |
| `verification_confirmed` | `verification_score > 0.80` confirmed and escalated the attack |
| `verification_downgraded` | `verification_score` reduced the severity from the model's initial assessment |
| `insufficient_evidence` | Combined signals fell below all thresholds — decision is SUSPICIOUS |

#### Evidence Persistence Order

Evidence must be written to Elasticsearch **before** mitigation tools run.
This preserves the original traffic data even if network state changes during
containment. The required write order is:

```
1. preserve_evidence()         → snapshot of raw FlowRecord features
2. push_confirmed_attack()     → structured entry in confirmed_attack_history
3. push_alert()                → entry in ands-alerts index
4. on_attack() / mitigate()    → firewall and containment tools execute
```

---

## 5. Full Decision Flow

```
Network flow arrives
        │
        ▼
┌───────────────────────────────────────┐
│  Stage 1: FusionEngine                │
│                                       │
│  model_confidence < 0.50?             │
│      └── YES → BENIGN (discard)       │
│                                       │
│  model_confidence ≥ 0.85?             │
│      └── YES → ATTACK (proceed)       │
│                                       │
│  model 0.65–0.84 + siem ≥ 0.70 + ≥2? │
│      └── YES → ATTACK (proceed)       │
│                                       │
│  model 0.50–0.64 + siem ≥ 0.80 + ≥3? │
│      └── YES → ATTACK (proceed)       │
│                                       │
│  Otherwise → SUSPICIOUS               │
│      └── log + monitor, stop here     │
└───────────────┬───────────────────────┘
                │ ATTACK
                ▼
┌───────────────────────────────────────┐
│  Stage 2: VerificationAgent           │
│                                       │
│  score > 0.80 → HIGH                  │
│      └── block / isolate / null-route │
│                                       │
│  score 0.50–0.80 → MEDIUM             │
│      └── rate-limit / throttle        │
│                                       │
│  score 0.20–0.49 → LOW               │
│      └── log + alert_soc only         │
│                                       │
│  score < 0.20 → INFO                  │
│      └── monitor_closely only         │
└───────────────┬───────────────────────┘
                │
                ▼
┌───────────────────────────────────────┐
│  Stage 3: Attack-Type Modifier        │
│                                       │
│  Apply attack-specific rule overrides │
│  on top of Stage 2 permitted actions  │
└───────────────┬───────────────────────┘
                │
                ▼
┌───────────────────────────────────────┐
│  Stage 4: Audit Trail                 │
│                                       │
│  1. preserve_evidence()               │
│  2. push_confirmed_attack()           │
│  3. push_alert()                      │
│  4. mitigate()                        │
│  5. tag decision_source               │
└───────────────────────────────────────┘
```

---

## 6. SUSPICIOUS State Handling

The SUSPICIOUS state is introduced by this policy and does not exist in the
current ANDS codebase. It must be implemented as follows:

- Push a low-priority entry to the `ands-alerts` Kibana index with
  `is_attack: false` and a `suspicious: true` flag.
- Do **not** write to `confirmed_attack_history`.
- Do **not** invoke any mitigation tools.
- Schedule a re-evaluation of the source IP after
  `suspicious_state.recheck_after_minutes` (default: 10 minutes).
- If the same IP accumulates `suspicious_state.escalate_if_count`
  (default: 3) SUSPICIOUS decisions within the recheck window, automatically
  re-run Stage 1 treating `siem_alert_count` as incremented by 3. This
  implements NIST §3.2.6 — *"Incident Prioritization"* through observed
  pattern escalation.

---

## 7. Policy Configuration Reference

All thresholds defined in this policy are externalized in
`config/incident_policy.yaml`. The values below are the defaults.
Change them without modifying source code.

```yaml
decision_policy:

  # Stage 1 — FusionEngine thresholds
  model_trust_floor: 0.50         # below this, model output is discarded
  model_high_confidence: 0.85     # above this, act without SIEM
  siem_corroboration_min: 0.70    # minimum SIEM confidence to corroborate
  siem_alert_count_min: 2         # minimum SIEM alerts to count as support

  # Stage 2 — VerificationAgent severity tiers
  verification:
    confirmed_threshold: 0.80     # HIGH severity — all tools permitted
    suspicious_threshold: 0.50    # MEDIUM severity — soft tools only
    low_evidence_threshold: 0.20  # LOW severity — log only

  # SUSPICIOUS state re-evaluation
  suspicious_state:
    recheck_after_minutes: 10
    escalate_if_count: 3

retention:
  evidence_days: 90               # confirmed_attack_history ILM policy
  alert_days: 30                  # ands-alerts ILM policy

notification:
  soc_webhook_url: ""
  soc_severity_minimum: "medium"

containment:
  auto_mitigate: false
  block_duration_minutes: 60
  unblock_after_minutes: 1440     # 24 hours
```

---

## 8. NIST Traceability

Each stage of this policy maps directly to a section of NIST SP 800-61r2:

| Policy Element | NIST Section | Requirement |
|---|---|---|
| Three-signal fusion | §3.2.2 | Use multiple indicator sources to reduce false positives |
| SUSPICIOUS state | §3.2.6 | Prioritize incidents — not all detections warrant immediate response |
| Verification gate | §3.3.1 | Choose containment strategy based on strength of evidence |
| Evidence preservation before mitigation | §3.3.2 | Gather and handle evidence before eradication |
| `decision_source` audit tag | §3.4.1 | Lessons learned require traceable decision records |
| ILM retention policy | §3.4.3 | Organizations must define how long evidence is retained |
| SOC webhook notification | §3.2.7 | Notify appropriate parties as incidents are detected |
