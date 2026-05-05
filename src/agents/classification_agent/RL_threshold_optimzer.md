# Reinforcement Learning Threshold Optimizer

## Overview
The Q-learning optimizer is designed to dynamically adjust the system's decision thresholds rather than relying on static, hard-coded values. The RL Optimizer continuously runs in the background, analyzing how well the model and SIEM integration have been performing (e.g., catching attacks vs. making false positives) over a recent time window. 

Based on these metrics, it decides whether to raise or lower strictness. The adjusted thresholds are written directly to the policy configuration, and the `PolicyEngine` reloads them immediately.

## System Architecture Flow

The complete feedback loop that updates our parameters looks like this:

```text
                ┌────────────────────┐
                │   ML Classifier    │
                │ attack + confidence│
                └─────────┬──────────┘
                          │
                ┌─────────▼──────────┐
                │   SIEM Fusion      │
                └─────────┬──────────┘
                          │
                ┌─────────▼──────────┐
                │   Policy Engine    │<────────────┐
                │ threshold decisions│             │
                └─────────┬──────────┘             │
                          │                        │
                     mitigation/logging            │
                          │                        │
                ┌─────────▼──────────┐             │
                │ Reward Collector   │             │
                │ FP/FN/Success stats│             │
                └─────────┬──────────┘             │
                          │                        │
                ┌─────────▼──────────┐             │
                │ RL Policy Optimizer│─────────────┘
                │(updates thresholds)│
                └────────────────────┘
```

## How the Thresholds Are Updated
The RL optimizer modifies four key thresholds, strictly keeping them within safe operating bounds to prevent runaway behavior. **These thresholds are continuously updated every 10 minutes (approximately every 100 network flows):**
1. **model_high_confidence** (Safe range: `0.75 - 0.95`): Increment/Decrement by 0.01 per step.
2. **model_trust_floor** (Safe range: `0.35 - 0.65`): Increment/Decrement by 0.01 per step.
3. **siem_corroboration_min** (Safe range: `0.55 - 0.90`): Increment/Decrement by 0.01 per step.
4. **suspicious_escalate_count** (Safe range: `2 - 6`): Increment/Decrement by 1 per step.

### The Update Cycle:
1. **Fetch Metrics**: The agent pulls recent decision patterns from Elasticsearch (or a local fallback), tracking true positives (TP), false positives (FP), false negatives (FN), average confidence rates, and suspicious activity rates.
2. **Compute State**: It gathers those continuous metrics and translates them into discrete states (bins like "low", "medium", "high") to represent the "current situation" internally.
3. **Select Action ($\varepsilon$-greedy)**: With a `10%` mathematical chance, it explores a *random* action. `90%` of the time, it looks up its Q-table log and exploits the *best-known* action for the current state.
4. **Apply and Reload**: The newly chosen action modifies the loaded parameters. The YAML policy file is updated and the changes immediately take effect.

## The Q-Learning Equation
The code uses the classic Bellman equation update for Q-learning to map the (State, Action) pairs to an expected Quality score (the Q-value). 

$$ Q_{new}(s_t, a_t) = Q(s_t, a_t) + \alpha \cdot \Big[R_{t+1} + \gamma \cdot \max_{a} Q(s_{t+1}, a) - Q(s_t, a_t)\Big] $$

**Breaking down the components:**
- **Q(s_t, a_t)**: The current Q-value in the table, estimating how good it is to take the previous action within the previous state.
- **Learning Rate ($\alpha=0.10$)**: Dictates how much new information overwrites old data. At 10%, the system learns gradually, preferring long-term trends over single spikes.
- **Reward Function ($R_{t+1}$)**: Deeply tailored to cybersecurity: 
  *Reward = 5·TP - 8·FP - 10·FN - 4·wrong_mitigation + 3·mitigation_success - 2·analyst_override*.
  Because security systems can't afford to miss attacks, a False Negative penalizes severely (-10), while False Positives cause a high penalty (-8).
- **Discount Factor ($\gamma=0.90$)**: Defines how important *future* rewards are compared to immediate rewards. A 0.9 indicates that the agent cares strongly about preventing bad long-term decision loops.
- **max Q**: The highest Q-value expected assuming optimal play from the new state the system landed in.

## Pertinent Files
- **`src/learning/rl_policy_optimizer.py`**: Contains the core logic for the Q-learning optimization. It defines the safe bounds, calculates the rewards from recent system metrics, fetches data, executes the RL update cycle, and re-writes the configuration.
- **`config/incident_policy.yaml`**: The configuration file that gets periodically modified by the optimizer to reflect the latest tuned threshold values. These values are immediately consumed by the system to adjust classification strictness.
  - **`decision_policy` section:** This mapping inside the YAML explicitly defines the current RL-tuned classification rules.
    - `model_trust_floor`: The absolute minimum model confidence where the system will even *consider* the flow. Below this, it is discarded immediately.
    - `model_high_confidence`: The threshold where the model is so certain it's an attack that it doesn't need SIEM corroboration to confirm it.
    - `siem_corroboration_min`: The required minimum SIEM confidence when the model score falls into the "unsure" zone (between trust floor and high confidence).
    - `suspicious_escalate_count`: The number of times an IP can perform low-level anomalous behavior before the system escalates it to a confirmed threat.

- **`logs/rl_qtable.json`**: The memory object (Q-table) serialized as JSON. It stores weights and historical value scores assigned to specific (State, Action) combos so the agent can learn to act intelligently across system restarts.
  - **Understanding the Q-Table Matrix:**
    An entry in the database looks like this:
    ```json
    {
      "(0, 0, 0, 2, 1)": {
        "0": 0.0, "1": 0.0, "2": 0.0, "3": 0.0,
        "4": 0.0, "5": 0.0, "6": 0.0, "7": 0.0, "8": 0.0
      }
    }
    ```
    - **The Key (The State)** e.g., `"(0, 0, 0, 2, 1)"`: Represents the discretized metrics snapshot. The metrics are binned into levels (0=Low, 1=Medium, 2=High) mapping to `(SuspiciousRate, FPRate, FNRate, AvgModelConfidence, AvgSIEMConfidence)`. In this example: Low errors, High model confidence, Medium SIEM confidence.
    - **The Inner Keys (The Actions)** `"0"` through `"8"`: Represent the 9 possible actions the agent can take (e.g., `"0"` increases `model_high_confidence`, `"8"` means do nothing).
    
            if action == 0:
                    thresholds["model_high_confidence"] += 0.01
                elif action == 1:
                    thresholds["model_high_confidence"] -= 0.01
                elif action == 2:
                    thresholds["model_trust_floor"] += 0.01
                elif action == 3:
                    thresholds["model_trust_floor"] -= 0.01
                elif action == 4:
                    thresholds["siem_corroboration_min"] += 0.01
                elif action == 5:
                    thresholds["siem_corroboration_min"] -= 0.01
                elif action == 6:
                    thresholds["suspicious_escalate_count"] += 1
                elif action == 7:
                    thresholds["suspicious_escalate_count"] -= 1
                # action == 8: no change

    - **The Values (The Q-Values)** e.g., `0.0`: The learned expected reward for taking that action in that state. As the system runs and evaluates the choices, these floats will rise for good actions and drop to negative numbers for bad ones, guiding the agent's future choices.