# This is how the classification agent should work

## ML Attack Classification + Agentic IP History Validation using Elasticsearch, Kibana, and MCP

------------------------------------------------------------------------
The system receives a **CSV file containing network flow traffic**,
updated automatically every 5 seconds.\
Each new row represents a network communication event with information
such as:

-   Timestamp
-   Source IP address
-   Destination IP address
-   Source port
-   Destination port
-   Protocol
-   Packets
-   Bytes
-   Duration
-   Flags
-   Additional statistical network features

A trained **machine learning classification model** analyzes these rows
and predicts whether the traffic is:

-   **Benign**
-   **Attack**

and if it is an attack, the model also predicts the **type of attack**.

Example:

``` python
prediction = "attack"
attack_type = "PortScan"
```

This means the ML model is not simply detecting statistical anomalies,
but directly generating a cybersecurity attack hypothesis.

However, even if the model predicts an attack, the system should not
blindly trust this output.

For this reason, the project introduces an **AI agent verification
layer** that uses historical cyberattack memory stored in Elasticsearch.

------------------------------------------------------------------------

## 2. Main Objective

The AI agent must verify the machine learning model's attack decision by
answering the following security question:

> **"Is this predicted attacker IP historically consistent with this
> detected attack?"**

More specifically, when the ML model predicts an attack, the AI agent
verifies:

-   Was this source IP involved in previous malicious incidents?
-   Was this IP previously associated with the same predicted attack
    type?
-   How frequent is this IP in confirmed malicious history?
-   When was it first and last seen maliciously?

This transforms the system from a simple attack classifier into an:

> **Agentic Historical Attack Validation System**

that combines:

-   machine learning intelligence,
-   historical attack memory,
-   and autonomous reasoning.

------------------------------------------------------------------------

## 3. Global System Pipeline

``` text
Live CSV Network Flow (updated every 5 sec)
        ↓
CSV Watcher detects new row
        ↓
ML Model classifies row
        ↓
Prediction = Benign or Attack + Attack Type
        ↓
If attack:
    AI Agent extracts source IP
        ↓
AI Agent calls MCP verification tools
        ↓
MCP communicates with Elasticsearch
        ↓
Historical malicious IP information returned
        ↓
Agent computes final verification confidence
        ↓
Final verdict generated
        ↓
Kibana dashboards updated
```

------------------------------------------------------------------------

## 4. Role of the Machine Learning Model

The ML model acts as the **first cyberattack detection layer**.

It observes the incoming traffic features and computes:

-   benign or attack
-   predicted attack type

Example:

``` python
prediction = "attack"
attack_type = "DoS Hulk"
```

This means the traffic behavior matches patterns learned from known
attack families.

But before issuing a final trusted alert, the system needs historical
evidence.

That evidence comes from the AI agent.

------------------------------------------------------------------------

## 5. Role of the AI Agent

The AI agent acts as an **autonomous cybersecurity verification
analyst**.

When the ML model predicts an attack, the agent performs:

### Step 1 --- Extract Source IP

Example:

``` python
src_ip = "192.168.1.55"
```

### Step 2 --- Ask Historical Questions

The agent verifies:

-   Has this IP appeared in previous confirmed attacks?
-   How many times?
-   Was it linked to the same attack type?
-   What attack types were associated with it?
-   When was it first seen maliciously?
-   When was it last seen maliciously?
-   Did it generate recent attacks?

### Step 3 --- Build Historical Trust

The agent computes whether this ML attack prediction is:

-   strongly supported by attacker history,
-   weakly suspicious,
-   or lacking historical evidence.

So the AI agent does not blindly trust the ML classifier.

It performs:

> **historical cyberattack consistency correlation.**

------------------------------------------------------------------------

## 6. Role of Elasticsearch

Elasticsearch is the **historical threat memory database**.

It stores all network observations and all confirmed malicious
incidents.

The system uses two main indices.

------------------------------------------------------------------------

### Index 1 --- `network_live_flows`

This index stores every incoming CSV row.

Example document:

``` json
{
  "@timestamp": "2026-05-01T15:10:05",
  "src_ip": "192.168.1.55",
  "dst_ip": "10.0.0.7",
  "src_port": 50444,
  "dst_port": 80,
  "protocol": "TCP",
  "packets": 1300,
  "bytes": 220000,
  "model_prediction": "attack",
  "predicted_attack_type": "PortScan"
}
```

------------------------------------------------------------------------

### Index 2 --- `confirmed_attack_history`

This is the critical intelligence memory.

Whenever an attack is confirmed malicious, it is stored here.

Example:

``` json
{
  "@timestamp": "2026-04-28T18:30:00",
  "src_ip": "192.168.1.55",
  "attack_type": "PortScan",
  "severity": "high",
  "incident_id": "INC_203"
}
```

This allows the agent to know:

> whether a suspicious IP has a malicious past and whether it matches
> the same attack family.

------------------------------------------------------------------------

## 7. Why Elasticsearch is Important

Elasticsearch allows:

-   very fast IP lookups,
-   attack count aggregation,
-   timestamp range filtering,
-   attack type retrieval,
-   historical incident analytics.

Instead of making decisions only from the current traffic row, the agent
can reason using:

> **months of previous cyberattack memory.**

------------------------------------------------------------------------

## 8. Role of MCP (Model Context Protocol)

MCP acts as the communication bridge between:

-   the AI agent
-   and Elasticsearch.

Without MCP:

the agent would need raw Elasticsearch code scattered everywhere.

With MCP:

the agent uses standardized security tools.

Example MCP tools:

``` python
check_ip_history(ip)
check_same_attack_type(ip, attack_type)
count_recent_ip_attacks(ip)
compute_ip_reputation(ip)
```

The agent simply calls these tools, and MCP handles:

-   Elasticsearch querying,
-   result formatting,
-   structured response delivery.

So MCP makes the architecture modular and scalable.

------------------------------------------------------------------------

## 9. Example Agent Verification Logic

Suppose ML predicts:

``` python
prediction = "attack"
attack_type = "PortScan"
src_ip = "192.168.1.55"
```

The agent asks MCP:

``` python
history = check_ip_history("192.168.1.55")
```

MCP returns:

``` python
{
    "previous_attack_count": 7,
    "first_seen": "2026-04-10",
    "last_seen": "2026-04-30",
    "attack_types": ["PortScan", "SYN Flood"],
    "same_attack_type_count": 5,
    "recent_attack_count": 3
}
```

The agent now knows:

-   this IP attacked before,
-   it attacked many times,
-   it was frequently associated with PortScan,
-   it appeared recently.

------------------------------------------------------------------------

## 10. Final Verification Score

The final malicious verification confidence should combine:

-   IP malicious history
-   same predicted attack type recurrence
-   recent attack recurrence

Example formula:

``` python
verification_score = (
    0.4 * ip_history_score
    + 0.4 * same_attack_type_score
    + 0.2 * recent_recurrence_score
)
```

Then:

-   if score \> 0.80 → Confirmed Historically Consistent Attack
-   if score between 0.50 and 0.80 → Suspicious Attack with Partial
    History
-   if score \< 0.50 → Newly Observed Attack / Low Historical Evidence

This creates a true **dual-intelligence cyberattack fusion engine**.

------------------------------------------------------------------------

## 11. Role of Kibana

Kibana is the monitoring dashboard and human investigation interface.

It visualizes:

### Dashboard 1 --- Top Recurrent Attacker IPs

Which IPs appear most often in confirmed attacks.

### Dashboard 2 --- Current Live Detected Attacker IPs

Current suspicious IP addresses detected by the system.

### Dashboard 3 --- IP Malicious Timeline

First seen and last seen malicious timestamps.

### Dashboard 4 --- Attack Type Distribution per IP

What types of attacks are linked to each IP.

### Dashboard 5 --- ML Prediction vs Historical Verification Confidence

Comparison between pure ML classification and final validated
confidence.

Kibana makes the AI agent's decisions transparent and auditable.

------------------------------------------------------------------------

## 12. Why This Project is Strong

This project is not just:

> ML attack classification + dashboard.

It is:

> **AI Agent + Machine Learning + Historical Threat Intelligence +
> Elasticsearch Memory + Autonomous Attack Validation**

This gives:

-   explainable attack confirmation,
-   historical evidence-backed alerts,
-   reduced false positives,
-   stronger cybersecurity trust.

------------------------------------------------------------------------

## 13. Final Concept Summary

The full system can be summarized as:

> A live network traffic monitoring platform where machine learning
> predicts cyberattacks and attack types, and an autonomous AI agent
> verifies the credibility of this prediction by consulting
> Elasticsearch-based historical attacker IP memory through MCP, while
> Kibana provides real-time cyber threat investigation dashboards.

------------------------------------------------------------------------

## 14. Core Innovation

The core innovation of this architecture is:

> **The attack is not accepted solely because the ML model predicts it.\
> It is validated through autonomous historical attacker reputation and
> attack-type consistency reasoning.**

This makes the system much closer to a real Security Operations Center
workflow.

------------------------------------------------------------------------
