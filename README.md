# Adaptive Network Defense System (ANDS)

## Project Overview
The Adaptive Network Defense System (ANDS) is an AI-powered cybersecurity platform designed to automatically detect, classify, and mitigate cyberattacks in real time. It replaces traditional static, signature-based defenses with dynamic behavioral analysis and intelligent response.

ANDS uses a Multi-Agent System (MAS) where several AI agents cooperate to monitor network traffic, detect anomalies, identify attack types, and apply mitigation strategies without human intervention.

## Objectives
- Monitor network traffic continuously
- Detect known and unknown (zero-day) threats
- Classify different types of cyberattacks
- Automatically mitigate attacks such as DDoS
- Reduce detection and response time

## System Architecture
ANDS is built using a Multi-Agent System composed of three specialized agents:
1. Flow Analysis Agent
2. Intrusion Classification Agent
3. DDoS Prevention Agent

Network traffic passes through these agents in sequence: anomaly detection, attack classification, and mitigation.

## Core Agents

### Flow Analysis Agent
This agent learns what normal network traffic looks like and detects deviations using unsupervised machine learning techniques such as Isolation Forests or Autoencoders. It can detect unknown or zero-day attacks.

### Intrusion Classification Agent
This agent analyzes suspicious traffic and identifies the type of attack, such as DDoS, port scanning, or malware communication. It uses supervised learning models trained on datasets like CIC-IDS2017.

### DDoS Prevention Agent
This agent monitors traffic over time to detect DDoS attacks. When an attack is detected, it generates and applies mitigation strategies such as blocking IP addresses or rate-limiting traffic using firewall rules.

## Datasets

ANDS is trained and evaluated on the improved versions of two well-known network intrusion datasets.
Raw dataset files are **not included** in this repository due to their size (~37 GB).

Download them from Kaggle and place the extracted CSVs under `data/raw/`:

| Dataset | Folder |
|---|---|
| Improved CICIDS2017 | `data/raw/CICIDS2017_improved/` |
| Improved CSE-CIC-IDS2018 | `data/raw/CSECICIDS2018_improved/` |

**Download link:** [Improved CICIDS2017 and CSE-CIC-IDS2018 on Kaggle](https://www.kaggle.com/datasets/ernie55ernie/improved-cicids2017-and-csecicids2018)

## Technologies
- Python
- Machine Learning and Deep Learning
- Multi-Agent Frameworks (CrewAI, AutoGen)
- Network Traffic Datasets (CIC-IDS2017, CSE-CIC-IDS2018)
- Firewall or Router APIs

## Challenges
- Requirement for large and high-quality network datasets
- Real-time processing constraints
- Avoiding false positives
- Integration with firewall systems

## Conclusion

ANDS represents a modern approach to cybersecurity by combining AI, multi-agent systems, and automation to build a self-defending network capable of responding to modern cyber threats in real time.

