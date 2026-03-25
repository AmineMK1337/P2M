"""
ANDS Pipeline
=============
Wires the ClassificationAgent → MitigationAgent.

Two usage patterns
------------------
1. Callback mode  (real-time)
   MitigationAgent fires automatically via the on_attack= hook on
   ClassificationAgent. Each attack is mitigated the moment it is detected.

2. Batch mode  (offline / replay)
   ClassificationAgent processes all flows first, then MitigationAgent
   handles every flagged ClassificationResult at once.

Run from the repo root:
    python src/pipeline.py           # default: callback mode
    python src/pipeline.py batch     # batch mode
"""

import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)

try:
    from src.agents.classification_agent.agent import (
        DetectionClassificationAgent,
        FlowInputConfig,
    )
    from src.agents.classification_agent.kibana_adapter import StubKibanaAdapter
    from src.agents.mitigation_agent.agent import MitigationAgent, MitigationResult
except ModuleNotFoundError:
    from agents.classification_agent.agent import (
        DetectionClassificationAgent,
        FlowInputConfig,
    )
    from agents.classification_agent.kibana_adapter import StubKibanaAdapter
    from agents.mitigation_agent.agent import MitigationAgent, MitigationResult


# ---------------------------------------------------------------------------
# Pattern 1 — Callback mode (real-time)
# ---------------------------------------------------------------------------

def run_callback_mode():
    """
    MitigationAgent is registered as the on_attack callback on the
    ClassificationAgent. Every confirmed attack is mitigated immediately.
    """
    mitigation_agent = MitigationAgent(model_name="llama3")

    def on_attack(classification_result):
        result: MitigationResult = mitigation_agent.mitigate(classification_result)
        print(result.summary())

    classification_agent = DetectionClassificationAgent(
        model_path="deployments/models/pca_intrusion_detector.joblib",
        kibana=StubKibanaAdapter(),
        on_attack=on_attack,            # ← MitigationAgent wired here
    )

    classification_agent.run(
        FlowInputConfig(mode="csv", csv_path="data/flows.csv")
    )


# ---------------------------------------------------------------------------
# Pattern 2 — Batch mode (offline / replay)
# ---------------------------------------------------------------------------

def run_batch_mode():
    """
    ClassificationAgent runs first, then MitigationAgent processes all
    flagged results in one pass.
    """
    classification_agent = DetectionClassificationAgent(
        model_path="deployments/models/pca_intrusion_detector.joblib",
        kibana=StubKibanaAdapter(),
    )

    classification_results = classification_agent.run(
        FlowInputConfig(mode="csv", csv_path="data/flows.csv")
    )

    mitigation_agent   = MitigationAgent(model_name="llama3")
    mitigation_results = mitigation_agent.run_batch(classification_results)

    # Both lists are index-aligned
    for c, m in zip(classification_results, mitigation_results):
        if c.is_attack:
            print(m.summary())


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "callback"
    if mode == "batch":
        run_batch_mode()
    else:
        run_callback_mode()