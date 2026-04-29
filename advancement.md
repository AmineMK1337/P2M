# ANDS Project Advancement Report

Date: 2026-04-29
Project: Adaptive Network Defense System (ANDS)
Workspace: P2M

## Executive Summary
You are at a strong prototype stage.

What is working well:
- Core flow classification pipeline is implemented and test-validated.
- PCA model loading and attack-type fallback logic are in place.
- Kibana adapter exists and can push/read alerts.
- Mitigation agent and strategy mapping are implemented.

What is still blocking "lab-ready autonomous defense":
- Runtime integration bug in constructor arguments (use_siem_history mismatch).
- SIEM history corroboration is not actually used in the current decision path.
- Mitigation hot path currently uses an LLM agent, which conflicts with your project rule "No LLM in hot path".
- Dedicated mitigation tests are missing.

## Where You Have Arrived (Current State)

### 1. Classification Agent: Implemented and Tested
Current status:
- Implemented in src/agents/classification_agent/agent.py.
- Supports:
  - CSV and CICFlowMeter ingestion.
  - PCA reconstruction-error anomaly scoring.
  - Attack-type fallback chain (bundle model, centroids, labels, generic Intrusion).
  - Human-readable reasoning and recommended actions.
- Unit tests are healthy.

Validation performed:
- Command executed:
  - python -m pytest tests/test_intrusion_classification_agent.py -q
- Result observed:
  - 13 passed in 0.62s

Conclusion:
- Classification internals are stable for current scope.

### 2. Main/API/Pipeline Wiring: Partially Implemented
Current status:
- src/main.py, src/api.py, and src/agents/mitigation_agent/pipeline.py all pass use_siem_history into DetectionClassificationAgent.
- DetectionClassificationAgent.__init__ currently does not accept use_siem_history.

Validation performed:
- Reproduced runtime error by direct constructor call with use_siem_history=True.
- Error:
  - TypeError: DetectionClassificationAgent.__init__() got an unexpected keyword argument 'use_siem_history'

Conclusion:
- Runtime entrypoints can fail before processing traffic, depending on path used.
- This is the highest priority blocker.

### 3. SIEM/Kibana Integration: Present but Not Fully Fused
Current status:
- Kibana adapter includes:
  - get_alerts
  - corroboration_score
  - push_alert
- FusionEngine exists in classification code.
- Current process_flow path does not query SIEM alerts for final decision fusion.

Conclusion:
- The architecture supports SIEM fusion, but active decisions are effectively model-first/model-only right now.
- This undercuts the core objective of reducing false positives using historical corroboration.

### 4. Mitigation Agent: Implemented but Architecturally Misaligned
Current status:
- Mitigation agent exists and is wired via callback.
- Tool functions exist for block/rate-limit/null-route/isolation/SOC alert.
- Some actions are real command invocations depending on OS.
- Some parts are explicitly stub/simulated.
- Mitigation control path uses ChatOllama + LangGraph ReAct.

Conclusion:
- Functional prototype exists.
- However, this conflicts with your stated principle that detection/mitigation hot path should be deterministic and not depend on an LLM.

### 5. Documentation and Reporting
Current status:
- README still mentions an older pass count (11 passed), while current tests show 13 passed.

Conclusion:
- Minor but important documentation drift.

## What Must Still Be Done (Detailed)

## Priority 0 (Immediate Blocker)
1. Fix constructor mismatch across runtime entrypoints.
- Option A (recommended): add use_siem_history parameter to DetectionClassificationAgent.__init__ and store it.
- Option B: remove use_siem_history from all callers.
- Expected outcome: main/API/pipeline start reliably without TypeError.

Acceptance criteria:
- python -m src.main --mode csv --csv data/test/test.csv runs without constructor error.
- API startup does not crash at agent initialization.

## Priority 1 (Core Functional Goal)
2. Re-enable real SIEM fusion in process_flow.
Required logic:
- If use_siem_history is enabled and flow is predicted as attack:
  - Fetch recent alerts by (src_ip, attack_type, window).
  - Compute SIEM corroboration score.
  - Fuse model and SIEM confidence using FusionEngine.
  - Set decision_source accordingly (model, model+siem, siem).
- Preserve deterministic behavior.

Acceptance criteria:
- decision_source changes based on available SIEM evidence.
- siem_confidence and siem_alert_count are non-zero when corroborating history exists.
- Add/adjust tests to cover with/without SIEM history.

## Priority 2 (Architecture Compliance)
3. Remove LLM dependency from mitigation hot path (or make it optional only).
Recommended implementation:
- Deterministic executor:
  - Read strategies from strategy_map.
  - Invoke mapped tools directly in order.
  - Always call alert_soc at end.
- Keep LLM path optional behind an explicit flag if you still want explainability experiments.

Acceptance criteria:
- Mitigation execution does not require ChatOllama availability.
- Same input produces same mitigation steps every run.

## Priority 3 (Quality + Safety)
4. Add mitigation-focused automated tests.
Minimum tests:
- Idempotent block behavior.
- Strategy selection by attack type and confidence.
- Tool failure handling and continuation.
- End-to-end callback contract from classification to mitigation.

Acceptance criteria:
- New mitigation test file(s) added under tests/.
- Test suite passes with deterministic outcomes.

## Priority 4 (Lab Readiness)
5. Run controlled end-to-end lab scenarios.
Scenarios:
- BENIGN traffic
- DDoS
- PortScan
Measurements:
- Detection latency
- False positive rate
- Mitigation success ratio
- SIEM corroboration effect

Acceptance criteria:
- Short experiment report produced (tables or markdown summary).
- Clear before/after comparison for SIEM-fusion impact.

## Priority 5 (Docs + Ops Hygiene)
6. Update project documentation.
- Correct test pass count and commands.
- Document required environment variables and startup behavior.
- Clarify which components are prototype vs production-ready.

Acceptance criteria:
- README and env docs align with actual runtime behavior.

## Suggested Next Sprint Plan
Sprint 1 (1-2 days):
- Fix constructor mismatch.
- Implement SIEM fusion in process_flow.
- Add tests for use_siem_history on/off.

Sprint 2 (1-2 days):
- Refactor mitigation to deterministic execution path.
- Add mitigation unit tests.

Sprint 3 (2-4 days):
- Run Kali -> Ubuntu live scenarios.
- Collect metrics and write final evaluation section.

## Progress Snapshot (Checklist)
- [x] Classification pipeline implemented
- [x] Classification tests passing (13)
- [x] Kibana adapter implemented
- [x] Mitigation strategies/tools implemented (prototype)
- [x] Runtime constructor mismatch fixed
- [x] SIEM history fusion active in decision path
- [x] Deterministic non-LLM mitigation hot path
- [x] Mitigation automated tests (10 new, 27 total passing)
- [ ] End-to-end lab evaluation report
- [ ] Documentation fully synchronized

## Risks If Not Addressed
- Startup/runtime failures due to argument mismatch.
- SIEM history objective not truly realized in decisions.
- Operational fragility if local LLM is unavailable.
- Harder final evaluation due to missing mitigation test evidence.

## Final Note
You have already built the hard foundation: data path, model path, schema path, adapter path, and a runnable prototype.
With the integration fix + SIEM fusion activation + deterministic mitigation refactor, your project will move from "good prototype" to "defensible academic system ready for lab validation".

Thank you.