================================================================================
ANDS PIPELINE - QUICK START REFERENCE
================================================================================

START THE PIPELINE
━━━━━━━━━━━━━━━━━━

Foreground (watch output):
  cd /home/gateway/P2M
  bash scripts/orchestrate_pipeline.sh

Background (daemon):
  cd /home/gateway/P2M
  bash scripts/orchestrate_pipeline.sh > /logs/daemon.log 2>&1 &
  disown


MONITOR EXECUTION
━━━━━━━━━━━━━━━━

Orchestrator log (detailed execution):
  tail -f /logs/orchestrator.log

Alerts (security events):
  tail -f /logs/alerts.log

Both in split view:
  tmux new-session -d -s monitor
  tmux send-keys "tail -f /logs/orchestrator.log" Enter
  tmux split-window -h
  tmux send-keys "tail -f /logs/alerts.log" Enter
  tmux attach


STOP THE PIPELINE
━━━━━━━━━━━━━━━━

Clean shutdown:
  bash scripts/stop_pipeline.sh

Or manually:
  pkill -f orchestrate_pipeline
  sudo pkill -f tcpdump


PIPELINE ARCHITECTURE
━━━━━━━━━━━━━━━━━━━

Every 5 seconds:
  1. CAPTURE (tcpdump 5s on enp0s8)
     ↓ /data/test1/simulated_attack.pcap
  
  2. EXTRACT (CICFlowMeter)
     ↓ /data/test1/output_<timestamp>.csv
  
  3. INFER (ML/PCA model)
     ↓ /data/test1/output_<timestamp>_results.csv
  
  4. DETECT & MITIGATE (Agents)
     ↓ /logs/alerts.log + iptables rules

Total time per cycle: ~5-8 seconds
Runs indefinitely until stopped.


KEY FILES
━━━━━━━━━

Main orchestrator:
  scripts/orchestrate_pipeline.py  (Core logic)
  scripts/orchestrate_pipeline.sh  (Bash wrapper)

Stop script:
  scripts/stop_pipeline.sh

Configuration:
  INTERFACE="enp0s8"
  CAPTURE_DURATION=5
  MODEL_PATH="deployments/models/pca_intrusion_detector.joblib"

Outputs:
  /data/test1/simulated_attack.pcap    (Live PCAP)
  /data/test1/output_*.csv              (Features)
  /data/test1/output_*_results.csv     (Predictions)
  /logs/orchestrator.log                (Execution log)
  /logs/alerts.log                      (Security alerts)


TROUBLESHOOTING
━━━━━━━━━━━━━

"Interface not found":
  ip link show                    # List available
  Edit scripts/orchestrate_pipeline.py, update INTERFACE

"tcpdump: command not found":
  sudo apt-get install tcpdump

"Model not found":
  ls -lh deployments/models/     # Should exist
  Train if missing: see ML model.md

"No alerts":
  1. Check PCAP size: ls -lh /data/test1/simulated_attack.pcap
  2. View CSV: head /data/test1/output_*.csv
  3. Check threshold: grep DETECTION_THRESHOLD scripts/orchestrate_pipeline.py


PERFORMANCE NOTES
━━━━━━━━━━━━━━━

- Cycle time: Fixed 5-second intervals
- Latency: ~1-2s detection delay after attack starts
- Throughput: 10-100+ flows per cycle (depends on traffic)
- Memory: ~200MB for Python process
- CPU: ~30-50% during inference (on single core)
- Disk: ~50MB per hour of logs + CSVs


NEXT: SEE guide.txt FOR COMPREHENSIVE DOCUMENTATION
================================================================================
