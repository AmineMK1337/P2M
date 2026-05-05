================================================================================
ANDS PIPELINE - DEPLOYMENT CHECKLIST
================================================================================

PRE-DEPLOYMENT VERIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━

Before running the pipeline, verify:

□ System Configuration
  □ Gateway VM has Ubuntu/Debian OS
  □ Has root or sudo access (needed for tcpdump, iptables)
  □ Network interface enp0s8 exists and is active
    Command: ip link show | grep enp0s8
  
□ Dependencies Installed
  □ Python 3.8+
    Command: python3 --version
  
  □ tcpdump
    Command: sudo tcpdump --version
  
  □ pip packages
    Command: pip list | grep -E "pandas|joblib|numpy|scapy"
  
□ Repository Setup
  □ Repository cloned to /home/gateway/P2M (or adjusted in scripts)
  □ All required directories exist:
    - deployments/models/
    - src/agents/
    - scripts/
  
  □ Model file exists
    Command: ls -lh deployments/models/pca_intrusion_detector.joblib
    Expected size: ~10MB
  
  □ Python dependencies installed
    Command: cd /home/gateway/P2M && pip install -r requirements.txt
  
  □ CICFlowMeter installed locally
    Command: pip install -e CICflow-meter/
  
  □ Can import ANDS modules
    Command: python3 -c "from src.agents.classification_agent.agent import DetectionClassificationAgent; print('✓ OK')"

□ Output Directories
  □ /data/test1/ exists and is writable
    Command: mkdir -p /data/test1 && touch /data/test1/test.txt && rm /data/test1/test.txt
  
  □ /logs/ exists and is writable
    Command: mkdir -p /logs && touch /logs/test.log && rm /logs/test.log

□ Script Permissions
  □ Scripts are executable
    Command: chmod +x scripts/orchestrate_pipeline.sh scripts/stop_pipeline.sh


ENVIRONMENT VARIABLES (OPTIONAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Before running, optionally set:

  # Elasticsearch/Kibana integration (optional)
  export KIBANA_HOST="http://localhost:9200"
  export KIBANA_INDEX="ands-alerts"
  export KIBANA_USER="elastic"
  export KIBANA_PASS="password"
  
  # Control SIEM integration
  export USE_SIEM_HISTORY="false"  # Set to false if Kibana unavailable
  
  # Detection threshold (0.0 - 1.0)
  export DETECTION_THRESHOLD="0.5"
  
  # Max alerts to retrieve from SIEM per query
  export SIEM_MAX_ALERTS="50"
  
  # SIEM lookback window (minutes)
  export SIEM_WINDOW_MINUTES="10"

If not set, defaults will be used (see orchestrate_pipeline.py).


QUICK DEPLOY STEPS
━━━━━━━━━━━━━━━━

1. Verify all prerequisites above

2. Navigate to repo:
   cd /home/gateway/P2M

3. Start pipeline in background:
   bash scripts/orchestrate_pipeline.sh > /logs/daemon.log 2>&1 &
   disown

4. Verify it's running:
   tail -f /logs/orchestrator.log
   # Should show: "ANDS PIPELINE ORCHESTRATOR - STARTING"

5. Generate test traffic (from attacker VM):
   hping3 -S --flood -p 80 <victim-ip>

6. Watch alerts:
   tail -f /logs/alerts.log
   # Should show attack detections


TROUBLESHOOTING AT DEPLOYMENT
━━━━━━━━━━━━━━━━━━━━━━━━━━

If pipeline doesn't start:

□ Check permissions
  sudo chown -R $(whoami):$(whoami) /data/test1 /logs

□ Check interface
  ip link show
  # Verify enp0s8 exists, if not update INTERFACE in orchestrate_pipeline.py

□ Check model
  ls -lh deployments/models/pca_intrusion_detector.joblib
  # File must exist and be readable

□ Check imports
  python3 -c "from src.agents.classification_agent.agent import *"
  # Should not print errors

□ Run in foreground to see errors
  bash scripts/orchestrate_pipeline.sh
  # Errors will print to console

□ Check logs
  cat /logs/daemon.log    # startup errors
  cat /logs/orchestrator.log  # execution trace


POST-DEPLOYMENT VERIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━

After starting, verify within 30 seconds:

□ Process is running
  pgrep -f orchestrate_pipeline
  # Should return a PID

□ Logs are being created
  ls -lh /logs/orchestrator.log
  # File size should be growing (tail shows new lines)

□ PCAP is being captured
  ls -lh /data/test1/simulated_attack.pcap
  # File should exist with size > 0

□ CSV files are being generated
  ls -lh /data/test1/output_*.csv
  # Should see new CSV files appearing

□ Pipeline is cycling correctly
  grep "CYCLE" /logs/orchestrator.log | tail -3
  # Should show rapid cycle numbers (1, 2, 3...)

□ No errors in logs
  grep -E "ERROR|CRITICAL" /logs/orchestrator.log
  # Should be empty (or very few warnings are OK)


PERFORMANCE BASELINE
━━━━━━━━━━━━━━━━━

Monitor these metrics to ensure healthy operation:

Cycle Duration:
  grep "Cycle complete" /logs/orchestrator.log
  # Each cycle should take 5-8 seconds

Flows per Cycle:
  grep "Extracted.*flows" /logs/orchestrator.log | tail -10 | awk '{print $NF}'
  # Typical: 5-100 flows per cycle (depends on traffic)

Detection Rate:
  grep "ATTACKS detected" /logs/orchestrator.log | wc -l
  # Should be 0 if no attack traffic, >0 when attacks run

Memory Usage:
  ps aux | grep orchestrate_pipeline | awk '{print $6}'
  # Typical: 200-500MB

CPU Usage:
  ps aux | grep orchestrate_pipeline | awk '{print $3}'
  # Typical: 5-15% when idle, 30-50% during inference


CONFIGURATION TUNING
━━━━━━━━━━━━━━━━━━

If you need to adjust behavior, edit scripts/orchestrate_pipeline.py:

Line ~30: INTERFACE = "enp0s8"
  Change to match your network interface

Line ~31: CAPTURE_DURATION = 5
  Reduce to ~2-3 for faster cycles, increase for more flows

Line ~32: CYCLE_INTERVAL = 5
  Must equal CAPTURE_DURATION (fixed interval)

Line ~53: DETECTION_THRESHOLD = 0.5
  Reduce to ~0.3 for higher sensitivity (more alerts)
  Increase to ~0.7 for lower sensitivity (fewer alerts)

After changes, restart pipeline:
  bash scripts/stop_pipeline.sh
  bash scripts/orchestrate_pipeline.sh > /logs/daemon.log 2>&1 &


MONITORING DASHBOARD SETUP (OPTIONAL)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Create a tmux session for real-time monitoring:

  tmux new-session -d -s ands_monitor
  
  tmux send-keys -t ands_monitor "echo 'Orchestrator Log:' && tail -f /logs/orchestrator.log" Enter
  
  tmux split-window -t ands_monitor -h
  tmux send-keys -t ands_monitor "sleep 1 && echo 'Alerts:' && tail -f /logs/alerts.log" Enter
  
  tmux attach -t ands_monitor

Access:
  - Navigate between panes: Ctrl+B, then arrow keys
  - Quit: Ctrl+B, then :kill-session


BACKUP & RECOVERY
━━━━━━━━━━━━━━━━

Important files to backup:

  /data/test1/output_*.csv         # Feature data
  /logs/orchestrator.log           # Execution trace
  /logs/alerts.log                 # Security alerts
  deployments/models/*.joblib      # ML models

Backup command:
  tar czf ands_backup_$(date +%s).tar.gz \
    /data/test1/output_*.csv \
    /logs/orchestrator.log \
    /logs/alerts.log

If pipeline crashes:
  1. Stop: bash scripts/stop_pipeline.sh
  2. Check logs: cat /logs/orchestrator.log | tail -100
  3. Restart: bash scripts/orchestrate_pipeline.sh > /logs/daemon.log 2>&1 &


SECURITY NOTES
━━━━━━━━━━━━━

- Pipeline runs as current user (not root)
  Only tcpdump and iptables run as sudo
- Model file is read-only and should not be modified
- Alert logs contain source IPs of attackers
- Ensure /logs is protected from unauthorized access
- When deploying to production, use proper file permissions


NEXT STEPS
━━━━━━━

1. Deploy to gateway VM
2. Run baseline test without attack traffic
3. Verify logs and outputs are normal
4. Run test attack from attacker VM
5. Verify detections in /logs/alerts.log
6. Integrate with frontend dashboard (optional)
7. Configure SIEM integration (optional)

See guide.txt for complete operational documentation.

================================================================================
