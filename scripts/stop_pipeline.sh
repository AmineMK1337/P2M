#!/bin/bash

################################################################################
# ANDS PIPELINE SHUTDOWN SCRIPT
# 
# Cleanly stops all running pipeline components
################################################################################

echo "[+] Stopping ANDS pipeline components..."
echo ""

# Kill orchestrator processes
echo "[+] Stopping orchestrator..."
pkill -f "orchestrate_pipeline.py" 2>/dev/null || true
pkill -f "orchestrate_pipeline.sh" 2>/dev/null || true

# Kill traffic capture
echo "[+] Stopping packet capture..."
sudo pkill -f "tcpdump" 2>/dev/null || true

# Kill flow extraction
echo "[+] Stopping CICFlowMeter processing..."
pkill -f "cicflowmeter" 2>/dev/null || true
pkill -f "sniffer.py" 2>/dev/null || true

# Kill ML/detection processes
echo "[+] Stopping ML inference..."
pkill -f "python.*pca_detector" 2>/dev/null || true
pkill -f "python.*inference" 2>/dev/null || true

# Kill agent processes
echo "[+] Stopping agents..."
pkill -f "classification_agent" 2>/dev/null || true
pkill -f "mitigation_agent" 2>/dev/null || true

# Kill any remaining legacy processes
echo "[+] Cleaning up legacy processes..."
pkill -f "pcap_loop.sh" 2>/dev/null || true
pkill -f "python -m src.main" 2>/dev/null || true
pkill -f "uvicorn src.api" 2>/dev/null || true

echo ""
sleep 2

# Final verification
echo "[+] Verifying shutdown..."
if pgrep -f orchestrate_pipeline > /dev/null; then
    echo "⚠ Warning: Some processes still running. Forcing kill..."
    pkill -9 -f orchestrate_pipeline
fi

echo "[✓] Pipeline stopped"
echo ""
echo "Logs available at:"
echo "  - /logs/orchestrator.log"
echo "  - /logs/alerts.log"
