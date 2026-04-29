#!/bin/bash

# Move to repo root (CRITICAL)
cd "$(dirname "$0")/.."

echo "====================================="
echo "   AND SYSTEM STARTING..."
echo "====================================="

# Create dirs
mkdir -p data/test1
mkdir -p data/flows_csv
mkdir -p logs

# Kill old processes (avoid duplicates)
echo "[+] Cleaning old processes..."
pkill -f tcpdump
pkill -f pcap_loop.sh
pkill -f "python -m src.main"
pkill -f "uvicorn src.api"

sleep 2

# Start packet capture
echo "[+] Starting packet capture..."
sudo tcpdump -i eth1 -w data/test1/capture_%s.pcap -G 5 -W 100 > logs/tcpdump.log 2>&1 &

sleep 2

# Start PCAP processing
echo "[+] Starting PCAP processing..."
bash scripts/pcap_loop.sh > logs/pcap_loop.log 2>&1 &

sleep 2

# Start ML engine
echo "[+] Starting ML detection API..."
export FLOW_WATCH_DIR="data/flows_csv"
python -m uvicorn src.api:app --host 0.0.0.0 --port 8000 > logs/ml.log 2>&1 &

sleep 2

echo "[+] SYSTEM RUNNING"
echo "Logs:"
echo "  - tcpdump:   logs/tcpdump.log"
echo "  - pcap loop: logs/pcap_loop.log"
echo "  - ML API:    logs/ml.log"

echo "====================================="