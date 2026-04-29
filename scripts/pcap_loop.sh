#!/bin/bash

# Move to repo root
cd "$(dirname "$0")/.."

PCAP_DIR="data/test1"
CSV_DIR="data/flows_csv"
CIC_PATH="python CICflow-meter/src/cicflowmeter/sniffer.py"

mkdir -p "$PCAP_DIR"
mkdir -p "$CSV_DIR"

echo "[+] PCAP → CSV loop started"
echo "Watching $PCAP_DIR for new pcap files..."

while true; do
  # Support both pcap and pcapng
  for p in "$PCAP_DIR"/*.pcap*; do
    [ -e "$p" ] || continue

    out="$CSV_DIR"/$(basename "$p").csv

    if [ ! -f "$out" ]; then
      echo "[+] Processing $p"

      $CIC_PATH -f "$p" -c "$out"

      # delete after processing (prevents clutter)
      rm -f "$p"
    fi
  done

  sleep 1
done