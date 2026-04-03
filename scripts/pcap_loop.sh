#!/bin/bash

PCAP_DIR=~/ands/pcaps
CSV_DIR=~/ands/flows_csv


CIC_PATH=C:\Users\user\Desktop\P2M\CICflow-meter

mkdir -p $CSV_DIR

echo "[+] PCAP → CSV loop started"

while true; do
  for p in $PCAP_DIR/*.pcap; do
    [ -e "$p" ] || continue

    out=$CSV_DIR/$(basename "$p" .pcap).csv

    if [ ! -f "$out" ]; then
      echo "[+] Processing $p"

      $CIC_PATH -f "$p" -c "$out"

      # delete after processing (prevents clutter)
      rm "$p"
    fi
  done

  sleep 1
done