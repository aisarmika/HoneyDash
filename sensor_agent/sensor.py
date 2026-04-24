#!/usr/bin/env python3
"""
HoneyDash Remote Sensor Agent
==============================
Run this on any machine that has a Cowrie JSON log file.
It tails the log and forwards new events to your HoneyDash instance.

Usage:
    python sensor.py

Configuration (edit the section below, or set as environment variables):
    HONEYDASH_URL      — https://yourdomain.com  (no trailing slash)
    SENSOR_API_KEY     — the key from HoneyDash's SENSOR_API_KEY env var
    COWRIE_LOG_PATH    — path to cowrie.json on this machine
    SENSOR_NAME        — friendly name shown in HoneyDash (e.g. "friends-vps")

Requirements:
    pip install requests
"""

import json
import os
import time

import requests

# ── Configuration ─────────────────────────────────────────────────────────────
HONEYDASH_URL   = os.getenv("HONEYDASH_URL",   "https://yourdomain.com")
SENSOR_API_KEY  = os.getenv("SENSOR_API_KEY",  "honeydash-sensor-key-change-me")
COWRIE_LOG_PATH = os.getenv("COWRIE_LOG_PATH", "/home/cowrie/var/log/cowrie/cowrie.json")
SENSOR_NAME     = os.getenv("SENSOR_NAME",     "remote-sensor-1")
BATCH_SIZE      = int(os.getenv("BATCH_SIZE",  "20"))    # events to buffer before sending
FLUSH_INTERVAL  = float(os.getenv("FLUSH_INTERVAL", "5"))  # seconds between forced flushes
# ─────────────────────────────────────────────────────────────────────────────

INGEST_URL = HONEYDASH_URL.rstrip("/") + "/api/ingest/batch"
HEADERS    = {"X-Sensor-Key": SENSOR_API_KEY, "Content-Type": "application/json"}


def send_batch(events: list[dict]) -> bool:
    try:
        r = requests.post(INGEST_URL, json=events, headers=HEADERS, timeout=10)
        if r.status_code == 202:
            result = r.json()
            print(f"[sensor] sent {result['accepted']}/{result['total']} events", flush=True)
            return True
        else:
            print(f"[sensor] server returned {r.status_code}: {r.text[:200]}", flush=True)
            return False
    except Exception as e:
        print(f"[sensor] send failed: {e}", flush=True)
        return False


def tail_log():
    path = COWRIE_LOG_PATH
    print(f"[sensor] watching {path}  →  {INGEST_URL}", flush=True)
    print(f"[sensor] sensor name: {SENSOR_NAME}", flush=True)

    # Wait for file to exist
    while not os.path.exists(path):
        print(f"[sensor] waiting for {path} ...", flush=True)
        time.sleep(5)

    buffer: list[dict] = []
    last_flush = time.time()

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # seek to end — only forward new events from now on

        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    # Tag with sensor name so HoneyDash knows where it came from
                    event.setdefault("sensor", SENSOR_NAME)
                    buffer.append(event)
                except json.JSONDecodeError:
                    pass

                if len(buffer) >= BATCH_SIZE:
                    if send_batch(buffer):
                        buffer.clear()
                    last_flush = time.time()
            else:
                # No new data — flush buffer if FLUSH_INTERVAL elapsed
                if buffer and (time.time() - last_flush) >= FLUSH_INTERVAL:
                    if send_batch(buffer):
                        buffer.clear()
                    last_flush = time.time()

                time.sleep(0.5)

                # Detect log rotation
                try:
                    current_size = os.path.getsize(path)
                    if current_size < f.tell():
                        print("[sensor] log rotation detected, seeking to start", flush=True)
                        f.seek(0)
                except OSError:
                    time.sleep(2)
                    while not os.path.exists(path):
                        time.sleep(2)
                    f.seek(0)


if __name__ == "__main__":
    tail_log()
