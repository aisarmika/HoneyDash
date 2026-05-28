#!/usr/bin/env python3
"""
HoneyDash Remote Sensor Forwarder
==================================
Tails a Cowrie JSON log file and forwards each event to the HoneyDash
ingest API in real time.

Usage:
    python3 forwarder.py

Requirements:
    pip install requests

Configuration (edit the variables below or set environment variables):
    HONEYDASH_URL     — HoneyDash backend URL  e.g. http://1.2.3.4:8000
    SENSOR_API_KEY    — Shared secret from backend/.env SENSOR_API_KEY
    SENSOR_NAME       — How this sensor appears in the dashboard
    COWRIE_LOG_PATH   — Path to cowrie.json on this machine
"""

import json
import os
import time
from datetime import datetime

import requests

# ── Configuration ────────────────────────────────────────────────────────────
HONEYDASH_URL  = os.getenv("HONEYDASH_URL",  "http://YOUR_VPS_IP:8000")
SENSOR_API_KEY = os.getenv("SENSOR_API_KEY", "change-this-sensor-key")
SENSOR_NAME    = os.getenv("SENSOR_NAME",    "remote-sensor-01")
COWRIE_LOG_PATH = os.getenv("COWRIE_LOG_PATH", "/home/cowrie/cowrie/var/log/cowrie/cowrie.json")

INGEST_URL  = f"{HONEYDASH_URL}/api/ingest/event"
HEADERS     = {"X-Sensor-Key": SENSOR_API_KEY, "Content-Type": "application/json"}
RETRY_DELAY = 5   # seconds between retries on connection error
POLL_DELAY  = 0.5 # seconds between log polls when no new lines

# ─────────────────────────────────────────────────────────────────────────────

def send_event(data: dict) -> bool:
    """POST a single event to the HoneyDash ingest API. Returns True on success."""
    # Stamp the sensor name so it shows up correctly in the dashboard
    data.setdefault("sensor", SENSOR_NAME)
    try:
        resp = requests.post(INGEST_URL, json=data, headers=HEADERS, timeout=10)
        if resp.status_code == 202:
            return True
        print(f"[{now()}] API error {resp.status_code}: {resp.text[:120]}")
    except requests.exceptions.ConnectionError:
        print(f"[{now()}] Cannot reach HoneyDash — will retry in {RETRY_DELAY}s")
        time.sleep(RETRY_DELAY)
    except Exception as exc:
        print(f"[{now()}] Error: {exc}")
    return False


def now() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def tail_log(path: str):
    """Tail a file, yielding new lines as they appear. Handles log rotation."""
    print(f"[{now()}] Waiting for log file: {path}")
    while not os.path.exists(path):
        time.sleep(5)

    print(f"[{now()}] Log file found. Seeking to end (only new events will be forwarded).")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)  # seek to end — skip historical events on startup
        last_size = os.path.getsize(path)

        while True:
            line = f.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(POLL_DELAY)
                # Detect log rotation
                try:
                    current_size = os.path.getsize(path)
                    if current_size < last_size:
                        print(f"[{now()}] Log rotation detected — re-opening from start")
                        f.seek(0)
                    last_size = current_size
                except OSError:
                    time.sleep(2)
                    while not os.path.exists(path):
                        time.sleep(2)
                    f.seek(0)
                    last_size = 0


def main():
    print(f"[{now()}] HoneyDash Remote Sensor Forwarder starting")
    print(f"[{now()}] Sensor name : {SENSOR_NAME}")
    print(f"[{now()}] Target      : {INGEST_URL}")
    print(f"[{now()}] Log file    : {COWRIE_LOG_PATH}")
    print()

    sent = 0
    for line in tail_log(COWRIE_LOG_PATH):
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if send_event(data):
            sent += 1
            eid = data.get("eventid", "?")
            ip  = data.get("src_ip", "?")
            print(f"[{now()}] Sent #{sent:>5} | {eid:<35} | {ip}")


if __name__ == "__main__":
    main()
