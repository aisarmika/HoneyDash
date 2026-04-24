"""
Mock Dionaea event generator for HoneyDash demo/testing.

Posts realistic Dionaea multi-protocol events to the HoneyDash ingest API
at a configurable rate. Simulates HTTP exploits, SMB/EternalBlue, FTP/MySQL/
MSSQL brute-force, SIP scanning and malware downloads.

Environment variables:
  BACKEND_URL        (default: http://backend:8000)
  SENSOR_API_KEY     (default: honeydash-sensor-key-change-me)
  EVENTS_PER_SECOND  (default: 0.4)
  SENSOR_NAME        (default: dionaea-01)
"""

import json
import os
import random
import time
import uuid
from datetime import datetime, timezone
from urllib import request as urllib_request
from urllib.error import URLError

BACKEND_URL      = os.environ.get("BACKEND_URL", "http://backend:8000")
SENSOR_API_KEY   = os.environ.get("SENSOR_API_KEY", "honeydash-sensor-key-change-me")
EVENTS_PER_SECOND = float(os.environ.get("EVENTS_PER_SECOND", "0.4"))
SENSOR_NAME      = os.environ.get("SENSOR_NAME", "dionaea-01")
SLEEP            = 1.0 / EVENTS_PER_SECOND
INGEST_URL       = f"{BACKEND_URL}/api/ingest/event"

# ── Attacker IP pools (different from Cowrie to show separate sources) ─────
ATTACKER_IPS = [
    "80.82.77.33",  "94.102.49.190", "198.20.69.74",  "162.142.125.11",
    "167.94.138.35","71.6.135.131",  "192.241.236.27","178.128.23.9",
    "5.34.178.30",  "91.191.209.26", "185.220.101.45","46.101.166.19",
    "142.93.200.47","134.209.82.24", "209.141.55.102","157.245.108.73",
    "178.62.112.153","68.183.103.130","159.89.135.102","104.248.228.124",
]

# ── Protocol config ─────────────────────────────────────────────────────────
PROTOCOLS = [
    {"proto": "smb",   "port": 445,  "weight": 20, "event": "dionaea.connection.smb"},
    {"proto": "http",  "port": 80,   "weight": 18, "event": "dionaea.connection.http"},
    {"proto": "ftp",   "port": 21,   "weight": 15, "event": "dionaea.connection.ftp"},
    {"proto": "mysql", "port": 3306, "weight": 15, "event": "dionaea.connection.mysql"},
    {"proto": "mssql", "port": 1433, "weight": 12, "event": "dionaea.connection.mssql"},
    {"proto": "sip",   "port": 5060, "weight": 10, "event": "dionaea.connection.sip"},
    {"proto": "https", "port": 443,  "weight": 10, "event": "dionaea.connection.https"},
]

FTP_USERS  = ["anonymous", "ftp", "admin", "user", "ftpuser", "upload"]
FTP_PASSES = ["anonymous", "", "ftp", "admin", "123456", "password"]
DB_USERS   = ["root", "admin", "sa", "mysql", "postgres", "dba", "test"]
DB_PASSES  = ["", "root", "admin", "123456", "password", "mysql", "1234", "sa", "admin123"]
HTTP_USERS = ["admin", "administrator", "root", "user", "test"]
HTTP_PASSES= ["admin", "password", "123456", "admin123", "pass"]

MALWARE_URLS = [
    "http://80.82.77.33/miner.exe",
    "http://94.102.49.190/payload.exe",
    "http://185.220.101.45/bot.elf",
    "http://46.101.166.19/rootkit.dll",
    "http://142.93.200.47/worm.bin",
]

MALWARE_MD5S = [
    "d41d8cd98f00b204e9800998ecf8427e",
    "098f6bcd4621d373cade4e832627b4f6",
    "5d41402abc4b2a76b9719d911017c592",
    "7215ee9c7d9dc229d2921a40e899ec5f",
    "b026324c6904b2a9cb4b88d6d61c81d1",
]


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def post_event(data: dict) -> bool:
    body = json.dumps(data).encode("utf-8")
    req = urllib_request.Request(
        INGEST_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Sensor-Key": SENSOR_API_KEY,
        },
        method="POST",
    )
    try:
        with urllib_request.urlopen(req, timeout=5) as resp:
            return resp.status == 202
    except Exception:
        return False


def pick_protocol():
    weights = [p["weight"] for p in PROTOCOLS]
    return random.choices(PROTOCOLS, weights=weights, k=1)[0]


class DionaeaSession:
    def __init__(self):
        self.conn_id = uuid.uuid4().hex[:12]
        self.ip      = random.choice(ATTACKER_IPS)
        self.src_port = random.randint(1024, 65535)
        proto_cfg    = pick_protocol()
        self.proto   = proto_cfg["proto"]
        self.port    = proto_cfg["port"]
        self.event   = proto_cfg["event"]
        self.phase   = "connect"
        self.login_count = 0
        self.max_logins  = random.randint(1, 8)

    def session_id(self):
        return f"dionaea-{self.conn_id}"

    def next_event(self) -> dict | None:
        """Return the next event dict or None to skip."""

        # ── Initial connection ──────────────────────────────────────────────
        if self.phase == "connect":
            self.phase = "login" if self.proto in ("ftp", "mysql", "mssql", "http") else "done"
            return {
                "eventid":   self.event,
                "src_ip":    self.ip,
                "src_port":  self.src_port,
                "dst_port":  self.port,
                "session":   self.session_id(),
                "timestamp": ts(),
                "sensor":    SENSOR_NAME,
                "protocol":  self.proto,
            }

        # ── Login brute-force attempts ──────────────────────────────────────
        if self.phase == "login":
            if self.login_count < self.max_logins:
                self.login_count += 1
                if self.proto == "ftp":
                    user, pw = random.choice(FTP_USERS), random.choice(FTP_PASSES)
                elif self.proto in ("mysql", "mssql"):
                    user, pw = random.choice(DB_USERS), random.choice(DB_PASSES)
                else:  # http
                    user, pw = random.choice(HTTP_USERS), random.choice(HTTP_PASSES)

                # Small chance of malware download after login
                if self.login_count == self.max_logins and random.random() < 0.15:
                    self.phase = "download"
                elif self.login_count == self.max_logins:
                    self.phase = "done"

                return {
                    "eventid":   f"dionaea.login.{self.proto}",
                    "src_ip":    self.ip,
                    "src_port":  self.src_port,
                    "dst_port":  self.port,
                    "session":   self.session_id(),
                    "timestamp": ts(),
                    "sensor":    SENSOR_NAME,
                    "protocol":  self.proto,
                    "username":  user,
                    "password":  pw,
                }
            self.phase = "done"
            return None

        # ── Malware download ────────────────────────────────────────────────
        if self.phase == "download":
            self.phase = "done"
            url = random.choice(MALWARE_URLS)
            md5 = random.choice(MALWARE_MD5S)
            return {
                "eventid":      "dionaea.download.captured",
                "src_ip":       self.ip,
                "src_port":     self.src_port,
                "dst_port":     self.port,
                "session":      self.session_id(),
                "timestamp":    ts(),
                "sensor":       SENSOR_NAME,
                "protocol":     self.proto,
                "url":          url,
                "download_md5": md5,
            }

        return None  # phase == "done"


def wait_for_backend(max_tries: int = 30) -> bool:
    health_url = f"{BACKEND_URL}/health"
    for i in range(max_tries):
        try:
            with urllib_request.urlopen(health_url, timeout=3) as r:
                if r.status == 200:
                    print(f"[mock-dionaea] Backend ready after {i+1} attempt(s)")
                    return True
        except Exception:
            pass
        print(f"[mock-dionaea] Waiting for backend… ({i+1}/{max_tries})")
        time.sleep(5)
    return False


def main():
    print(f"[mock-dionaea] Starting — target {INGEST_URL} at {EVENTS_PER_SECOND} events/sec")
    if not wait_for_backend():
        print("[mock-dionaea] Backend never became ready — exiting")
        return

    active_sessions: list[DionaeaSession] = []

    while True:
        # Spawn new session occasionally
        if random.random() < 0.35 or not active_sessions:
            active_sessions.append(DionaeaSession())

        still_active = []
        for sess in active_sessions:
            event = sess.next_event()
            if event:
                ok = post_event(event)
                status = "✓" if ok else "✗"
                print(f"  {status} {event['eventid']} [{event['protocol'].upper()}] from {event['src_ip']}")
            if sess.phase != "done":
                still_active.append(sess)
        active_sessions = still_active

        time.sleep(SLEEP)


if __name__ == "__main__":
    main()
