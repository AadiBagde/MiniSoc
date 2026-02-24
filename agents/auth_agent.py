"""
Auth Agent
Collects Linux auth logs → normalizes → detects → correlates → generates alerts/incidents
"""

import os
import time
import json
import hashlib
from datetime import datetime
from typing import Generator, Dict

from parser.log_parser import parse_auth_log
from detection.rules_engine import process_event
from correlation.incident_builder import correlate_event


# =========================
# CONFIGURATION
# =========================

CONFIG = {
    "log_file": "/var/log/auth.log",   # Change to /var/log/secure if needed
    "poll_interval": 1,
    "agent_name": "auth_agent",
    "host": os.uname().nodename
}


# =========================
# UTILS
# =========================

def file_hash(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


def current_timestamp() -> str:
    return datetime.utcnow().isoformat() + "Z"


# =========================
# FILE FOLLOWER (tail -f style)
# =========================

def follow_log(file_path: str) -> Generator[str, None, None]:

    with open(file_path, "r") as f:
        f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino

        while True:
            line = f.readline()

            if line:
                yield line
            else:
                time.sleep(CONFIG["poll_interval"])

                try:
                    if os.stat(file_path).st_ino != inode:
                        f.close()
                        f = open(file_path, "r")
                        inode = os.fstat(f.fileno()).st_ino
                except FileNotFoundError:
                    time.sleep(1)


# =========================
# MAIN AGENT LOOP
# =========================

def run_agent():

    if not os.path.exists(CONFIG["log_file"]):
        raise FileNotFoundError(f"Log file not found: {CONFIG['log_file']}")

    print(f"[+] Auth Agent started on {CONFIG['host']}")
    print(f"[+] Monitoring {CONFIG['log_file']}")

    for line in follow_log(CONFIG["log_file"]):

        # Filter noise early
        if "sshd" not in line and "sudo" not in line:
            continue

        # -------------------------
        # Step 1: Normalize
        # -------------------------
        normalized_event = parse_auth_log(line)
        if not normalized_event:
            continue

        # -------------------------
        # Step 2: Detection
        # -------------------------
        alert = process_event(normalized_event)

        # -------------------------
        # Step 3: Correlation
        # -------------------------
        incident = correlate_event(normalized_event)

        # -------------------------
        # Step 4: Print Event
        # -------------------------
        print("\n📦 EVENT")
        print(json.dumps(normalized_event, indent=2))

        # -------------------------
        # Step 5: Print Alert
        # -------------------------
        if alert:
            print("\n🚨 ALERT GENERATED 🚨")
            print(json.dumps(alert, indent=2))

        # -------------------------
        # Step 6: Print Incident
        # -------------------------
        if incident:
            print("\n🔥 INCIDENT CREATED 🔥")
            print(json.dumps(incident, indent=2))


# =========================
# ENTRY POINT
# =========================

if __name__ == "__main__":
    try:
        run_agent()
    except KeyboardInterrupt:
        print("\n[!] Auth Agent stopped")
    except Exception as e:
        print(f"[ERROR] {e}")