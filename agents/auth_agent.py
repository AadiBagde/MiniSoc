"""Auth agent: collect and forward SSH/sudo/auth logs (placeholder)."""

import os 
import time 
import json
import hashlib
from datetime import datetime
from typing import List, Dict, Generator


# =========================
# CONFIGURATION
# =========================

CONFIG = {
    "log_file" : "/var/log/auth.log",
    "poll_interval" : 1,
    "agent_name" : "auth_agent",
    "host" : os.uname().nodename
}

# =========================
# UTILS
# =========================

def file_hash(line: str) -> str:
    """Generate a hash for a log line."""
    return hashlib.sha256(line.encode()).hexdigest()

def current_timestamp() -> str: 
    """Get the current timestamp in ISO format."""
    return datetime.utcnow().isoformat() + "Z"

# =========================
# FILE FOLLOWER 
# =========================

def follow_log(file_path: str) -> Generator[str, None, None]:
    """
    Follow a log file like tail -f
    Handles log rotation safely
    """
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
                        # Log rotated
                        f.close()
                        f = open(file_path, "r")
                        inode = os.fstat(f.fileno()).st_ino
                except FileNotFoundError:
                    time.sleep(1)

# =========================
# EVENT BUILDER
# =========================

def build_event(raw_line: str) -> Dict:
    """
    Convert raw log line to structured security event
    """
    return {
        "agent": CONFIG["agent_name"],
        "host": CONFIG["host"],
        "event_source": "linux_auth",
        "raw_log": raw_line.strip(),
        "timestamp": current_timestamp(),
        "hash": file_hash(raw_line)
    }

# =========================
# MAIN AGENT LOOP
# =========================

def run_agent():
    if not os.path.exists(CONFIG["log_file"]):
        raise FileNotFoundError(f"Log file not found: {CONFIG['log_file']}")

    print(f"[+] Auth Agent started on {CONFIG['host']}")
    print(f"[+] Monitoring {CONFIG['log_file']}")

    for line in follow_log(CONFIG["log_file"]):
        if "sshd" in line or "sudo" in line:
            event = build_event(line)
            print(json.dumps(event, indent=2))

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