"""Log parser: regex + schema-based parsing (placeholder)."""
import re
from datetime import datetime
from typing import Optional, Dict
from parser.event_schema import base_event_schema
import os

HOSTNAME = os.uname().nodename

SSH_FAILED_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*sshd\[(?P<pid>\d+)\]: '
    r'Failed password for (invalid user )?(?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

SSH_SUCCESS_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*sshd\[(?P<pid>\d+)\]: '
    r'Accepted password for (?P<user>\w+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

SUDO_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>[\d:]+).*sudo: '
    r'(?P<user>\w+) : .*COMMAND=(?P<command>.+)'
)

def normalize_timestamp(month: str, day: str, time_str: str) -> str:
    current_year = datetime.utcnow().year
    timestamp_str = f"{month} {day} {current_year} {time_str}"
    dt = datetime.strptime(timestamp_str, "%b %d %Y %H:%M:%S")
    return dt.isoformat() + "Z"

def parse_auth_log(raw_log: str) -> Optional[Dict]:

    failed_match = SSH_FAILED_PATTERN.search(raw_log)
    if failed_match:
        event = base_event_schema()
        event.update({
            "event_id": 1001,
            "event_type": "ssh_failed_login",
            "event_category": "authentication",
            "timestamp": normalize_timestamp(
                failed_match.group("month"),
                failed_match.group("day"),
                failed_match.group("time")
            ),
            "host": HOSTNAME,
            "username": failed_match.group("user"),
            "source_ip": failed_match.group("ip"),
            "process_id": failed_match.group("pid"),
            "status": "failure",
            "severity": "MEDIUM",
            "risk_score": 40,
            "mitre_technique": "T1110",
            "raw_log": raw_log.strip()
        })
        return event

    success_match = SSH_SUCCESS_PATTERN.search(raw_log)
    if success_match:
        event = base_event_schema()
        event.update({
            "event_id": 1002,
            "event_type": "ssh_success_login",
            "event_category": "authentication",
            "timestamp": normalize_timestamp(
                success_match.group("month"),
                success_match.group("day"),
                success_match.group("time")
            ),
            "host": HOSTNAME,
            "username": success_match.group("user"),
            "source_ip": success_match.group("ip"),
            "process_id": success_match.group("pid"),
            "status": "success",
            "severity": "LOW",
            "risk_score": 10,
            "mitre_technique": "T1078",
            "raw_log": raw_log.strip()
        })
        return event

    sudo_match = SUDO_PATTERN.search(raw_log)
    if sudo_match:
        event = base_event_schema()
        event.update({
            "event_id": 2001,
            "event_type": "sudo_execution",
            "event_category": "privilege_escalation",
            "timestamp": normalize_timestamp(
                sudo_match.group("month"),
                sudo_match.group("day"),
                sudo_match.group("time")
            ),
            "host": HOSTNAME,
            "username": sudo_match.group("user"),
            "command": sudo_match.group("command"),
            "status": "success",
            "severity": "HIGH",
            "risk_score": 70,
            "mitre_technique": "T1068",
            "raw_log": raw_log.strip()
        })
        return event

    return None