"""Incident builder: group events into incidents (placeholder)."""
import time
from collections import defaultdict
from typing import Dict, Optional, List


# =========================
# INCIDENT STATE STORE
# =========================

INCIDENT_STORE = defaultdict(list)
INCIDENT_TIMEOUT = 300  # 5 minutes window


# =========================
# INCIDENT BUILDER
# =========================

def build_incident(key: str, events: List[Dict], reason: str) -> Dict:
    return {
        "incident_id": f"INC-{int(time.time())}",
        "incident_key": key,
        "severity": calculate_severity(events),
        "event_count": len(events),
        "events": events,
        "reason": reason,
        "timestamp": time.time()
    }


def calculate_severity(events: List[Dict]) -> str:
    max_risk = max(e.get("risk_score", 0) for e in events)

    if max_risk >= 80:
        return "CRITICAL"
    elif max_risk >= 50:
        return "HIGH"
    elif max_risk >= 30:
        return "MEDIUM"
    return "LOW"


# =========================
# CORRELATION LOGIC
# =========================

def correlate_event(event: Dict) -> Optional[Dict]:

    key = event.get("source_ip") or event.get("username")

    if not key:
        return None

    now = time.time()

    # Remove expired events
    INCIDENT_STORE[key] = [
        e for e in INCIDENT_STORE[key]
        if now - e["__internal_time"] <= INCIDENT_TIMEOUT
    ]

    # Add new event with internal timestamp
    event["__internal_time"] = now
    INCIDENT_STORE[key].append(event)

    # Correlation rule:
    # If we see:
    # - Failed login
    # - Success login
    # - Privilege escalation
    # within time window → create incident

    event_types = {e["event_type"] for e in INCIDENT_STORE[key]}

    if {
        "ssh_failed_login",
        "ssh_success_login",
        "sudo_execution"
    }.issubset(event_types):

        incident = build_incident(
            key=key,
            events=INCIDENT_STORE[key],
            reason="Multi-stage SSH compromise with privilege escalation"
        )

        INCIDENT_STORE[key] = []  # reset after incident

        return incident

    return None