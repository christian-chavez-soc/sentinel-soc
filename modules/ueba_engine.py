"""
Sentinel SOC - Option J: UEBA Engine
modules/ueba_engine.py

Detects behavioral anomalies:
  1. Login outside normal hours
  2. Login from new location/IP
  3. Unusual event volume spike
  4. Access to new systems never seen before
"""

from datetime import datetime
from collections import defaultdict

# ── Baseline storage ──────────────────────────────────────────
# Keyed by username
_baselines = defaultdict(lambda: {
    "login_hours":    [],       # list of hour integers seen
    "known_ips":      set(),    # IPs ever seen for this user
    "known_hosts":    set(),    # hosts ever accessed
    "event_counts":   [],       # daily event counts for volume baseline
    "total_events":   0,
    "first_seen":     None,
    "last_seen":      None,
})

_anomaly_log = []   # list of anomaly dicts
_event_counts_today = defaultdict(int)  # username -> count today


def _hour_is_anomalous(username: str, hour: int) -> bool:
    """Flag if login hour is outside the user's normal window."""
    hours = _baselines[username]["login_hours"]
    if len(hours) < 10:
        return False  # not enough data yet
    avg = sum(hours) / len(hours)
    # Flag if more than 6 hours from average (e.g. avg=9am, flag if before 3am or after 3pm)
    return abs(hour - avg) > 6


def _ip_is_new(username: str, ip: str) -> bool:
    if not ip or ip in ("unknown", "0.0.0.0"):
        return False
    known = _baselines[username]["known_ips"]
    if len(known) == 0:
        return False  # first event, not anomalous
    return ip not in known


def _host_is_new(username: str, host: str) -> bool:
    if not host or host in ("unknown", ""):
        return False
    known = _baselines[username]["known_hosts"]
    if len(known) == 0:
        return False
    return host not in known


def _volume_is_anomalous(username: str) -> bool:
    """Flag if today's event count is 3x above the user's daily average."""
    counts = _baselines[username]["event_counts"]
    if len(counts) < 3:
        return False
    avg = sum(counts) / len(counts)
    today = _event_counts_today[username]
    return avg > 0 and today > avg * 3


def analyze_event(event: dict) -> list:
    """
    Analyze a single event for behavioral anomalies.
    Updates baseline and returns list of anomaly dicts (empty if none).
    """
    username   = event.get("username", "")
    source_ip  = event.get("source_ip", "unknown")
    agent_host = event.get("agent_host", "unknown")
    timestamp  = event.get("timestamp", datetime.utcnow().isoformat())
    risk_score = event.get("risk_score", 0)

    if not username or username in ("unknown", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-"):
        return []

    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", ""))
    except Exception:
        dt = datetime.utcnow()

    hour = dt.hour
    anomalies = []

    # ── Check anomalies BEFORE updating baseline ──────────────
    if _hour_is_anomalous(username, hour):
        anomalies.append({
            "type":        "off_hours_login",
            "title":       "Off-Hours Login Detected",
            "description": f"{username} logged in at {hour:02d}:00 UTC — outside their normal activity window",
            "severity":    "HIGH",
            "username":    username,
            "source_ip":   source_ip,
            "host":        agent_host,
            "timestamp":   timestamp,
            "risk_boost":  75,
        })

    if _ip_is_new(username, source_ip):
        anomalies.append({
            "type":        "new_ip",
            "title":       "Login from New IP Address",
            "description": f"{username} logged in from {source_ip} — IP never seen before for this user",
            "severity":    "HIGH",
            "username":    username,
            "source_ip":   source_ip,
            "host":        agent_host,
            "timestamp":   timestamp,
            "risk_boost":  80,
        })

    if _host_is_new(username, agent_host):
        anomalies.append({
            "type":        "new_host",
            "title":       "Access to New System",
            "description": f"{username} accessed {agent_host} — system never seen before for this user",
            "severity":    "MEDIUM",
            "username":    username,
            "source_ip":   source_ip,
            "host":        agent_host,
            "timestamp":   timestamp,
            "risk_boost":  50,
        })

    if _volume_is_anomalous(username):
        anomalies.append({
            "type":        "volume_spike",
            "title":       "Unusual Event Volume Spike",
            "description": f"{username} has generated {_event_counts_today[username]} events today — significantly above their baseline",
            "severity":    "MEDIUM",
            "username":    username,
            "source_ip":   source_ip,
            "host":        agent_host,
            "timestamp":   timestamp,
            "risk_boost":  40,
        })

    # ── Update baseline ───────────────────────────────────────
    bl = _baselines[username]
    bl["login_hours"].append(hour)
    if len(bl["login_hours"]) > 200:
        bl["login_hours"] = bl["login_hours"][-200:]

    if source_ip and source_ip not in ("unknown", "0.0.0.0"):
        bl["known_ips"].add(source_ip)

    if agent_host and agent_host not in ("unknown", ""):
        bl["known_hosts"].add(agent_host)

    bl["total_events"] += 1
    bl["last_seen"] = timestamp
    if not bl["first_seen"]:
        bl["first_seen"] = timestamp

    _event_counts_today[username] += 1

    # Store anomalies
    for a in anomalies:
        _anomaly_log.append(a)

    return anomalies


def get_anomalies(limit: int = 100) -> list:
    return _anomaly_log[-limit:]


def get_user_profiles() -> list:
    """Return UEBA profile summary for all tracked users."""
    profiles = []
    for username, bl in _baselines.items():
        hours = bl["login_hours"]
        avg_hour = round(sum(hours) / len(hours), 1) if hours else 0
        profiles.append({
            "username":       username,
            "total_events":   bl["total_events"],
            "known_ips":      list(bl["known_ips"]),
            "known_hosts":    list(bl["known_hosts"]),
            "avg_login_hour": avg_hour,
            "first_seen":     bl["first_seen"],
            "last_seen":      bl["last_seen"],
            "anomaly_count":  sum(1 for a in _anomaly_log if a["username"] == username),
        })
    profiles.sort(key=lambda x: x["anomaly_count"], reverse=True)
    return profiles


def get_stats() -> dict:
    total_anomalies = len(_anomaly_log)
    by_type = {}
    by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in _anomaly_log:
        by_type[a["type"]] = by_type.get(a["type"], 0) + 1
        sev = a.get("severity", "LOW")
        if sev in by_severity:
            by_severity[sev] += 1
    return {
        "total_anomalies": total_anomalies,
        "users_tracked":   len(_baselines),
        "by_type":         by_type,
        "by_severity":     by_severity,
    }
