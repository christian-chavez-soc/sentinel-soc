import geoip2.database
import os
from datetime import datetime

GEOIP_DB = "C:\\AI\\sentinel\\GeoLite2-City.mmdb"

attack_locations = []

def lookup_ip(ip):
    if not ip or ip in ["unknown", "-", "127.0.0.1", "::1", "0.0.0.0"]:
        return None
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
        return None
    if not os.path.exists(GEOIP_DB):
        return None
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.city(ip)
            return {
                "ip": ip,
                "country": response.country.name or "Unknown",
                "country_code": response.country.iso_code or "XX",
                "city": response.city.name or "Unknown",
                "latitude": float(response.location.latitude or 0),
                "longitude": float(response.location.longitude or 0),
                "accuracy": response.location.accuracy_radius or 0
            }
    except Exception:
        return None

def track_attack(risk):
    ip = risk.get("source_ip", "unknown")
    username = risk.get("username", "unknown")
    score = risk.get("risk_score", 0)
    agent = risk.get("agent_host", "unknown")

    geo = lookup_ip(ip)
    if not geo:
        return None

    entry = {
        "ip": ip,
        "username": username,
        "risk_score": score,
        "agent": agent,
        "country": geo["country"],
        "country_code": geo["country_code"],
        "city": geo["city"],
        "latitude": geo["latitude"],
        "longitude": geo["longitude"],
        "timestamp": datetime.now().isoformat()
    }
    attack_locations.append(entry)
    print(f"GEO TRACK: {username} from {geo['city']}, {geo['country']} ({ip}) Risk: {score}")
    return entry

def get_attack_locations():
    return attack_locations

def get_country_stats():
    stats = {}
    for loc in attack_locations:
        country = loc["country"]
        if country not in stats:
            stats[country] = {"count": 0, "total_risk": 0, "country_code": loc["country_code"]}
        stats[country]["count"] += 1
        stats[country]["total_risk"] += loc["risk_score"]
    return sorted(stats.items(), key=lambda x: x[1]["total_risk"], reverse=True)
