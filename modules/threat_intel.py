import requests
import json
import os
from datetime import datetime, timedelta

CACHE_FILE = "C:\\AI\\sentinel\\threat_intel_cache.json"
CACHE_EXPIRY_HOURS = 24

# Free threat intel sources
ABUSE_IPDB_URL = "https://api.abuseipdb.com/api/v2/check"
THREAT_FOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Known malicious IP ranges and indicators (built-in offline list)
KNOWN_MALICIOUS_RANGES = [
    "192.168.1.44",  # example
]

KNOWN_BAD_USERNAMES = [
    "administrator", "admin", "root", "guest", "test",
    "user", "oracle", "postgres", "mysql", "ftpuser",
    "anonymous", "backup", "deploy", "jenkins", "tomcat"
]

SUSPICIOUS_PATTERNS = {
    "credential_stuffing": ["admin", "administrator", "root", "guest"],
    "service_accounts": ["svc_", "service_", "_svc", "_service"],
    "default_accounts": ["test", "demo", "temp", "backup"]
}

def load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_cache(data):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except:
        pass

def is_cache_valid(entry):
    if "cached_at" not in entry:
        return False
    cached_at = datetime.fromisoformat(entry["cached_at"])
    return datetime.now() - cached_at < timedelta(hours=CACHE_EXPIRY_HOURS)

def check_ip_reputation(ip):
    if not ip or ip in ["unknown", "-", "127.0.0.1", "::1"]:
        return {"score": 0, "malicious": False, "source": "skipped"}

    cache = load_cache()
    cache_key = f"ip_{ip}"

    if cache_key in cache and is_cache_valid(cache[cache_key]):
        return cache[cache_key]["data"]

    result = {"ip": ip, "score": 0, "malicious": False, "source": "local"}

    # Check built-in list
    if ip in KNOWN_MALICIOUS_RANGES:
        result["score"] = 100
        result["malicious"] = True
        result["reason"] = "Known malicious IP (local list)"
        result["source"] = "local"

    # Try AbuseIPDB (free tier - no key needed for basic check)
    try:
        response = requests.get(
            ABUSE_IPDB_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": "free", "Accept": "application/json"},
            timeout=3
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            if abuse_score > 0:
                result["score"] = abuse_score
                result["malicious"] = abuse_score > 50
                result["reports"] = data.get("totalReports", 0)
                result["country"] = data.get("countryCode", "unknown")
                result["source"] = "abuseipdb"
    except:
        pass

    # Try ThreatFox for IOC lookup
    try:
        response = requests.post(
            THREAT_FOX_URL,
            json={"query": "search_ioc", "search_term": ip},
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("query_status") == "ok":
                iocs = data.get("data", [])
                if iocs:
                    result["score"] = max(result["score"], 75)
                    result["malicious"] = True
                    result["threat_type"] = iocs[0].get("threat_type", "unknown")
                    result["malware"] = iocs[0].get("malware", "unknown")
                    result["source"] = "threatfox"
    except:
        pass

    cache[cache_key] = {
        "data": result,
        "cached_at": datetime.now().isoformat()
    }
    save_cache(cache)
    return result

def check_username_threat(username):
    if not username:
        return {"score": 0, "suspicious": False}

    result = {"username": username, "score": 0, "suspicious": False, "flags": []}

    username_lower = username.lower()

    if username_lower in KNOWN_BAD_USERNAMES:
        result["score"] += 30
        result["suspicious"] = True
        result["flags"].append("Known high-risk username")

    for pattern_name, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if pattern in username_lower:
                result["score"] += 20
                result["suspicious"] = True
                result["flags"].append(f"Matches {pattern_name} pattern")
                break

    return result

def enrich_event(event):
    ip = event.get("source_ip", "unknown")
    username = event.get("username", "unknown")

    ip_intel = check_ip_reputation(ip)
    username_intel = check_username_threat(username)

    enrichment = {
        "ip_reputation": ip_intel,
        "username_intel": username_intel,
        "threat_score": ip_intel.get("score", 0) + username_intel.get("score", 0),
        "indicators": []
    }

    if ip_intel.get("malicious"):
        enrichment["indicators"].append(f"Malicious IP: {ip} (score: {ip_intel.get('score')})")
    if ip_intel.get("country"):
        enrichment["indicators"].append(f"Origin country: {ip_intel.get('country')}")
    if ip_intel.get("malware"):
        enrichment["indicators"].append(f"Associated malware: {ip_intel.get('malware')}")
    if username_intel.get("suspicious"):
        enrichment["indicators"].extend(username_intel.get("flags", []))

    return enrichment

def get_cache_stats():
    cache = load_cache()
    return {
        "total_cached": len(cache),
        "ips_checked": len([k for k in cache.keys() if k.startswith("ip_")])
    }
