import subprocess

containment_log = []

def contain_threat(risk):
    origin = risk.get("origin", "unknown")
    score = risk.get("risk_score", 0)
    confidence = risk.get("confidence", 0)
    source_ip = risk.get("source_ip", origin)

    if score < 150 and confidence < 0.5:
        return

    print()
    print("NETWORK CONTAINMENT ACTIVATED")
    print(f"Target: {source_ip} | Score: {score}")

    # Block inbound IP
    try:
        rule_name = f"Sentinel_Block_{source_ip}"
        result = subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in", "action=block",
            f"remoteip={source_ip}"
        ], capture_output=True, text=True, shell=True)
        success = result.returncode == 0
        entry = {
            "action": "BLOCK_IP",
            "target": source_ip,
            "success": success,
            "detail": result.stdout.strip() or "Firewall rule created"
        }
        containment_log.append(entry)
        status = "OK" if success else "FAILED"
        print(f"  [{status}] BLOCK_IP -> {source_ip}")
        risk["containment"] = entry
    except Exception as e:
        print(f"  [FAILED] BLOCK_IP -> {source_ip} | {e}")

def get_containment_log():
    return containment_log
