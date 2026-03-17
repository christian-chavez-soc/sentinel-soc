import subprocess
import re

def run_check():
    findings = []
    risk = 0

    try:
        result = subprocess.check_output("netstat -ano", shell=True, text=True)

        lines = result.splitlines()

        listening_ports = []
        established_external = []

        for line in lines:
            if "LISTENING" in line:
                parts = re.split(r"\s+", line)
                if len(parts) >= 4:
                    local_address = parts[1]
                    port = local_address.split(":")[-1]
                    listening_ports.append(port)

            if "ESTABLISHED" in line:
                parts = re.split(r"\s+", line)
                if len(parts) >= 4:
                    foreign_address = parts[2]
                    if not foreign_address.startswith("127.0.0.1") and not foreign_address.startswith("0.0.0.0"):
                        established_external.append(foreign_address)

        high_risk_ports = {
            "3389": "RDP",
            "445": "SMB",
            "5985": "WinRM",
            "5986": "WinRM HTTPS"
        }

        for port in listening_ports:
            if port in high_risk_ports:
                findings.append(f"{high_risk_ports[port]} exposed on port {port}")
                risk += 2

        if established_external:
            findings.append(f"External connections detected: {len(established_external)} active session(s)")
            risk += 1

        if findings:
            status = "WARNING"
            details = "\n".join(findings)
        else:
            status = "PASS"
            details = "No high-risk network exposures detected."

        return {
            "title": "Network Exposure Check",
            "status": status,
            "details": details,
            "risk": risk
        }

    except Exception as e:
        return {
            "title": "Network Exposure Check",
            "status": "ERROR",
            "details": str(e),
            "risk": 1
        }
