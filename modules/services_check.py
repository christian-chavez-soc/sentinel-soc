import subprocess

def run_check():
    result = {
        "title": "Service Exposure Check",
        "status": "PASS",
        "details": "",
        "risk": 0
    }

    try:
        services = subprocess.check_output(
            ["powershell", "-Command", "Get-Service | Where-Object {$_.Status -eq \"Running\"}"],
            text=True
        )

        risky_keywords = ["remote", "ssh", "telnet", "vnc"]

        findings = []
        for line in services.splitlines():
            for keyword in risky_keywords:
                if keyword.lower() in line.lower():
                    findings.append(line.strip())

        if findings:
            result["status"] = "WARNING"
            result["risk"] = 2
            result["details"] = "Potential remote-related services running:\n" + "\n".join(findings)
        else:
            result["details"] = "No obvious remote-related services detected."

    except Exception as e:
        result["status"] = "ERROR"
        result["details"] = str(e)
        result["risk"] = 1

    return result
