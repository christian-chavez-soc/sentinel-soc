import subprocess

def run_check():
    findings = []
    risk = 0

    try:
        # Check if user is local administrator
        groups = subprocess.check_output("whoami /groups", shell=True, text=True)
        if "BUILTIN\\Administrators" in groups:
            findings.append("User is member of Local Administrators")
            risk += 2

        # Check privileges
        privileges = subprocess.check_output("whoami /priv", shell=True, text=True)

        if "SeDebugPrivilege" in privileges and "Enabled" in privileges:
            findings.append("SeDebugPrivilege is ENABLED (process injection risk)")
            risk += 2

        if "SeImpersonatePrivilege" in privileges and "Enabled" in privileges:
            findings.append("SeImpersonatePrivilege is ENABLED (token abuse risk)")
            risk += 2

        if findings:
            status = "WARNING"
            details = "\n".join(findings)
        else:
            status = "PASS"
            details = "No high-risk privilege exposures detected."

        return {
            "title": "Privilege Exposure Check",
            "status": status,
            "details": details,
            "risk": risk
        }

    except Exception as e:
        return {
            "title": "Privilege Exposure Check",
            "status": "ERROR",
            "details": str(e),
            "risk": 1
        }
