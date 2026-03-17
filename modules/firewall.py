import subprocess

def check_firewall():
    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles"],
            capture_output=True,
            text=True
        )

        output = result.stdout

        firewall_on = "State                                 ON" in output

        return {
            "name": "Firewall Check",
            "status": firewall_on,
            "details": "Firewall is ENABLED" if firewall_on else "Firewall is DISABLED"
        }

    except Exception as e:
        return {
            "name": "Firewall Check",
            "status": False,
            "details": f"Error: {str(e)}"
        }
