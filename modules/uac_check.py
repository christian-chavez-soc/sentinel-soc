import subprocess

def run():
    try:
        result = subprocess.check_output(
            'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA',
            shell=True,
            text=True
        )

        if "0x1" in result:
            return {
                "name": "UAC Check",
                "status": "PASS",
                "risk": 0,
                "details": "UAC is ENABLED"
            }
        else:
            return {
                "name": "UAC Check",
                "status": "FAIL",
                "risk": 2,
                "details": "UAC is DISABLED"
            }

    except Exception as e:
        return {
            "name": "UAC Check",
            "status": "ERROR",
            "risk": 1,
            "details": str(e)
        }
