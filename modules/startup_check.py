import os
import winreg

def run_check():
    findings = []
    risk = 0

    keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ]

    for key_path in keys:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            i = 0
            while True:
                name, value, _ = winreg.EnumValue(key, i)
                findings.append(f"{name} -> {value}")
                i += 1
        except OSError:
            pass

    startup_folder = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
    if os.path.exists(startup_folder):
        for file in os.listdir(startup_folder):
            findings.append(f"Startup Folder Entry -> {file}")

    if findings:
        risk = 2
        status = "WARNING"
        details = "Startup entries detected:\n" + "\n".join(findings)
    else:
        status = "PASS"
        details = "No startup persistence entries found."

    return {
        "title": "Startup Persistence Check",
        "status": status,
        "details": details,
        "risk": risk
    }
