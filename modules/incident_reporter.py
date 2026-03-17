
import os
from datetime import datetime

REPORT_DIR = r"C:\AI\sentinel\reports"

def generate_incident_report(risk):

    score = risk.get("risk_score",0)

    if score < 100:
        return

    if not os.path.exists(REPORT_DIR):
        os.makedirs(REPORT_DIR)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    filename = f"incident_{timestamp}.txt"

    filepath = os.path.join(REPORT_DIR, filename)

    report = []
    report.append("SENTINEL INCIDENT REPORT")
    report.append("-------------------------")
    report.append(f"Time: {datetime.now()}")
    report.append(f"User: {risk.get('username')}")
    report.append(f"Origin: {risk.get('origin')}")
    report.append("")

    report.append(f"Risk Score: {risk.get('risk_score')}")
    report.append("")
    report.append("Detection Reasons:")

    for r in risk.get("reasons",[]):
        report.append(f"- {r}")

    report.append("")
    report.append("Sentinel automated response executed.")

    with open(filepath,"w") as f:
        f.write("\n".join(report))

    print("INCIDENT REPORT GENERATED")
    print("Report saved to:", filepath)
