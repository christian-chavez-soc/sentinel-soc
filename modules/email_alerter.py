import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

GMAIL_ADDRESS = "cc83196@gmail.com"
GMAIL_APP_PASSWORD = "fcyxplutwzwhiwmn"
ALERT_RECIPIENT = "cc83196@gmail.com"

last_email_time = {}
EMAIL_COOLDOWN_SECONDS = 60

def should_send_email(key):
    now = datetime.now()
    if key in last_email_time:
        elapsed = (now - last_email_time[key]).total_seconds()
        if elapsed < EMAIL_COOLDOWN_SECONDS:
            return False
    last_email_time[key] = now
    return True

def send_alert_email(risk):
    severity = get_severity(risk.get("risk_score", 0), risk.get("confidence", 0))
    if severity not in ["CRITICAL", "HIGH"]:
        return False

    username = risk.get("username", "unknown")
    origin = risk.get("origin", "unknown")
    score = risk.get("risk_score", 0)
    confidence = risk.get("confidence", 0)
    reasons = risk.get("reasons", [])
    agent = risk.get("agent_host", "local")

    # Cooldown per user to avoid spam
    cooldown_key = f"{username}_{severity}"
    if not should_send_email(cooldown_key):
        print(f"Email cooldown active for {username} - skipping")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SENTINEL {severity}] {username} @ {origin} - Risk: {score}"
        msg["From"] = GMAIL_ADDRESS
        msg["To"] = ALERT_RECIPIENT

        text_body = f"""
SENTINEL SOC ALERT
==================
Severity:   {severity}
User:       {username}
Origin:     {origin}
Agent:      {agent}
Risk Score: {score}
Confidence: {confidence}
Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Detection Reasons:
{chr(10).join(f'  - {r}' for r in reasons)}

Recommended Action:
{'Immediately isolate affected hosts and reset credentials.' if severity == 'CRITICAL' else 'Investigate account activity and review access logs.'}

-- Sentinel SOC Platform
        """

        html_body = f"""
<html>
<body style="background:#0b0f14;color:#00ffcc;font-family:monospace;padding:20px;">
<h2 style="color:{'#ff0000' if severity == 'CRITICAL' else '#ff6600'}">
  SENTINEL {severity} ALERT
</h2>
<table style="border-collapse:collapse;width:100%">
  <tr><td style="padding:8px;color:#ffffff99">Severity</td><td style="padding:8px;color:{'#ff0000' if severity == 'CRITICAL' else '#ff6600'};font-weight:bold">{severity}</td></tr>
  <tr><td style="padding:8px;color:#ffffff99">User</td><td style="padding:8px;color:#00ffcc">{username}</td></tr>
  <tr><td style="padding:8px;color:#ffffff99">Origin</td><td style="padding:8px;color:#00ffcc">{origin}</td></tr>
  <tr><td style="padding:8px;color:#ffffff99">Agent</td><td style="padding:8px;color:#00ffcc">{agent}</td></tr>
  <tr><td style="padding:8px;color:#ffffff99">Risk Score</td><td style="padding:8px;color:{'#ff0000' if score >= 200 else '#ff6600'};font-weight:bold">{score}</td></tr>
  <tr><td style="padding:8px;color:#ffffff99">Confidence</td><td style="padding:8px;color:#00ffcc">{confidence}</td></tr>
  <tr><td style="padding:8px;color:#ffffff99">Time</td><td style="padding:8px;color:#00ffcc">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
</table>
<h3 style="color:#00ffcc99">Detection Reasons</h3>
<ul style="color:#ffffff">
{''.join(f'<li>{r}</li>' for r in reasons)}
</ul>
<h3 style="color:#00ffcc99">Recommended Action</h3>
<p style="color:#ffffff">{'Immediately isolate affected hosts and reset credentials.' if severity == 'CRITICAL' else 'Investigate account activity and review access logs.'}</p>
<hr style="border-color:#00ffcc33"/>
<p style="color:#ffffff44;font-size:11px">Sentinel SOC Platform - Automated Alert</p>
</body>
</html>
        """

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_ADDRESS, ALERT_RECIPIENT, msg.as_string())

        print(f"EMAIL SENT: [{severity}] {username} @ {origin} -> {ALERT_RECIPIENT}")
        return True

    except Exception as e:
        print(f"EMAIL FAILED: {e}")
        return False

def get_severity(score, confidence):
    if score >= 200 or confidence >= 0.8:
        return "CRITICAL"
    if score >= 100 or confidence >= 0.5:
        return "HIGH"
    if score >= 50 or confidence >= 0.3:
        return "MEDIUM"
    if score >= 20 or confidence >= 0.1:
        return "LOW"
    return "INFO"
