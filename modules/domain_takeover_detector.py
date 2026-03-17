CRITICAL_DOMAIN_SYSTEMS = ["DC01","DC02"]

def detect_domain_takeover(username, host, risk_score):

    if host in CRITICAL_DOMAIN_SYSTEMS and risk_score > 120:

        print("\n?? CRITICAL ALERT ??")
        print("Possible Domain Takeover Attempt")
        print("User:", username)
        print("Target:", host)
        print("Risk Score:", risk_score)
        print()
