from modules import eventlog_monitor

telemetry = eventlog_monitor.poll_security_events()

print("Telemetry result:")
print(telemetry)
