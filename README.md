# Sentinel SOC Platform

A full-stack Security Operations Center platform built from scratch in Python/Flask. Sentinel replicates enterprise SOC capabilities including real-time threat detection, SIEM log analysis, vulnerability scanning, incident response, and proactive threat hunting.

## Modules

| Module | Description |
|--------|-------------|
| SIEM Log Viewer | Real-time event search, filter by severity/type/time, MITRE ATT&CK display, CSV export |
| Vulnerability Scanner | TCP port scan, banner grab, CVE lookup via NIST NVD, CVSS scoring |
| UEBA | Behavioral baseline per user - detects off-hours logins, new IPs, volume spikes |
| IR Playbooks | Auto-generates step-by-step response procedures mapped to MITRE ATT&CK techniques |
| Threat Hunting Console | 7 saved hunt presets, free-text search, multi-field filtering |
| Network Analyzer | Live connection monitoring, anomaly detection, process attribution |
| Geo-IP Attack Map | Real-time attack visualization on world map |
| MITRE ATT&CK Detection | Technique mapping across T1110, T1021, T1190, T1078 and more |
| Threat Intelligence | IOC enrichment and threat scoring per event |
| PDF Report Generator | Automated incident report generation |
| Email Alerter | Critical alert notifications |
| Automated Response Engine | Rule-based containment and response actions |

## Tech Stack

- Backend: Python, Flask, Flask-SocketIO
- Frontend: HTML, CSS, JavaScript
- Data: SQLite, NVD REST API, GeoLite2
- Libraries: psutil, Folium, ReportLab

## Installation

Clone the repo, install dependencies with pip, then run sentinel_dashboard.py and open http://localhost:5000

## Author

Christian Chavez - Cybersecurity Professional | SOC Analyst  
B.S. Cyber Security, Bellevue University
