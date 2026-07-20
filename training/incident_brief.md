# Incident Brief - PUC2 (CYNET) Sub Case 2c

## Malware Attack Detection & Response Training

### Scenario
A targeted malware campaign unfolds inside the cyber range. The **NG-SOC Operator**
kicks off the exercise; a phishing email delivers a payload to a Lab Host/Endpoint.
The **BIPS** capability (AI/ML anomaly detection — see VALIDATION.md for its mapping)
flags anomalous activity and NG-SIEM raises an alert for the **SOC Analyst (Cyber
Incident Responder)**. Analysts correlate firewall/AV/host logs in NG-SIEM, open a
case in CICMS enriched from CTI-SS, drive automated containment through NG-SOAR, and
finally share intel and debrief.

### Roles (trainees)
| Role | Responsibility |
|------|----------------|
| NG-SOC Operator | Initiates the scenario, opens the incident case |
| SOC Analyst / Cyber Incident Responder | Correlation, confirmation, drives response |
| NG-SOAR Operator | Executes/monitors automated containment playbooks |
| CTI Specialist | Enriches and shares threat intelligence |

### Systems
| System | Component | Host | Access |
|--------|-----------|------|--------|
| NG-SIEM | Wazuh dashboard (`siemng`) | `ng-siem` | https://10.0.16.70 |
| CTI-SS | MISP | `docker-server` | https://10.0.16.60:8443 |
| CICMS | DFIR-IRIS | `docker-server` | https://10.0.16.60:8083 |
| NG-SOAR | containment webhook | `docker-server` | http://10.0.16.60:8080/trigger/playbook |
| Lab Host/Endpoint | victim workstation | `victim` | 10.0.16.100 |
| Simulated C2 | IOC address only — no component runs there | — | 10.0.16.50 |

### Known IOCs (provided to CTI Specialist mid-exercise)
- MD5 `44d88612fea8a8f36de82e1278abb02f`
- Domain `c2.puc2-training.lab`
- C2/host `10.0.16.50` (beacon target, tcp/4444)
- Phishing sender `billing@puc2-training.lab`

### Safety note
The "payload" (`invoice.exe`) is an **EICAR-equivalent benign test artifact**.
No real malware is present anywhere in this sandbox.
