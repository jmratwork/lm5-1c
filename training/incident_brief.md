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
| System | Component | Access |
|--------|-----------|--------|
| NG-SIEM | Wazuh dashboard | https://10.10.10.20 |
| CTI-SS | MISP | https://10.10.10.10:8443 |
| CICMS | DFIR-IRIS | https://10.10.10.10 |
| NG-SOAR | Shuffle | http://10.10.10.10:5000 |
| Endpoints | endpoint-1/2 | 10.10.20.11 / 10.10.20.12 |
| Attacker | mail-attacker | 10.10.30.10 |

### Known IOCs (provided to CTI Specialist mid-exercise)
- MD5 `44d88612fea8a8f36de82e1278abb02f`
- Domain `c2.puc2-training.lab`
- C2/host `10.10.30.10`
- Phishing sender `billing@puc2-training.lab`

### Safety note
The "payload" (`invoice.exe`) is an **EICAR-equivalent benign test artifact**.
No real malware is present anywhere in this sandbox.
