# Scenario Runbook - PUC2 Sub Case 2c (instructor)

End-to-end execution mapping each of the 13 UML steps to a concrete action, the
host it happens on, and the resource that supports it.

| # | UML step | Trainee action | Host | Resource / file |
|---|----------|----------------|------|-----------------|
| 1 | Initiate malware scenario | NG-SOC Operator runs the kickoff | `kali` 10.0.16.50 | `/opt/malware-injection/inject_scenario.sh` |
| 2 | Inject phishing + payload | Script delivers the payload to the endpoint | `kali` → `victim` | role `malware_injection_2c` (payload server `:8000` + `phishing_email.eml`) |
| 3 | Telemetry (file hash) | Wazuh agent ships FIM events | `victim` 10.0.16.100 | role `lab_endpoint_2c` (FIM on `~victim/Downloads`) → NG-SIEM |
| 4 | Enrich hash with CTI | SIEM matches the CDB IOC list; MISP holds the same IOCs | `ng-siem` ↔ `docker-server` | `ng_siem_rules_2c` (`etc/lists/cti-malware-hashes`) + `cti_ss_2c` + the substrate MISP integration |
| 5 | Alert: malware detected | NG-SIEM rule 100101 alerts the analyst | `ng-siem` 10.0.16.70 | `ng_siem_rules_2c/files/local_rules.xml` |
| 6 | Correlate logs + confirm | Analyst correlates on the dashboard; rule 100103 confirms | `ng-siem` | `training/ng_siem_correlation_guide.md` |
| 7 | Open case + attach SIEM context | Case is created automatically on alert (dedup by `case_soc_id`) | `docker-server` 10.0.16.60 | substrate `custom-iris` integration + `cicms_2c` case template |
| 8 | Enrich with CTI (IOCs/TTPs) | IRIS pulls from MISP | `docker-server` | `cicms_2c` ↔ `cti_ss_2c`; IRIS MISP module wired by the substrate |
| 9 | Execute containment playbooks | Rules 100101/100103 fire the active response | `ng-siem` | `<active-response>` injected by `ng_siem_rules_2c` |
| 10 | Apply isolation + remediation | AR script contains the endpoint | `victim` | `lab_endpoint_2c/templates/puc2-isolate.j2`; library in `soar_actions_2c/files/*.yml` |
| 11 | Containment/eradication status | Analyst reads the status markers | `victim` | `/var/run/ngsoar_isolated`, `/var/run/ngsoar_eradication_status`, `active-responses.log` |
| 12 | Share malware intel | CTI Specialist publishes to the sharing group | `docker-server` | `cti_ss_2c` (`PUC2-CYNET-Training`) + the playbook library |
| 13 | Training summary + feedback | Cyber Range debrief | `ng-siem` | `evaluation_reporting` (`collect_evaluation.sh`, lessons-learned template) |

## Quick run order

```bash
# Steps 1-2 — on kali (10.0.16.50)
sudo /opt/malware-injection/inject_scenario.sh

# Steps 3-6 — on ng-siem: work the dashboard, watch the chain fire
tail -f /var/ossec/logs/alerts/alerts.json | grep -E '1001(00|01|02|03)'

# Steps 7-8 — on docker-server: the case is created automatically by the
# custom-iris integration. Open DFIR-IRIS and enrich it:
#   https://10.0.16.60:8083     (case template "PUC2-2C-Malware")
#   https://10.0.16.60:8443     (MISP, for the IOC lookup)

# Steps 9-11 — containment is AUTOMATIC via the Wazuh active response.
# Verify on victim (10.0.16.100):
cat /var/run/ngsoar_isolated /var/run/ngsoar_eradication_status
sudo iptables -L -n
curl -m5 http://10.0.16.50:8000/invoice.exe   # must FAIL (C2 blocked)
ping -c2 10.0.16.70                            # must SUCCEED (SIEM reachable)

# Step 12 — on docker-server: publish the event to the sharing group in MISP.
# The seed event and the playbook library are already on disk:
#   /opt/cti-ss-seed/misp_event_puc2_malware.json
#   /opt/NG-SOAR/playbooks/

# Step 13 — on ng-siem
/opt/evaluation/collect_evaluation.sh
```

## Resetting between runs

```bash
# On victim — lift containment and clear the payload:
sudo iptables -P INPUT ACCEPT; sudo iptables -P OUTPUT ACCEPT; sudo iptables -F
sudo rm -f /var/run/ngsoar_isolated /var/run/ngsoar_eradication_status
sudo rm -rf /var/quarantine/* /home/victim/Downloads/invoice.exe
sudo sed -i '/c2.puc2-training.lab/d' /etc/hosts
sudo systemctl restart wazuh-agent
```
