# Scenario Runbook - PUC2 Sub Case 2c (instructor)

End-to-end execution mapping each of the 13 UML steps to a concrete action, the
host it happens on, and the resource that supports it.

| # | UML step | Trainee action | Host | Resource / file |
|---|----------|----------------|------|-----------------|
| 1 | Initiate malware scenario | NG-SOC Operator runs the kickoff | Cyber Range → `victim` | `--tags puc2-inject` or `/opt/puc2/inject_scenario.sh` |
| 2 | Inject phishing + payload | Cyber Range injects directly on the endpoint | Cyber Range → `victim` | role `scenario_injection_2c` (4-stage EICAR delivery + `phishing_email.eml`) |
| 3 | Telemetry (file hash) | Wazuh agent ships FIM events | `victim` 10.0.16.100 | role `lab_endpoint_2c` (FIM on `~victim/Downloads` and `/tmp`) → NG-SIEM |
| 4 | Enrich hash with CTI | SIEM matches the CDB IOC list; MISP holds the same IOCs | `ng-siem` ↔ `docker-server` | `ng_siem_rules_2c` (`etc/lists/cti-malware-hashes`) + `cti_ss_2c` + the substrate MISP integration |
| 5 | Alert: malware detected | NG-SIEM rule 100101 alerts the analyst | `ng-siem` 10.0.16.70 | `ng_siem_rules_2c/templates/local_rules.xml.j2`, deployed as `/var/ossec/ruleset/rules/9999-puc2-2c.xml` |
| 6 | Correlate logs + confirm | Analyst correlates FIM + firewall drops; 100102 and 100103 confirm | `ng-siem` | endpoint `kern.log` → built-in firewall decoding → rule `100102` + `training/ng_siem_correlation_guide.md` |
| 7 | Open case + attach SIEM context | Auto-created on alert; the NG-SOC Operator also opens one explicitly | `docker-server` 10.0.16.60 | substrate `custom-iris` + `/opt/cicms-assets/open_case.sh` |
| 8 | Enrich with CTI (IOCs/TTPs) | IRIS pulls from MISP | `docker-server` | `cicms_2c` ↔ `cti_ss_2c`; IRIS MISP module wired by the substrate |
| 9 | Execute containment playbooks | Rule 100103 (correlated confirmation) fires the AR; the NG-SOAR Operator can also drive the webhook | `ng-siem` / `docker-server` | `<active-response>` + `/opt/NG-SOAR/playbooks/ngsoar_trigger.sh` |
| 10 | Apply isolation + remediation | AR script contains the endpoint | `victim` | `lab_endpoint_2c/templates/puc2-isolate.j2`; library in `soar_actions_2c/files/*.yml` |
| 11 | Containment/eradication status | Analyst reads the status markers | `victim` | `/var/run/ngsoar_isolated`, `/var/run/ngsoar_eradication_status`, `active-responses.log` |
| 12 | Share malware intel | CTI Specialist publishes to the sharing group | `docker-server` | `/opt/cti-ss-seed/share_intel.sh` + the playbook library |
| 13 | Training summary + feedback | Cyber Range debrief | `ng-siem` | `evaluation_reporting` (`collect_evaluation.sh`, lessons-learned template) |

## Quick run order

The range starts clean. Provisioning already fired this chain once, in the
rehearsal, and removed every trace: no PUC2 alert in `alerts.log` or the
dashboard, no PUC2 case in DFIR-IRIS, no markers, empty quarantine. The run below
is the first to create any of them.

```bash
# Steps 1-2 — the Cyber Range injects into the endpoint.
# Provisioning stages the scenario but never fires it:
ansible-playbook provisioning/playbook.yml --tags puc2-inject --limit victim
# (or, on the endpoint itself: sudo /opt/puc2/inject_scenario.sh)

# Steps 3-6 — on ng-siem: work the dashboard, watch the chain fire
tail -f /var/ossec/logs/alerts/alerts.json | grep -E '1001(00|01|02|03)'

# Step 7 — on docker-server. The case is created automatically by the
# custom-iris integration; the NG-SOC Operator ALSO has an explicit action:
sudo /opt/cicms-assets/open_case.sh "SIEM context: rules 100101/100103, agent victim"
#   https://10.0.16.60:8083     (DFIR-IRIS, case template "PUC2-2C-Malware")

# Step 8 — enrich the case from CTI-SS:
#   https://10.0.16.60:8443     (MISP, for the IOC lookup)

# Step 9 — containment fires AUTOMATICALLY via the Wazuh active response.
# The NG-SOAR Operator can also drive the real orchestration webhook:
sudo /opt/NG-SOAR/playbooks/ngsoar_trigger.sh isolate_host 10.0.16.100

# Steps 10-11 — verify on victim (10.0.16.100):
cat /var/run/ngsoar_isolated /var/run/ngsoar_eradication_status
sudo iptables -L -n
ping -c2 -W2 10.0.16.50   # must FAIL    (C2 blocked by containment)
ping -c2 -W2 10.0.16.70   # must SUCCEED (NG-SIEM stays reachable)
tail /var/log/puc2-security-updates.log        # detached patch run

# Step 12 — on docker-server: the CTI Specialist publishes the event into the
# sharing group, together with the relevant playbooks:
sudo /opt/cti-ss-seed/share_intel.sh

# Step 13 — on ng-siem
/opt/evaluation/collect_evaluation.sh
```

## Resetting between runs

**A fresh sandbox per cohort is the reliable reset**: every deploy re-proves the
range and hands it over clean. To reuse one, a run leaves traces in four places,
and all four have to go — a PUC2 case left in DFIR-IRIS both gives the next
trainee the L10 answer and stops custom-iris from opening their own case, because
it deduplicates on a SOC id that is the same every run.

```bash
# On victim — lift containment and clear the payload. --lift resets the iptables
# policies, removes the C2 DROP and SSH rules and both markers, and drops the C2
# lines from /etc/hosts. Never `iptables -F`: it takes out the egress filter and
# rules other roles own.
sudo /var/ossec/active-response/bin/puc2-isolate --lift
echo "10.0.16.50 c2.puc2-training.lab" | sudo tee -a /etc/hosts   # the observable sinkhole --arm checks
sudo rm -rf /var/quarantine/* /home/victim/Downloads/*.exe /tmp/invoice.exe
sudo chage -d "$(date +%F)" victim          # containment expired the password
sudo systemctl restart puc2-fw-baseline     # re-arm the egress filter that feeds rule 100102

# On ng-siem — the console path of L10, and the dashboard's indexer:
sudo truncate -s 0 /var/ossec/logs/alerts/alerts.log   # Filebeat reads alerts.json, not this file
sudo curl -sk --cert /etc/wazuh-indexer/certs/admin.pem --key /etc/wazuh-indexer/certs/admin-key.pem \
  -H 'Content-Type: application/json' \
  -X POST 'https://127.0.0.1:9200/wazuh-alerts-*/_delete_by_query?conflicts=proceed&refresh=true' \
  -d '{ "query": { "terms": { "rule.id": [ "100100", "100101", "100102", "100103" ] } } }'

# In DFIR-IRIS (https://10.0.16.60:8083): delete every case whose SOC id starts
# with WAZUH-10010. Keep CASE-PUC2-2C, the scenario case L14 grades.

# Then, from the controller, let the gate confirm the range is clean again:
ansible-playbook provisioning/playbook.yml --tags puc2-preflight
```
