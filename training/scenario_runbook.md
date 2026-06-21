# Scenario Runbook - PUC2 Sub Case 2c (instructor)

End-to-end execution mapping each of the 13 UML steps to a concrete action and the
resource that supports it.

| # | UML step | Trainee action | Resource / file |
|---|----------|----------------|-----------------|
| 1 | Initiate malware scenario | NG-SOC Operator runs the kickoff | `mail-attacker:/opt/malware-injection/inject_scenario.sh` |
| 2 | Inject phishing + payload | Script delivers payload to endpoints | role `malware_injection` (payload server + phishing_email.eml) |
| 3 | Telemetry (file hash) | Wazuh agent ships FIM events | role `lab_endpoint` → NG-SIEM |
| 4 | Enrich hash with CTI | SIEM matches IOC list / MISP | role `ng_siem` (`cti_integration`) + role `cti_ss` |
| 5 | Alert: malware detected | NG-SIEM rule 100101/100103 alerts analyst | `ng_siem/files/local_rules.xml` |
| 6 | Correlate logs + confirm | Analyst correlates on dashboard | `training/ng_siem_correlation_guide.md` |
| 7 | Open case + attach SIEM context | NG-SOC Operator opens CICMS case | role `cicms` (`case_template_puc2.json`, `open_case.sh`) |
| 8 | Enrich with CTI (IOCs/TTPs) | IRIS pulls from MISP | role `cicms` (`misp_integration.conf`) ↔ role `cti_ss` |
| 9 | Execute containment playbooks | SOC Analyst triggers NG-SOAR | role `ng_soar` (`run_containment.sh`) |
| 10 | Apply isolation + remediation | SOAR acts on endpoints | `isolate_host.yml`, `block_malicious_ip.yml`, `reset_credentials.yml`, `quarantine_and_patch.yml` |
| 11 | Containment/eradication status | SOAR reports back | `run_containment.sh` output + `/var/run/ngsoar_*` markers |
| 12 | Share malware intel | CTI Specialist publishes to MISP | role `cti_ss` (`load_cti.sh`, sharing group) |
| 13 | Training summary + feedback | Cyber Range debrief | role `evaluation_reporting` (`collect_evaluation.sh`, lessons-learned template) |

## Quick run order
```
# Step 1-2 (on mail-attacker)
/opt/malware-injection/inject_scenario.sh

# Steps 3-6: work the NG-SIEM dashboard (see correlation guide)

# Steps 7-8 (on soc-services)
/opt/cicms-assets/open_case.sh

# Steps 9-11 (on soc-services) - contain the affected endpoint
/opt/NG-SOAR/playbooks/run_containment.sh 10.10.20.11

# Step 12 (on soc-services)
/opt/cti-ss-seed/load_cti.sh

# Step 13 (on ng-siem)
/opt/evaluation/collect_evaluation.sh
```
