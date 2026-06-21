# PUC2 (CYNET) – Sub Case 2c: Malware Attack Detection & Response Training

A **CyberRangeCZ Sandbox Definition** implementing the full training scenario
*Malware Attack Detection & Response*. It satisfies the 13-step UML sequence and
the 6.3.2.3 functional description: a phishing-delivered malware attack is
detected by NG-SIEM, triaged and case-managed in CICMS with CTI-SS enrichment,
contained automatically by NG-SOAR, and debriefed by the cyber range.

## Topology

```
                          internet-connection (WAN 100.100.100.0/24)
        ┌───────────────┬──────────────────────────┬────────────────┐
   soc-router       endpoint-router            attacker-router
        │                  │                          │
  soc-net 10.10.10.0/24   endpoint-net 10.10.20.0/24  attacker-net 10.10.30.0/24
   ├ soc-services .10       ├ endpoint-1 .11           └ mail-attacker .10
   │  (NG-SOAR/MISP/IRIS)    └ endpoint-2 .12              (phishing + payload)
   └ ng-siem .20 (Wazuh)
```

Endpoints sit on a **separate network** from the SOC stack so that the NG-SOAR
isolation action (UML step 10) is observable and verifiable.

| Host | Role | Image / flavor |
|------|------|----------------|
| soc-services | NG-SOAR + MISP (CTI-SS) + DFIR-IRIS (CICMS) | ubuntu-noble / standard.large |
| ng-siem | NG-SIEM = Wazuh (gap-fill) | ubuntu-noble / standard.large |
| endpoint-1/2 | Lab Hosts/Endpoints (victims, telemetry) | ubuntu-noble / medium·small |
| mail-attacker | Phishing + payload delivery origin | debian-12 / standard.small |

## Component → resource mapping

| UML component | Provided by | Status |
|---------------|-------------|--------|
| Lab Hosts/Endpoints | `endpoint-1`, `endpoint-2` + role `lab_endpoint` | new |
| NG-SIEM | Wazuh via role `ng_siem` | **new (gap-fill)** |
| CTI-SS | MISP via role `docker_server` + `cti_ss` | reused pattern |
| CICMS | DFIR-IRIS via role `docker_server` + `cicms` | reused pattern |
| NG-SOAR | Shuffle via role `docker_server` + `ng_soar` | reused pattern |
| Phishing/payload injection | role `malware_injection` (mail-attacker) | new (simulated) |

## The 13 UML steps → resources

| # | Step | Covered by |
|---|------|-----------|
| 1 | Initiate malware scenario | `malware_injection/inject_scenario.sh` |
| 2 | Inject phishing + payload | role `malware_injection` (payload server + `phishing_email.eml`) |
| 3 | Telemetry (file hash) | role `lab_endpoint` (Wazuh agent + FIM) → NG-SIEM |
| 4 | Enrich hash with CTI | role `ng_siem` CTI integration + role `cti_ss` (MISP) |
| 5 | Alert: malware detected | `ng_siem/files/local_rules.xml` (rules 100101/100103) |
| 6 | Correlate logs + confirm | `training/ng_siem_correlation_guide.md` |
| 7 | Open case + attach SIEM context | role `cicms` (`case_template_puc2.json`, `open_case.sh`) |
| 8 | Enrich with CTI (IOCs/TTPs) | role `cicms` ↔ role `cti_ss` (IRIS↔MISP) |
| 9 | Execute containment playbooks | role `ng_soar` (`run_containment.sh`) |
| 10 | Apply isolation + remediation | `isolate_host.yml`, `block_malicious_ip.yml`, `reset_credentials.yml`, `quarantine_and_patch.yml` |
| 11 | Containment/eradication status | `run_containment.sh` output + `/var/run/ngsoar_*` markers |
| 12 | Share malware intel | role `cti_ss` (`load_cti.sh` + sharing group) |
| 13 | Training summary + feedback | role `evaluation_reporting` |

A per-step quick-run order is in [training/scenario_runbook.md](training/scenario_runbook.md).

## Repository layout

```
/topology.yml                       # REQUIRED at root - sandbox topology
/provisioning/
  playbook.yml                      # orchestrates all roles by group
  requirements.yml                  # Galaxy collections
  group_vars/all.yml                # non-secret globals
  group_vars/vault.yml.example      # template for vault-encrypted secrets
  roles/
    common/                         # base packages, rsyslog
    docker_server/                  # Docker engine + NG-SOAR/MISP/DFIR-IRIS  (NG-SOC pattern)
    ng_siem/                        # Wazuh deployment (gap-fill)
    cti_ss/                         # MISP sharing/enrichment config
    cicms/                          # DFIR-IRIS case mgmt + MISP integration
    ng_soar/                        # containment playbooks
    lab_endpoint/                   # Wazuh agent + telemetry
    malware_injection/              # phishing + payload simulation
    evaluation_reporting/           # post-incident feedback (step 13)
/training/                          # incident brief, correlation guide, runbook
/VALIDATION.md                      # validation results + gap analysis
```

## NG-SIEM decision (gap analysis)

The reference NG-SOC `docker_server` role on branch `central` deploys NG-SOAR,
MISP, RITA, DFIR-IRIS and Portainer **but no SIEM**. A `ng-siem` role exists on
branches `siemng2` / `ng-siem`, but it only manages the *lifecycle/networking of
pre-existing Wazuh containers* — it contains no engine install or compose
bring-up. **Decision:** deploy a full **Wazuh** single-node stack (indexer +
manager + dashboard) in a dedicated `ng_siem` role, reusing the `docker_server`
engine-install tasks and adding the host-resolution/init steps from the reference
`ng-siem` role. Wazuh provides telemetry ingestion (step 3), CTI enrichment via
its MISP integration (step 4), alerting (step 5) and correlation (step 6).

## Deploy & run

1. Push this repo as a CyberRangeCZ Sandbox Definition; the platform builds the
   topology and runs `provisioning/playbook.yml`.
2. Provide secrets via vault: `cp provisioning/group_vars/vault.yml.example
   provisioning/group_vars/vault.yml`, fill it, `ansible-vault encrypt` it.
3. Run the scenario with [training/scenario_runbook.md](training/scenario_runbook.md).

## Secrets management

The reference role hardcoded a password hash, a Docker Hub PAT, SMB credentials
and MISP IPs/keys. **None of those are copied here.** Every credential is an
overridable Ansible variable defaulting to a documented `CHANGE_ME` placeholder,
sourced from an Ansible Vault file that is git-ignored. The repository contains
**no secrets in clear text**. See `provisioning/group_vars/vault.yml.example`.

## Safety

The injected "payload" (`invoice.exe`) is an **EICAR-equivalent benign test
artifact**. No real malware exists anywhere in this sandbox.
