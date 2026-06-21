# Validation Report — PUC2 (CYNET) Sub Case 2c

## 1. UML resource availability (every component is provided)

| UML component | Sandbox resource | Provisioning | Reuse vs new |
|---------------|------------------|--------------|--------------|
| Cyber Range (platform) | CyberRangeCZ itself | n/a | platform |
| Lab Hosts/Endpoints | `endpoint-1`, `endpoint-2` | role `lab_endpoint` | new |
| NG-SIEM | `ng-siem` (Wazuh) | role `ng_siem` | **new (gap-fill)** |
| CTI-SS | MISP on `soc-services` | roles `docker_server` + `cti_ss` | reused NG-SOC pattern |
| CICMS | DFIR-IRIS on `soc-services` | roles `docker_server` + `cicms` | reused NG-SOC pattern |
| NG-SOAR | Shuffle on `soc-services` | roles `docker_server` + `ng_soar` | reused NG-SOC pattern |
| Phishing/payload injection | `mail-attacker` | role `malware_injection` | new (simulated) |

### Per-step traceability (13/13 covered)
See the table in [README.md](README.md#the-13-uml-steps--resources) and the
[scenario runbook](training/scenario_runbook.md). Every step maps to a concrete
file/role; none are left implicit.

## 2. Reference-pattern reuse confirmed

- **NG-SOAR, MISP (CTI-SS), DFIR-IRIS (CICMS)** are deployed by role
  `docker_server`, replicating the NG-SOC `docker_server` pattern: apt Docker
  Engine install, optional CIFS artifact share, per-app `community.docker.docker_compose_v2`
  bring-up (NG-SOAR copied/templated compose, MISP git-cloned, IRIS deployed),
  plus Portainer. The MISP↔IRIS integration (reference role wired BASE_URL/
  IRIS_MISP_URL) is reproduced via `cicms/misp_integration.conf`.
- **RITA** from the reference role is intentionally omitted (network-traffic
  analysis is represented by NG-SOAR's traffic analysis in the scenario; can be
  re-enabled by adding its compose to `docker_server`).

## 3. NG-SIEM gap analysis (resolved)

- Inspected `NG-SOC-eu/ng-soc-ansible`: branch `central` roles = `all`,
  `docker_server`, `kali`, `victim` → **no SIEM**.
- A `ng-siem` role exists on branches `siemng2` / `ng-siem`, but it only restarts
  pre-existing Wazuh containers and fixes `/etc/hosts` resolution — **no engine
  install, no compose bring-up**.
- **Resolution:** dedicated `ng_siem` role deploys a full **Wazuh** single-node
  stack (indexer + manager + dashboard) via compose, reusing the `docker_server`
  engine install and adding the readiness/host-resolution steps from the
  reference role. Custom correlation rules in `ng_siem/files/local_rules.xml`
  implement steps 5–6.

## 4. Detection capability mapping (BIPS / UEBA / advanced)

| Capability cited in 6.3.2.3 | Mapped to | Status |
|-----------------------------|-----------|--------|
| BIPS (AI/ML anomaly detection) | NG-SIEM (Wazuh) rule engine + FIM + correlation rule 100103 | **simulated** — rule-based stand-in for AI/ML behaviour |
| UEBA | Wazuh agent behaviour events + correlation | **simulated** (rule-based) |
| Anomaly detection in IT systems | Wazuh rules 100100–100103 | implemented (signature/correlation) |
| APT detection | correlation rule 100103 (multi-stage) | partial / simulated |
| Data exfiltration prevention | firewall-drop rule 100102 + NG-SOAR `block_malicious_ip` | implemented |
| Phishing detection | `malware_injection` phishing email + FIM rule 100100 | implemented (scenario) |
| NG-SOAR file/behaviour/code analysis | Shuffle workflows + containment playbooks | implemented (orchestration); deep file analysis **out of scope** |

Anything marked *simulated / out of scope* above is explicitly NOT claimed as a
native AI/ML product — it is a training stand-in driven by Wazuh rules.

## 5. Topology coherence (automated checks — PASS)

Validated with a Python cross-reference script:

```
YAML files parsed OK
TOPOLOGY CROSS-REF: OK        # unique node names, all net/router/group/monitoring refs resolve
CIDRs disjoint: OK            # soc 10.10.10.0/24, endpoint 10.10.20.0/24, attacker 10.10.30.0/24, wan 100.100.100.0/24
```

- Flavors used: `standard.small/medium/large` (all valid).
- Images used: `ubuntu-noble-x86_64`, `debian-12-x86_64` (all valid base boxes).
- Telemetry path (step 3): `endpoint-net` → routed → `soc-net` → `ng-siem` ✓
- Isolation verifiable (step 10): endpoints on a separate network; `isolate_host.yml`
  drops all traffic except `soc-net`, observable from the SOC stack ✓

## 6. Syntax / lint results

| Check | Tool | Result |
|-------|------|--------|
| YAML lint | `yamllint` (config `.yamllint`) | **PASS** — 0 errors, 0 warnings |
| YAML parse (all `.yml`) | `python -c yaml.safe_load_all` | **PASS** |
| Topology cross-reference | custom script | **PASS** |
| CIDR disjointness | `ipaddress` | **PASS** |
| Role completeness | every role in `playbook.yml` has `tasks/main.yml` | **PASS** |
| `src:` file references | every `copy`/`template` src exists in `files/`/`templates/` | **PASS** |
| Ansible syntax-check | `ansible-playbook --syntax-check` | **NOT RUN** — Ansible does not support a Windows control node (`check_blocking_io` → `WinError 87`). Run on the Linux platform node: `ansible-playbook --syntax-check provisioning/playbook.yml`. |
| `ansible-lint` | `ansible-lint` | **NOT RUN** — same Windows control-node limitation. |

> The two Ansible-native checks could not execute on this Windows workstation
> (Ansible is Linux/macOS control-node only). They will run on the CyberRangeCZ
> provisioning node, which is Linux. All platform-independent validations pass.

## 7. Secrets hygiene

- No password hash, Docker Hub PAT, SMB credential, or MISP key from the
  reference role is copied. All are overridable variables defaulting to
  documented `CHANGE_ME`/empty placeholders.
- Real values come from an Ansible Vault file (`group_vars/vault.yml`), which is
  git-ignored. Template provided: `group_vars/vault.yml.example`.
- `no_log: true` is set on tasks that render secrets.
