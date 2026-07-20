# PUC2 (CYNET) – Sub Case 2c: Malware Attack Detection & Response Training

A **CyberRangeCZ Sandbox Definition** implementing the training scenario
*Malware Attack Detection & Response*: a phishing-delivered payload is detected
by NG-SIEM, enriched from CTI-SS, case-managed in CICMS, contained
automatically, and debriefed by the cyber range. It satisfies the 13-step UML
sequence and the 6.3.2.3 functional description.

The platform clones **this single repository**: `topology.yml` at the root and
`provisioning/playbook.yml` are the only entry points.

---

## Reuse of the `integrations` substrate

This sandbox is **not** built from scratch. It sits on the proven substrate of
[`NG-SOC-eu/ng-soc-ansible@integrations`](https://github.com/NG-SOC-eu/ng-soc-ansible/tree/integrations),
which is vendored here **byte-identical**:

| Vendored verbatim | What it gives us |
|---|---|
| `topology.yml` | the tested flat `testnet` 10.0.16.0/24 |
| `provisioning/roles/all/` | `/etc/hosts` wiring, sandbox command logging |
| `provisioning/roles/docker_server/` | MISP, DFIR-IRIS, NG-SOAR, RITA, MCP servers, SACTI; publishes `misp_api_key`, `iris_api_key`, `docker_server_internal_ip` |
| `provisioning/roles/ng-siem/` | the `siemng` image (Wazuh + SPHYNX stack); injects the MISP and `custom-iris` integrations into `ossec.conf` |
| `provisioning/roles/kali/` | Caldera, Metasploit, OpenVAS, Docker |
| `provisioning/roles/victim/` | Wazuh agent, already enrolled against `ng-siem` |
| `provisioning/roles/man/` | syslog-ng on the management node |

**These roles are never modified.** Sub Case 2c is layered on top as an
**additive overlay** of `*_2c` roles that run *after* them and use their own
`blockinfile` markers, so the substrate's `ossec.conf` integrations are never
clobbered. Verify with:

```bash
git clone --depth 1 -b integrations https://github.com/NG-SOC-eu/ng-soc-ansible.git /tmp/subs
for r in all docker_server ng-siem kali victim man; do
  diff -r /tmp/subs/provisioning/roles/$r provisioning/roles/$r
done
diff /tmp/subs/topology.yml topology.yml
```

Two documented deltas outside those roles: `provisioning/requirements.yml`
merges the substrate's `sandbox-logging` role requirement with the collections
its roles depend on, and one trailing space was stripped from
`provisioning/playbook.yml` so `yamllint` passes.

---

## Topology

Flat, single-subnet testnet — the layout the substrate is tested on:

```
                 router 10.0.16.1
                        │
        ───────── testnet 10.0.16.0/24 ─────────
         │            │            │           │
      kali .50   docker-server .60  ng-siem .70  victim .100
   (phishing +   (MISP/IRIS/       (siemng:      (Wazuh agent,
    payload)      NG-SOAR)          Wazuh+SPHYNX) FIM + AR)
```

### UML actor → host mapping

| UML actor | Host | IP | Services |
|---|---|---|---|
| Lab Hosts/Endpoints | `victim` | 10.0.16.100 | Wazuh agent (enrolled by the substrate), FIM, `puc2-isolate` active response |
| NG-SIEM | `ng-siem` | 10.0.16.70 | `siemng` image, Wazuh manager (native systemd), 443 / 9200 |
| CTI-SS | `docker-server` | 10.0.16.60 | MISP `:8443` |
| CICMS | `docker-server` | 10.0.16.60 | DFIR-IRIS `:8083` |
| NG-SOAR | `docker-server` | 10.0.16.60 | webhook `:8080/trigger/playbook` |
| Phishing / payload origin | `kali` | 10.0.16.50 | Caldera + payload server `:8000` |
| Cyber Range (hands-on platform) | CyberRangeCZ | — | sandbox lifecycle, evaluation |

Addresses are resolved from the facts the substrate publishes
(`hostvars['ng-siem'].ng_siem_internal_ip`,
`hostvars['docker-server'].docker_server_internal_ip`); the `10.0.16.x`
literals in `provisioning/group_vars/puc2_2c.yml` are only a standalone
fallback.

---

## Containment: what is live, and what is orchestration

This is the single most important thing to understand about the sandbox.

**LIVE and verifiable — Wazuh active response.**
Rules `100101` / `100103` on the `ng-siem` manager execute
`/var/ossec/active-response/bin/puc2-isolate` on the affected endpoint
(`location=local`). That script ports the logic of all four containment
playbooks: iptables isolation that keeps `10.0.16.0/24` reachable so the agent
keeps reporting, a DROP on the C2 host plus a `/etc/hosts` blackhole of the C2
domain, payload quarantine, and credential expiry. It writes
`/var/run/ngsoar_isolated` and `/var/run/ngsoar_eradication_status`, which are
what UML step 11 reports. This path is provisioned end to end by
`ng_siem_rules_2c` + `lab_endpoint_2c`, and it is what `VALIDATION.md` exercises.

**Orchestration — NG-SOAR.**
DFIR-IRIS already POSTs to `http://<docker-server>:8080/trigger/playbook` (the
`SOARCA` webhook the substrate's `docker_server` role configures in
`iris_webhooks_module`). The NG-SOAR workflow itself lives in the `NG-SOAR.yml`
compose file copied off the SMB share at build time — **it is deliberately not
reimplemented here**. `soar_actions_2c` only deploys the four playbooks as the
action library that workflow references.

---

## The 13 UML steps → file map

| # | Step | Host | Covered by |
|---|---|---|---|
| 1 | Initiate malware scenario | kali | `roles/malware_injection_2c/templates/inject_scenario.sh.j2` (run by the instructor, not at provision time) |
| 2 | Inject phishing + payload delivery | kali → victim | `roles/malware_injection_2c/tasks/main.yml` (EICAR payload server `:8000`) + `templates/phishing_email.eml.j2` |
| 3 | Telemetry (file hash) | victim → ng-siem | `roles/lab_endpoint_2c/tasks/main.yml` (FIM on `~victim/Downloads`) → rule `100100` |
| 4 | Enrich hash with CTI | ng-siem ↔ docker-server | `roles/ng_siem_rules_2c` (CDB list `etc/lists/cti-malware-hashes`) + `roles/cti_ss_2c` (same IOCs seeded into MISP) + the substrate's MISP integration |
| 5 | Alert: malware detected | ng-siem | `roles/ng_siem_rules_2c/files/local_rules.xml` rule `100101` (level 12) |
| 6 | Correlate logs + confirm attack pattern | ng-siem | rules `100102` / `100103` + `training/ng_siem_correlation_guide.md` |
| 7 | Open incident case + attach SIEM context | ng-siem → docker-server | substrate `custom-iris` integration (creates the case, dedups by `case_soc_id`) + `roles/cicms_2c` (case template & tasks) |
| 8 | Enrich with CTI (IOCs/TTPs) | docker-server | `roles/cicms_2c` + `roles/cti_ss_2c`; the IRIS↔MISP module is wired by the substrate |
| 9 | Execute containment playbooks | ng-siem | `<active-response>` block injected by `roles/ng_siem_rules_2c` (rules `100101,100103`) — orchestration path: IRIS → NG-SOAR webhook |
| 10 | Apply isolation and remediation | victim | `roles/lab_endpoint_2c/templates/puc2-isolate.j2`; library in `roles/soar_actions_2c/files/*.yml` |
| 11 | Containment and eradication status | victim → analyst | `/var/run/ngsoar_isolated`, `/var/run/ngsoar_eradication_status`, `/var/ossec/logs/active-responses.log` |
| 12 | Share malware intel (+ playbooks) | docker-server | `roles/cti_ss_2c` sharing group `PUC2-CYNET-Training` + `roles/soar_actions_2c` library |
| 13 | Training summary + feedback | ng-siem | `roles/evaluation_reporting` (`collect_evaluation.sh`, `lessons_learned_template.md`) |

---

## Provisioning order

`provisioning/playbook.yml` runs the substrate plays unchanged, then appends
the overlay in this order:

```
docker-server (facts: misp_api_key, iris_api_key, docker_server_internal_ip)
  → ng-siem (substrate integrations)
    → ng_siem_rules_2c      (rules, CDB list, active-response wiring)
      → lab_endpoint_2c     (FIM + puc2-isolate on the endpoint)
        → cti_ss_2c / cicms_2c / soar_actions_2c
          → malware_injection_2c
            → evaluation_reporting
```

`provisioning/group_vars/puc2_2c.yml` is the single source of IPs, ports and
IOCs. It is loaded through `vars_files` rather than by name: the substrate
topology declares `groups: []`, so a `group_vars/<group>.yml` file would never
be auto-loaded.

---

## Running the exercise

```bash
# 1. Provision the sandbox (the platform does this from topology.yml)
# 2. Kick off the scenario — UML steps 1-2, on kali:
sudo /opt/malware-injection/inject_scenario.sh

# 3. Watch the detection chain on ng-siem:
tail -f /var/ossec/logs/alerts/alerts.json | grep -E '1001(00|01|02|03)'

# 4. Confirm containment on victim (UML step 11):
cat /var/run/ngsoar_isolated /var/run/ngsoar_eradication_status
sudo iptables -L -n

# 5. Debrief — UML step 13, on ng-siem:
/opt/evaluation/collect_evaluation.sh
```

See `VALIDATION.md` for the full acceptance procedure and `training/` for the
trainee-facing brief, runbook and correlation guide.

---

## Secrets

No credential is committed by this overlay. MISP and DFIR-IRIS API keys are
taken at runtime from the cacheable facts the substrate's `docker_server` role
publishes; `provisioning/group_vars/vault.yml` (git-ignored, see
`vault.yml.example`) only overrides them for standalone runs.

> ⚠️ **Rotation required — inherited from the upstream public repository.**
> The vendored `integrations` roles contain hardcoded credentials that are
> public on GitHub and must be rotated at the source:
> a Docker Hub PAT (`dckr_pat_…`, in `roles/kali` and `roles/docker_server`),
> a DFIR-IRIS API key (`c-8vTC8nDC…`, in `roles/docker_server`), and a password
> hash for the `ubuntu` user. They are reproduced here **verbatim and
> unmodified on purpose**, because the substrate roles must stay byte-identical
> for the reuse guarantee above to hold. Fix them upstream, not here.
