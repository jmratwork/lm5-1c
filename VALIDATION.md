# Validation Report — PUC2 (CYNET) Sub Case 2c on the `integrations` substrate

## 0. What changed, and why

This sandbox previously invented its own infrastructure: a three-network
topology, a Wazuh stack deployed by compose, an NG-SOAR deployed by compose and
driven over SSH, and its own `docker_server`. **All of that is gone.** The
scenario is now an additive overlay on the tested substrate of
`NG-SOC-eu/ng-soc-ansible@integrations`.

| Previously | Now | Consequence |
|---|---|---|
| `roles/ng_siem` deployed Wazuh (indexer + manager + dashboard) via compose | the `siemng` base box, configured by the substrate `roles/ng-siem` | **no Wazuh is deployed by this repo any more**; the manager runs natively under systemd, not in a container |
| `roles/docker_server` (own MISP/IRIS/NG-SOAR compose) | substrate `roles/docker_server` | MISP `:8443`, IRIS `:8083`, NG-SOAR `:8080` come from the proven role, which also publishes `misp_api_key` / `iris_api_key` / `docker_server_internal_ip` as cacheable facts |
| `roles/ng_soar` ran playbooks over SSH from a compose'd Shuffle | substrate NG-SOAR (`NG-SOAR.yml` from the SMB share) + Wazuh active response | containment is now **live** through the SIEM, and orchestration uses the webhook IRIS already calls |
| `roles/lab_endpoint` installed the Wazuh agent | substrate `roles/victim` | the agent is enrolled once, by the substrate; `lab_endpoint_2c` only adds FIM + the AR script |
| `roles/common` | substrate `roles/all` | superseded |
| `roles/malware_injection` served the payload from a Python `http.server` on an attacker host | overlay `scenario_injection_2c` on `victim` | **the UML has no attacker host**: step 2 originates at the Cyber Range. The HTTP server was a component present in neither the UML nor the substrate, so it was removed; `kali` is provisioned by the substrate but no longer employed by the scenario |
| 3 routed networks, 5 hosts | flat `testnet` 10.0.16.0/24, 4 hosts + router | matches the topology the substrate is tested on |

### Isolation is still verifiable on a flat network

The old design justified three networks by saying isolation would otherwise be
unobservable. That justification does not survive the move to the tested flat
topology, and it is not needed: `puc2-isolate` sets the iptables default
policies to DROP and allow-lists only `10.0.16.0/24`, then inserts an explicit
DROP for the attacker host *ahead* of that allow rule. So after containment the
endpoint can still reach NG-SIEM (the agent keeps reporting, which is what makes
the containment observable at all) but can no longer reach the payload/C2 host
— demonstrable with `iptables -L -n`, a failing `ping` to the C2 address
`10.0.16.50`, and a successful one to NG-SIEM at `10.0.16.70`.

## 1. UML resource availability (13/13 steps covered)

| UML component | Sandbox resource | Provisioning | Reuse vs new |
|---|---|---|---|
| Cyber Range (platform) | CyberRangeCZ itself | n/a | platform |
| Lab Hosts/Endpoints | `victim` 10.0.16.100 | substrate `victim` + overlay `lab_endpoint_2c` | **reused** + thin overlay |
| NG-SIEM | `ng-siem` 10.0.16.70 (`siemng` image) | substrate `ng-siem` + overlay `ng_siem_rules_2c` | **reused** + rules/AR overlay |
| CTI-SS | MISP `:8443` on `docker-server` | substrate `docker_server` + overlay `cti_ss_2c` | **reused** + IOC seeding |
| CICMS | DFIR-IRIS `:8083` on `docker-server` | substrate `docker_server` + overlay `cicms_2c` | **reused** + case template |
| NG-SOAR | webhook `:8080` on `docker-server` | substrate `docker_server`; overlay `soar_actions_2c` supplies the action library only | **reused, not reimplemented** |
| Cyber Range (injection, steps 1-2) | the provisioning layer acting on `victim` | overlay `scenario_injection_2c` | **no new component** |

Per-step file traceability: see the 13-row table in
[README.md](README.md#the-13-uml-steps--file-map). Every step maps to a
concrete file, host and IP; none is left implicit.

## 1b. Live-trigger audit (every step has a working path)

An earlier revision had artefacts for all 13 steps but three of them could
never actually fire. Resolved as follows:

| Finding | Was | Now |
|---|---|---|
| Rule 100103 unreachable — `frequency="2"` over 100101, but the injection delivered the payload once | UML step 6 had no live trigger, and half the active-response trigger set was dead | `inject_scenario.sh` performs a **4-stage delivery** (Downloads → C2 beacon → /tmp staging → second lure), producing three 100101 hits inside the 600 s window |
| Rule 100102 unreachable — keyed on `<if_group>firewall</if_group>`, but nothing emitted firewall logs | the "blocked C2/exfil" branch of step 6 never fired | endpoint carries a **pre-staged iptables LOG+DROP** for tcp/4444 (`puc2-fw-baseline.service`) and `/var/log/kern.log` is ingested via `<localfile>`, so the group is now populated — by Wazuh's own kernel decoder |
| Rule 100102 unreachable *again* — the fix above keyed it on `<decoded_as>puc2-iptables</decoded_as>`, a custom prematch-only decoder | analysisd matches an event carrying a `program_name` (`kernel`) only against decoders that declare one, so the custom decoder was never consulted and 100102 could not fire in the exercise either. The file existed, so every file-based check passed | 100102 keys on the built-in decoding instead; the custom decoder is removed rather than left on disk looking like working detection |
| Rule 100102 unreachable *a third time* — `<if_group>firewall</if_group>` parked it beside rule 4100 rather than beneath it | analysisd matched rule 2, descended into 4100, then into 4100's children, and never revisited the remaining siblings — so 100102 was loaded but never even tried, which the "Rule debugging" block shows by omission | 100102 uses `<if_sid>4100</if_sid>`: an explicit parent that does not depend on how a group name resolves into a position in the rule tree |
| NG-SOAR Operator had no touchpoint | step 9's actor was unrepresented | `ngsoar_trigger.sh` POSTs to the real NG-SOAR webhook the substrate wires |
| NG-SOC Operator had no touchpoint for step 7 | case creation was fully automatic | `open_case.sh` gives the operator an explicit case-opening action alongside the automatic one |
| CTI Specialist had no touchpoint for step 12 | provisioning created the sharing group; nobody published | `share_intel.sh` scopes the event to the sharing group and publishes it |
| "apply security updates" (6.3.2.3) missing from the live path | only present in the playbook library | `puc2-isolate` triggers a **detached** apt security run and records the outcome in the eradication marker (detached because a blocking AR would be killed by the manager) |
| Active response wired to `100101,100103` — 100101 fires on the **first** payload drop, seconds into a delivery that takes ~60 s | containment ran mid-injection: the C2 name was sinkholed to `0.0.0.0` and `OUTPUT` policy set to DROP **before** stage 2 beaconed, so rule 100102 could never fire and UML step 6 lost its firewall evidence; the payload was also quarantined before the analyst could see it | the trigger set is **`100103` only** (`puc2_active_response_rules`). The whole 4-stage delivery completes, 100102 fires on the blocked beacon, and containment follows the *targeted attack confirmed* verdict — the order the UML draws (step 6 → step 9) |
| `puc2-isolate` set `INPUT/OUTPUT` policy DROP allowing only `10.0.16.0/24` | trainees reach `victim` over the CyberRangeCZ **management** interface, which is outside that CIDR: an already-open SSH session survived on the conntrack rule, but every **reconnect** was refused, leaving training levels L20/L22 ("read the containment markers on victim") unanswerable over SSH | the action explicitly preserves the administrative channel (`tcp/{{ puc2_admin_ssh_port }}`, default 22) before flipping the policy, and records `admin_channel=` in the isolation marker. Malware containment is unaffected — the payload does not listen on 22 |

Ruleset loading is no longer assumed: after the restart, `ng_siem_rules_2c`
feeds `wazuh-logtest` the exact kernel line the endpoint's `LOG+DROP` rule
writes and **fails the deployment** unless analysisd answers with rule `100102`
— an answer that requires `local_rules.xml` to be loaded *and* rule 100102 to
key on something the endpoint's log lines actually produce. `puc2_preflight`
re-runs the same probe as a blocking gate, and `validate_training.sh` runs it
over SSH. None of them asks the ruleset to describe itself: `wazuh-logtest`
reports the decoder and rule that matched the line it was given and never lists
what is loaded, so grepping its output for rule ids proves nothing. Nor does
any of them check that a rule or decoder *file* exists — that is what let a
decoder analysisd could never consult pass every check for two rounds.

## 2. Detection capability mapping (BIPS / UEBA / advanced)

Unchanged in substance from the previous report — restated for honesty about
what is real and what is a training stand-in.

| Capability cited in 6.3.2.3 | Mapped to | Status |
|---|---|---|
| BIPS (AI/ML anomaly detection) | Wazuh rule engine + FIM + correlation rule 100103 | **simulated** — rule-based stand-in, not AI/ML |
| UEBA | Wazuh agent behaviour events + correlation | **simulated** (rule-based) |
| Anomaly detection in IT systems | rules 100100–100103 | implemented (signature/correlation) |
| APT detection | multi-stage correlation rule 100103 | partial / simulated |
| Data exfiltration prevention | rule 100102 + the C2 DROP in `puc2-isolate` | implemented |
| Phishing detection | scenario email + FIM rule 100100 | **simulated** — no mail gateway is deployed (not a UML component); the `.eml` is trainee context |
| NG-SOAR file/behaviour/code analysis | NG-SOAR workflow (substrate) + containment library | orchestration implemented; deep file analysis **out of scope** |

Anything marked *simulated / out of scope* is explicitly NOT claimed as a
native AI/ML product.

## 3. Automated checks

| Check | Tool | Result |
|---|---|---|
| Substrate byte-identity (6 roles + `topology.yml`) | `diff -r` against a fresh `integrations` clone | **PASS** — no differences |
| `grep -rn '10\.10\.'` | ripgrep over the whole repo | **PASS** — no matches |
| YAML lint | `yamllint .` | **PASS** — 0 errors. 6 `truthy` warnings remain, all on `become: yes` lines inside the vendored substrate portion of `playbook.yml`, which must stay verbatim |
| YAML parse (all `.yml` + `topology.yml`) | `yaml.safe_load` | **PASS** |
| Role completeness | every role in `playbook.yml` has `tasks/main.yml` | **PASS** (13 roles + `sandbox-logging` from Galaxy) |
| `src:` / `lookup('template')` references | custom script | **PASS** — 10/10 resolve |
| Topology cross-reference | custom script | **PASS** — unique node names, all network refs resolve |
| Payload-hash consistency | runtime assertion in `scenario_injection_2c` | **enforced at provision time** — the run fails if the generated EICAR MD5 diverges from the IOC seeded into MISP and the NG-SIEM CDB list |
| Ansible syntax-check | `ansible-playbook --syntax-check` | **NOT RUN** — Ansible has no Windows control node (`check_blocking_io` → `WinError 87`) |
| `ansible-lint` | `ansible-lint` | **NOT RUN** — same limitation (`No module named 'grp'`) |

Run the two outstanding checks on any Linux node:

```bash
ansible-playbook provisioning/playbook.yml --syntax-check
ansible-lint provisioning/
```

## 4. Manual acceptance procedure (run after provisioning)

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | Substrate intact | `diff -r /tmp/subs/provisioning/roles/ng-siem provisioning/roles/ng-siem` | no output |
| 2 | Overlay did not clobber the integrations | `grep -c 'ANSIBLE MANAGED' /var/ossec/etc/ossec.conf` on `ng-siem` | both the `CYBERRANGE INTEGRATIONS` and the `PUC2-2C DETECTION AND RESPONSE` markers present |
| 3 | Rules loaded | pipe a `PUC2-FW-DROP:` kernel line into `/var/ossec/bin/wazuh-logtest -v` on `ng-siem` | Phase 3 reports `id: '100102'` (not a built-in id such as `4100`) |
| 4 | CDB list compiled | `ls -l /var/ossec/etc/lists/cti-malware-hashes*` | `.cdb` present |
| 5 | AR deployed | `ls -l /var/ossec/active-response/bin/puc2-isolate` on `victim` | `root:wazuh 0750` |
| 6 | CTI seeded | MISP UI → search md5 `44d88612…` | event *PUC2 … Sub Case 2c* present |
| 7 | Steps 1–2 | `ansible-playbook provisioning/playbook.yml --tags puc2-inject --limit victim` | 4-stage delivery; payload lands in `~victim/Downloads` |
| 8 | Steps 3–5 | `grep -c '"id":"100101"' /var/ossec/logs/alerts/alerts.json` on `ng-siem` | **3** hits after a full injection run |
| 8b | Step 6 — firewall branch | `grep '"id":"100102"' /var/ossec/logs/alerts/alerts.json` | present (decoded from the endpoint's blocked C2 beacon) |
| 8c | Step 6 — correlation | `grep '"id":"100103"' /var/ossec/logs/alerts/alerts.json` | present (repeated IOC inside 600 s) |
| 9 | Step 7 | DFIR-IRIS UI `:8083`; then `/opt/cicms-assets/open_case.sh` | auto-created case present and deduped; the operator script opens a second, operator-owned case |
| 9b | Step 9 — operator path | `/opt/NG-SOAR/playbooks/ngsoar_trigger.sh isolate_host` | webhook returns 2xx |
| 10 | Steps 9–11 | `cat /var/run/ngsoar_isolated /var/run/ngsoar_eradication_status` on `victim` | markers present; `status=eradicated`; `security_updates=triggered_background` |
| 11 | Isolation effective | `ping -c2 -W2 10.0.16.50` then `ping -c2 -W2 10.0.16.70` on `victim` | C2 unreachable, NG-SIEM still reachable — the discriminator that proves containment is selective |
| 11b | Endpoint still administrable | **new** SSH session to `victim` after containment | connects — the preserved admin channel is what keeps L20/L22 answerable |
| 11c | Trigger set correct | `grep -A2 '<active-response>' /var/ossec/etc/ossec.conf` on `ng-siem` | `<rules_id>100103</rules_id>` — 100101 must NOT be there |
| 12 | Step 13 | `/opt/evaluation/collect_evaluation.sh` on `ng-siem` | report lists per-rule alert counts and both markers |

## 5. Secrets hygiene

- **This overlay commits no credential.** MISP and DFIR-IRIS API keys are taken
  at runtime from the cacheable facts the substrate `docker_server` role
  publishes; `group_vars/vault.yml` (git-ignored; see `vault.yml.example`) only
  overrides them for standalone runs. `no_log: true` is set on every task that
  renders a key.
- **Inherited exposure — rotation required at the source.** The vendored
  substrate roles contain hardcoded credentials that are public on GitHub: a
  Docker Hub PAT (`dckr_pat_…` in `roles/kali` and `roles/docker_server`), a
  DFIR-IRIS API key (`c-8vTC8nDC…` in `roles/docker_server`), and a password
  hash for the `ubuntu` user in `roles/docker_server` and `roles/victim`.
  They are reproduced here verbatim **on purpose**, because the byte-identity
  guarantee is what makes the substrate reuse auditable. Parameterising them
  here would fork the substrate and hide the problem rather than fix it.
  **Rotate them upstream in `ng-soc-ansible`, then re-vendor.**
