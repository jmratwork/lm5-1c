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
| `provisioning/roles/docker_server/` | MISP, DFIR-IRIS, NG-SOAR; publishes `misp_api_key`, `iris_api_key`, `docker_server_internal_ip` |
| `provisioning/roles/ng-siem/` | the `siemng` image (Wazuh + SPHYNX stack); injects the MISP and `custom-iris` integrations into `ossec.conf` |
| `provisioning/roles/victim/` | Wazuh agent, already enrolled against `ng-siem` |

Sub Case 2c is layered on top as an **additive overlay** of `*_2c` roles that run
*after* them and use their own `blockinfile` markers, so the substrate's
`ossec.conf` integrations are never clobbered.

### Trimmed to the UML's components

The substrate provisions a broader NG-SOC platform than this sub case uses. The
UML lifelines are Cyber Range, Lab Hosts/Endpoints, NG-SIEM, CTI-SS, CICMS and
NG-SOAR, so **Wazuh, MISP, DFIR-IRIS and NG-SOAR stay and the rest is switched
off** — 43 tasks, by `when:` flag rather than deletion, so the roles stay
re-syncable and any component returns by flipping one value in
`group_vars/puc2_2c.yml`:

| Flag (all `false`) | Component | Tasks |
|---|---|---|
| `puc2_deploy_rita` | RITA network traffic analysis | 7 |
| `puc2_deploy_mcp_servers` | MISP/IRIS MCP bridges for AI agents | 14 |
| `puc2_deploy_sacti` | SACTI + liboqs post-quantum CTI aggregation | 16 |
| `puc2_deploy_anythingllm` | AnythingLLM local LLM chat UI | 4 |
| `puc2_deploy_portainer` | Portainer Docker UI | 1 |
| `puc2_deploy_pandora` | Pandora UI container on `ng-siem` | 1 |

Two tasks inside the MCP block are deliberately **not** gated: those writing
`/etc/misp-mcp.env` and `/etc/iris-mcp.env`, because `puc2_keys` and `puc2_diag`
read the API keys from them. They outlive their namesake; only the servers are
gone, which makes the filenames a misnomer.

The `kali` and `man` **roles are deleted**: kali installed Caldera and offensive
tooling, and the UML has no attacker host (the Cyber Range injects on the
endpoint); `man` configured syslog-ng on a management node. The **`kali` node
remains** — `puc2_c2_ip` derives from its address and it is the candidate
analyst workstation. `man` and `proxy-jump` are **platform-provided nodes, absent
from `topology.yml`**, so they still exist; only our configuration of them is
gone, and the `hostvars["man"]` test that selects the syslog forwarding port is
left intact on purpose.

So the substrate is **no longer byte-identical**. To see exactly how it differs:

```bash
git clone --depth 1 -b integrations https://github.com/NG-SOC-eu/ng-soc-ansible.git /tmp/subs
for r in all docker_server ng-siem victim; do
  diff -r /tmp/subs/provisioning/roles/$r provisioning/roles/$r
done
diff /tmp/subs/topology.yml topology.yml
```

Expect only `when:` lines in `docker_server` and `ng-siem`. Other documented
deltas: `provisioning/requirements.yml` merges the substrate's `sandbox-logging`
requirement with the collections its roles need, and one trailing space was
stripped from `provisioning/playbook.yml` so `yamllint` passes.

---

## Topology

Flat, single-subnet testnet — the layout the substrate is tested on:

```
                 router 10.0.16.1
                        │
        ───────── testnet 10.0.16.0/24 ─────────
         │            │            │           │
      kali .50   docker-server .60  ng-siem .70  victim .100
   (deployed by  (MISP/IRIS/       (siemng:      (Wazuh agent,
    substrate,    NG-SOAR)          Wazuh+SPHYNX) FIM + AR,
    UNUSED)                                       injection target)
```

### UML actor → host mapping

| UML actor | Host | IP | Services |
|---|---|---|---|
| Lab Hosts/Endpoints | `victim` | 10.0.16.100 | Wazuh agent (enrolled by the substrate), FIM, `puc2-isolate` active response |
| NG-SIEM | `ng-siem` | 10.0.16.70 | `siemng` image, Wazuh manager (native systemd), 443 / 9200 |
| CTI-SS | `docker-server` | 10.0.16.60 | MISP `:8443` |
| CICMS | `docker-server` | 10.0.16.60 | DFIR-IRIS `:8083` |
| NG-SOAR | `docker-server` | 10.0.16.60 | webhook `:8080/trigger/playbook` |
| Cyber Range (hands-on platform) | CyberRangeCZ (the provisioning layer) | — | sandbox lifecycle, scenario injection (steps 1-2), evaluation |

`kali` is part of the substrate topology and is provisioned by the substrate
role, but **the scenario does not employ it**: the UML has no attacker host.
Its address is reused as the simulated C2 IOC, and nothing runs there.

Addresses are resolved from the facts the substrate publishes
(`hostvars['ng-siem'].ng_siem_internal_ip`,
`hostvars['docker-server'].docker_server_internal_ip`); the `10.0.16.x`
literals in `provisioning/group_vars/puc2_2c.yml` are only a standalone
fallback.

---

## Containment: what is live, and what is orchestration

This is the single most important thing to understand about the sandbox.

**LIVE and verifiable — Wazuh active response.**
Rule `100103` — the correlated *targeted attack confirmed* rule — on the
`ng-siem` manager executes `/var/ossec/active-response/bin/puc2-isolate` on the
affected endpoint (`location=local`). Only that rule triggers it: `100101` fires
on the very first payload drop, seconds into a delivery that takes about a
minute, so containing there would sinkhole the C2 name before the beacon stage
and rule `100102` could never fire. Containing after confirmation is also the
order the UML draws (step 6 → step 9). That script ports the logic of all four
containment playbooks: iptables isolation that keeps `10.0.16.0/24` reachable so
the agent keeps reporting **and preserves tcp/22 so the endpoint stays
administrable** (the trainee reaches it over the management interface, which is
outside the sandbox CIDR), a DROP on the C2 host plus a `/etc/hosts` blackhole
of the C2 domain, payload quarantine, and credential expiry. It writes
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
| 1 | Initiate malware scenario | Cyber Range → victim | `roles/scenario_injection_2c` — fired by `--tags puc2-inject`, never by ordinary provisioning |
| 2 | Inject phishing + payload delivery | Cyber Range → victim | `roles/scenario_injection_2c/templates/inject_scenario.sh.j2` (4-stage EICAR delivery) + `templates/phishing_email.eml.j2` |
| 3 | Telemetry (file hash) | victim → ng-siem | `roles/lab_endpoint_2c/tasks/main.yml` (FIM on `~victim/Downloads`) → rule `100100` |
| 4 | Enrich hash with CTI | ng-siem ↔ docker-server | `roles/ng_siem_rules_2c` (CDB list `etc/lists/cti-malware-hashes`) + `roles/cti_ss_2c` (same IOCs seeded into MISP) + the substrate's MISP integration |
| 5 | Alert: malware detected | ng-siem | `roles/ng_siem_rules_2c/files/local_rules.xml` rule `100101` (level 12) |
| 6 | Correlate logs + confirm attack pattern | ng-siem | rule `100102` (firewall source: the endpoint's baseline egress filter, decoded by Wazuh's built-in kernel decoder) and rule `100103` (fired by the multi-stage delivery) + `training/ng_siem_correlation_guide.md` |
| 7 | Open incident case + attach SIEM context | ng-siem → docker-server | **automatic:** substrate `custom-iris` integration (dedups by `case_soc_id`); **operator-driven:** `roles/cicms_2c/templates/open_case.sh.j2` + the registered case template |
| 8 | Enrich with CTI (IOCs/TTPs) | docker-server | `roles/cicms_2c` + `roles/cti_ss_2c`; the IRIS↔MISP module is wired by the substrate |
| 9 | Execute containment playbooks | ng-siem / docker-server | **automatic:** `<active-response>` block injected by `roles/ng_siem_rules_2c` (rule `100103` only — see *Containment*); **operator-driven:** `roles/soar_actions_2c/templates/ngsoar_trigger.sh.j2` → the NG-SOAR webhook |
| 10 | Apply isolation and remediation | victim | `roles/lab_endpoint_2c/templates/puc2-isolate.j2` (isolation, C2 block, quarantine, credential reset, security updates); library in `roles/soar_actions_2c/files/*.yml` |
| 11 | Containment and eradication status | victim → analyst | `/var/run/ngsoar_isolated`, `/var/run/ngsoar_eradication_status`, `/var/ossec/logs/active-responses.log`, `/var/log/puc2-security-updates.log` |
| 12 | Share malware intel (+ playbooks) | docker-server | `roles/cti_ss_2c` sharing group `NG-SOC-PUC2` + `templates/share_intel.sh.j2` (CTI Specialist action) + the playbook library |
| 13 | Training summary + feedback | ng-siem | `roles/evaluation_reporting` (`collect_evaluation.sh`, `lessons_learned_template.md`) |

### Component scope rule (read this before proposing an addition)

**The Sub Case 2c scenario employs only the software components that appear in
the UML diagram**, configured as they are configured in the `integrations`
substrate. That set is exactly:

> Cyber Range · Lab Hosts/Endpoints · NG-SIEM · CTI-SS · CICMS · NG-SOAR

The substrate installs a good deal more than that — RITA, SACTI, Caldera,
Metasploit, OpenVAS, the MISP/DFIR-IRIS MCP servers, AnythingLLM, Portainer,
neo4j — and it provisions the whole `kali` host, which the UML does not
contain at all. All of it is deployed, because the substrate roles are vendored verbatim
and are never edited. **None of it is referenced by the scenario, and that is
deliberate, not an oversight.** Wiring any of it in would make the sandbox
diverge from the sequence it is meant to train.

The rule cuts both ways: it forbids reaching for a non-UML component that
happens to be installed, **and** it forbids inventing one. An earlier revision
served the payload from a Python `http.server` on `kali`; that was a software
component present in neither the UML nor the substrate, so it was removed and
step 2 was moved to the Cyber Range, which is where the diagram puts it.

So: an idea of the form *"RITA is already there, we could use it for the
network-traffic analysis the description mentions"* is out of scope by
construction. The correct response to a capability the UML components cannot
provide is to catalogue it as a stand-in in `VALIDATION.md` §2 — not to reach
for a non-UML component that happens to be installed.

Two consequences worth stating plainly:

- **BIPS and UEBA do not exist in the `integrations` substrate.** Searching it
  for `bips`, `ueba`, `behaviour`, `anomaly`, `machine learning` returns
  nothing; the only `ML` matches are `ML-DSA-44` / `ML-KEM-512`, which are
  post-quantum *Module-Lattice* algorithms in SACTI and have no connection to
  machine learning. There is therefore no configuration to reuse for them, and
  the corresponding rows in `VALIDATION.md` §2 stay marked as simulated.
- **The one legitimate avenue not yet exploited is inside NG-SIEM itself.** The
  `siemng` image runs `alerts-correlator`, `backend`, `navigator` (MITRE
  ATT&CK) and `fluentd` alongside Wazuh. Those are NG-SIEM internals, so they
  are in scope — but the substrate role only starts the containers, and what
  they expose is not described anywhere in the repository. Determining that
  requires inspecting a running sandbox.

### Declared deviations from the UML

Two steps are implemented with a different actor than the diagram shows, and
one capability is a training stand-in. These are choices, not oversights:

| UML | Diagram says | Implementation | Why |
|---|---|---|---|
| Step 7 | NG-SOC Operator opens the case | the case is *also* created automatically by `custom-iris` on alert | automatic creation is faster and dedups; `open_case.sh` preserves the operator's explicit action, so both actors have a path |
| Step 9 | NG-SOAR Operator triggers containment | containment *also* fires automatically from the SIEM active response | the automatic path is the one that reliably works in the sandbox; `ngsoar_trigger.sh` drives the real NG-SOAR webhook so the operator exercises orchestration, not a mock |
| 6.3.2.3 | BIPS detects via AI/ML; UEBA; NG-SOAR file/code analysis | Wazuh rule chain + FIM + correlation | no AI/ML component is deployed; this is explicitly a rule-based stand-in, catalogued in `VALIDATION.md` §2 |

Everything else follows the diagram's actor, direction and ordering.

---

## Provisioning order

`provisioning/playbook.yml` runs the substrate plays unchanged, then appends
the overlay in this order:

```
docker-server (facts: misp_api_key, iris_api_key, docker_server_internal_ip)
  → ng-siem (substrate integrations)
    → ng_siem_rules_2c      (rules, CDB list, active-response wiring)
      → lab_endpoint_2c     (FIM + puc2-isolate on the endpoint)
        → scenario_injection_2c  (stages the attack; does NOT fire it)
          → cti_ss_2c / cicms_2c / soar_actions_2c
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
# 2. Kick off the scenario — UML steps 1-2. The Cyber Range injects into the
#    endpoint; provisioning never fires this by itself:
ansible-playbook provisioning/playbook.yml --tags puc2-inject --limit victim
#    (equivalently, on the endpoint: sudo /opt/puc2/inject_scenario.sh)

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

The 30-level linear training definition uploaded to CyberRangeCZ is
`puc2-cynet-2c-malware-detection-response_linear-training-definition.json`, in
the repository root — the single source of truth for it. `validation/
validate_training.sh` checks that every graded answer in it is actually
obtainable in the built sandbox.

---

## Access paths — console and dashboard

**Terminology.** The **GUI** is the CyberRangeCZ web platform. From it
(*Topology* → `Generate console URL`) you attach to a node and get either a
**console** — a command-line terminal in a new window — or a **graphical
desktop**, depending on what that node's image ships and what the tooling needs.
Console and desktop are both reached *through* the GUI; they are not alternatives
to it. Direct SSH (`Get SSH Access`) is a separate route that bypasses the GUI.

Every hands-on level is answerable **from a console**, so the training never
depends on a graphical desktop being available. The dashboards remain a valid
route where a desktop is present.

**Where the desktop is.** The SOC dashboards live on internal testnet IPs, so a
browser must run *inside* the sandbox. Per `diagnostics/ACCESS-MATRIX.md`, the
only node that can serve as the analyst workstation is **kali (10.0.16.50)** —
which in this scenario also plays the simulated C2. That the C2 address doubles
as the analyst desktop is deliberate and stated in L1. Whether the kali image
actually ships a desktop and browser is not knowable from this repo; run the
read-only probe to confirm and fill `diagnostics/ACCESS-PROBE-RESULTS.md`:

```bash
ansible-playbook provisioning/playbook.yml \
  --tags puc2_access_probe -e puc2_access_probe_enabled=true
```

**Credentials.** Dashboard logins are published inside the sandbox, never in this
repo or the training JSON: `sudo cat /opt/puc2/CREDENTIALS.txt` on
**docker-server** (0600, root). Any password not resolvable from the deployed
`.env` is named in that file with where to fetch it, rather than guessed.

**Level → console → dashboard.** All 15 hands-on levels, and the gate that
verifies each is answerable:

| Level | Answer | Console path | Dashboard path | Gated by preflight |
|------|--------|--------------|----------------|--------------------|
| L4  | `puc2-2c-armed` | `inject_scenario.sh --arm` on victim | — | yes |
| L5  | `invoice.exe` | `grep href= /var/mail/victim` | — | yes |
| L8  | payload MD5 | `md5sum /opt/puc2/invoice.exe` | Wazuh FIM | yes |
| L9  | `T1566.001` | **`cti_lookup.sh`** on docker-server | MISP event | yes (console gate) |
| L10 | `100101` | `grep 1001 …/alerts.log` on ng-siem | Wazuh alerts | yes |
| L11 | `targeted` | `grep PUC2-FW-DROP /var/log/kern.log` | Wazuh correlation | yes |
| L14 | `CASE-PUC2-2C` | **`case_lookup.sh`** on docker-server | IRIS cases | yes (console gate) |
| L15 | `c2.puc2-training.lab` | **`cti_lookup.sh`** on docker-server | MISP / IRIS | yes (console gate) |
| L18 | `isolate_host` | `ls /opt/NG-SOAR/playbooks/` | NG-SOAR | yes |
| L19 | `isolated` | `cat /var/run/ngsoar_isolated` | — | yes |
| L20 | `10.0.16.50` | `cti_lookup.sh` (IOC) / firewall log | MISP IOC | yes |
| L21 | `eradicated` | `cat /var/run/ngsoar_eradication_status` | — | yes |
| L24 | `NG-SOC-PUC2` | `share_intel.sh` on docker-server | MISP distribution | yes |
| L25 | `phishing` | `collect_evaluation.sh` on ng-siem | IRIS timeline | yes |
| L26 | `T1204.002` | `cti_lookup.sh` (execution technique) | MISP tag | yes |

The three levels that were dashboard-only — **L9, L14, L15** — gained the
`cti_lookup.sh` / `case_lookup.sh` console helpers (read-only, key never printed;
see Phase 1). `puc2_preflight` fails the deployment if a helper is missing or
stops returning its expected value, or if the credentials file is not present as
0600 root.

---

## Secrets

No credential is committed by this overlay. MISP and DFIR-IRIS API keys are
taken at runtime from the cacheable facts the substrate's `docker_server` role
publishes; `provisioning/group_vars/vault.yml` (git-ignored, see
`vault.yml.example`) only overrides them for standalone runs.

> ⚠️ **Rotation required — inherited from the upstream public repository.**
> The vendored `integrations` roles contain hardcoded credentials that are
> public on GitHub and must be rotated at the source:
> a Docker Hub PAT (`dckr_pat_…`) and a password hash for the `ubuntu` user.
>
> **All three are now out of this tree.** The DFIR-IRIS key was deleted with the
> dead task files that held it; the PAT and the password hash are read from
> `ansible-vault` (`vault_dockerhub_pat`, `vault_ubuntu_password_hash`) and both
> degrade safely when unset — the Docker Hub login is skipped and images pull
> anonymously, and the password task omits the field so the account is left
> alone rather than blanked.
>
> Removing them here does **not** un-publish them: the PAT and the hash are
> public in the upstream substrate and the IRIS key is in this repo's history.
> All three must be rotated — `validation/SECURITY_ROTATION.md` has the steps.
