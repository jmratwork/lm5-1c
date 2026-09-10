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
vendored here:

| Vendored | What it gives us | Local changes |
|---|---|---|
| `topology.yml` | the tested flat `testnet` 10.0.16.0/24 | none |
| `provisioning/roles/all/` | `/etc/hosts` wiring, sandbox command logging | none of substance |
| `provisioning/roles/docker_server/` | MISP, DFIR-IRIS, NG-SOAR; publishes `misp_api_key`, `iris_api_key`, `docker_server_internal_ip` | **yes** — hardcoded credentials moved to vault, the DFIR-IRIS build no longer depends on a `github.com` clone, unset MISP compose variables pinned, obsolete `version:` key dropped |
| `provisioning/roles/ng-siem/` | the `siemng` image (Wazuh + SPHYNX stack); injects the MISP and `custom-iris` integrations into `ossec.conf` | minor |
| `provisioning/roles/victim/` | Wazuh agent, enrolled against `ng-siem` at install time via `WAZUH_MANAGER` | minor |

This table said "vendored **byte-identical**" long after that stopped being
true — `docker_server` alone carries nine commits. Where the substrate is
modified it is because it had to be (public credentials, an unreachable build
dependency) and the reason is in the commit; the *scenario* itself adds nothing
to these roles.

Sub Case 2c is layered on top as an **additive overlay** of `*_2c` roles that run
*after* them and use their own `blockinfile` markers, so the substrate's
`ossec.conf` integrations are never clobbered.

One substrate promise is worth singling out: `roles/victim` sets
`WAZUH_MANAGER` at package-install time, so the agent enrols itself. Nothing
verified that it had until the preflight gate started asking the *manager* which
agents it holds — an agent that installs, starts and never registers passes
`systemctl is-active` on the endpoint and produces a range where no rule that
depends on FIM telemetry can ever fire.

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

The `kali` **role is deleted**: it installed Caldera and offensive tooling, and
the UML has no attacker host (the Cyber Range injects on the endpoint). The
**`kali` node remains** — `puc2_c2_ip` derives from its address and it is the
candidate analyst workstation.

The `man` role and the substrate's command-logging play are **kept as platform
plumbing, not scenario components**. `man` configures syslog-ng on the
CyberRangeCZ management node so sandbox event logs reach the platform's central
collector (`10.250.232.186:515`), and `sandbox-logging` records the in-sandbox
command trail on `routers` and `hosts`. Both run *after* the overlay, appended at
the tail of `provisioning/playbook.yml` (the substrate's original inline
command-logging play is commented out where it stood); the `hostvars["man"]` test
still selects the forwarding port — 514 when a `man` node is present, else 515.
`man` and `proxy-jump` are **platform-provided nodes, absent from
`topology.yml`**, so a play targeting `man` simply has no hosts when the platform
does not supply it.

So the substrate is **no longer byte-identical**. To see exactly how it differs:

```bash
git clone --depth 1 -b integrations https://github.com/NG-SOC-eu/ng-soc-ansible.git /tmp/subs
for r in all docker_server ng-siem victim; do
  diff -r /tmp/subs/provisioning/roles/$r provisioning/roles/$r
done
diff /tmp/subs/topology.yml topology.yml
```

Expect mostly `when:` lines in `docker_server` and `ng-siem`, plus one
functional deviation in `docker_server`: its DFIR-IRIS step now comments out the
`evtx2splunk` / `iris_evtx` requirement chain before the image build and retries
the build on transient network resets. That chain pulls `splunk-hec` from
`git+https://github.com/...` during `pip3 install`, and the sandbox's git clone
to github.com is reset ("Connection reset by peer"), which failed the
`iris_app`/`worker` build and aborted the whole deployment on this first play.
PUC2 2c does not use the IRIS EVTX import pipeline, so dropping it makes the build
independent of GitHub egress; the retry hardens it against other transient
fetches. Other documented deltas: `provisioning/requirements.yml` merges the
substrate's `sandbox-logging` requirement with the collections its roles need,
and `provisioning/playbook.yml` carries the overlay plays plus the `man`
syslog-ng and command-logging plays at its tail (with the substrate's original
inline command-logging play commented out where it stood).

---

## Topology

Flat, single-subnet testnet — the layout the substrate is tested on:

```
                 router 10.0.16.1
                        │
        ───────── testnet 10.0.16.0/24 ─────────
         │            │            │           │
      kali .50   docker-server .60  ng-siem .70  victim .100
   (analyst      (MISP/IRIS/       (siemng:      (Wazuh agent,
    workstation;  NG-SOAR)          Wazuh+SPHYNX) FIM + AR,
    C2 IOC)                                       injection target)
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
| *(no UML actor)* | `kali` | 10.0.16.50 | analyst workstation — the browser that reaches the four dashboards; its address doubles as the simulated C2 IOC |

**`kali` has no UML lifeline, but it is not idle.** The UML has no attacker host,
so nothing attacks from it and no trainee ever logs into it as an attacker. Two
things do depend on it:

- It is the **analyst workstation**. The dashboards listen on testnet addresses,
  so a browser has to run inside the sandbox, and kali is the only node whose
  image ships a desktop — which is why the access primer (L1) sends every
  trainee there for NG-SIEM, MISP, DFIR-IRIS and NG-SOAR.
- Its address is reused as the **simulated C2 IOC**, the one rule `100102`
  reports a blocked beacon to and `block_malicious_ip` drops.

`puc2_node_access` therefore gives its `debian` user the same known password and
passwordless sudo as the other nodes, and `puc2_preflight` gates it: browser,
graphical session and a live route to all four dashboards. It was described here
as `UNUSED` until the 2026-09-10 build, when nothing in the deployment checked
any of that — the role that would have was tagged `never`.

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

The same script also takes a **manual operator invocation** — `puc2-isolate
--now` (isolate) and `puc2-isolate --lift` (roll back) — which reads no stdin and
runs exactly the automatic containment. It exists as a deterministic console
fallback for the NG-SOAR containment of level L18: the automatic response is the
authoritative path, but a trainee who reaches L19/L21 before it has landed can
run `--now` on `victim` to guarantee the two status markers rather than face a
`cat` on a missing file. It is safe and idempotent, and preserves the same
sandbox-subnet + tcp/22 allow-list as the automatic path.

**Orchestration — NG-SOAR.**
DFIR-IRIS already POSTs to `http://<docker-server>:8080/trigger/playbook` (the
`SOARCA` webhook the substrate's `docker_server` role configures in
`iris_webhooks_module`). The NG-SOAR workflow itself lives in the `NG-SOAR.yml`
compose file copied off the SMB share at build time — **it is deliberately not
reimplemented here**. `soar_actions_2c` only deploys the four playbooks as the
action library that workflow references. Its `ngsoar_trigger.sh` drives that
webhook from `docker-server`; because the webhook path does not itself write the
endpoint markers, on success (and when the webhook is unreachable) it prints the
endpoint-local enforce command (`puc2-isolate --now` on the target) so the
operator can guarantee the L19/L21 markers without cross-node plumbing.

---

## The 13 UML steps → file map

| # | Step | Host | Covered by |
|---|---|---|---|
| 1 | Initiate malware scenario | Cyber Range → victim | `roles/scenario_injection_2c` — fired by `--tags puc2-inject`, never by ordinary provisioning |
| 2 | Inject phishing + payload delivery | Cyber Range → victim | `roles/scenario_injection_2c/templates/inject_scenario.sh.j2` (4-stage EICAR delivery) + `templates/phishing_email.eml.j2` |
| 3 | Telemetry (file hash) | victim → ng-siem | `roles/lab_endpoint_2c/tasks/main.yml` (FIM on `~victim/Downloads`) → rule `100100` |
| 4 | Enrich hash with CTI | ng-siem ↔ docker-server | `roles/ng_siem_rules_2c` (CDB list `etc/lists/cti-malware-hashes`) + `roles/cti_ss_2c` (same IOCs seeded into MISP) + the substrate's MISP integration |
| 5 | Alert: malware detected | ng-siem | `roles/ng_siem_rules_2c/templates/local_rules.xml.j2` rule `100101` (level 12), deployed as `/var/ossec/ruleset/rules/9999-puc2-2c.xml` — **not** `etc/rules/`, which this image does not read |
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
one-clock play            (every node onto UTC, before anything timestamps)
docker-server (facts: misp_api_key, iris_api_key, docker_server_internal_ip)
  → ng-siem (substrate integrations)
    → ng_siem_rules_2c      (rules, CDB list, active-response wiring)
      → lab_endpoint_2c     (FIM + puc2-isolate on the endpoint)
        → scenario_injection_2c  (stages the attack; does NOT fire it)
          → cti_ss_2c / cicms_2c / soar_actions_2c
            → evaluation_reporting
              → puc2_node_access  (trainee login + passwordless sudo)
                → puc2_rehearsal  (fires the chain, verifies it, self-cleans)
                  → puc2_preflight (QA gate; fails the deploy if a level is unanswerable)
```

`provisioning/group_vars/puc2_2c.yml` is the single source of IPs, ports and
IOCs. It is loaded through `vars_files` rather than by name: the substrate
topology declares `groups: []`, so a `group_vars/<group>.yml` file would never
be auto-loaded.

### Deploying

The platform runs `provisioning/playbook.yml` with no extra arguments and that
is the supported path. Two switches are worth knowing:

```bash
# Docker Hub pulls are anonymous unless a PAT is supplied, and anonymous pulls
# are rate-limited. A deploy that dies on "429 Too Many Requests" while pulling
# an image wants this — nothing else does:
ansible-playbook provisioning/playbook.yml \
  -e vault_dockerhub_pat=dckr_pat_... -e vault_dockerhub_user=<user>

# Skip the end-to-end rehearsal (a smoke deploy, or a re-run against a sandbox
# students are already using — it fires the real scenario before cleaning up):
ansible-playbook provisioning/playbook.yml -e puc2_rehearsal_enabled=false
```

Skipping the rehearsal is a clean skip, not a failure, but the range then ships
without runtime proof that rule 100101 alerts, that 100103 correlates, or that
containment writes the markers L19/L21 grade. The log says so explicitly when it
happens. Do not hand a sandbox to students off such a run without re-checking.

#### The Docker Hub limit is the most likely way a deploy dies

`docker-server` is the first play, and a failure there ends the whole job — the
platform does not go on to build the other eleven plays. It pulls six images
from Docker Hub (`mariadb`, `valkey`, `mongo`, `soarca`, `cacao-roaster`,
`rabbitmq`), and the anonymous quota is **per egress IP, shared by every sandbox
on the platform**, so consecutive deploys exhaust it. On 2026-09-10 five images
pulled and the sixth returned 429, taking the deployment with it.

Three things now stand between that and a twenty-minute wasted build:

1. **A preflight.** Before the first pull, the role asks Docker Hub how much
   headroom is left (a HEAD on the probe repository, which does not itself
   consume a pull) and refuses to start a build the quota cannot finish. It
   blocks only on a *measured* shortfall: an unreachable probe, or an account
   whose limit the registry does not publish, proceeds — "could not measure"
   must never read as "empty".
2. **Four of the six images no longer come from Docker Hub at all.** They are
   pulled from registries that do not share its per-IP limit and re-tagged
   under their Docker Hub names, so compose finds them in the local cache:

   | Image | Pulled instead from |
   |---|---|
   | `mariadb:10.11` | `public.ecr.aws/docker/library/…` |
   | `rabbitmq:3.8-management` | `public.ecr.aws/docker/library/…` |
   | `mongo:latest` | `public.ecr.aws/docker/library/…` |
   | `valkey/valkey:7.2` | `ghcr.io/valkey-io/valkey` |

   These are the **same images**, not lookalikes: all four answered HTTP 200 on
   the alternative registry, and the manifest digests match Docker Hub's
   exactly (checked 2026-09-10 for `rabbitmq:3.8-management` and
   `valkey/valkey:7.2`). Re-tagging rather than editing the three upstream
   compose files: those are cloned, unzipped and copied off an SMB share, so an
   edit would have to be re-done every time upstream moves. A tag that later
   moves falls back to Docker Hub and is reported, never fatal.

   Only `cossas/soarca` and `cyentific/cacao-roaster` are left — they publish
   nowhere but Docker Hub. **Two anonymous pulls, not six**, which is why a
   deploy without a PAT now has a real chance of succeeding.
3. **An honest failure when it still happens.** The three compose tasks
   recognise a 429 and say so by name. DFIR-IRIS no longer burns its five
   retries on it: the retry exists for a genuine mid-build network reset, and a
   rate limit whose window is hours is not that — retrying only issued four more
   requests against the limit that was already the problem. It stops after one
   attempt and names the PAT as the fix.

The mirror in (2) was **not** verifiable from the machine this was written on,
which is why it degrades to the old behaviour rather than assuming. The first
deploy to run it will print one `SEEDED` / `MISS` line per image, and that is
the answer.

The last two plays of the file are diagnostics (`puc2_diag`,
`puc2_access_probe`), tagged `never` and absent from a normal deploy:

```bash
ansible-playbook provisioning/playbook.yml --tags puc2_diag --limit docker-server
ansible-playbook provisioning/playbook.yml \
  --tags puc2_access_probe -e puc2_access_probe_enabled=true
```

---

## The deployment proves itself, or it fails

A range that cannot answer its own training must never reach a student. Two
plays enforce that, and both run in every deploy — **no dashboard is glanced at
and no human confirms anything**.

**`puc2_rehearsal` — the runtime proof.** Fires the real scenario and follows
every link:

```
100101 → 100102 → 100103 → active response → markers → quarantine
```

then rolls containment back, restores the sinkhole and the baseline egress
filter, empties the quarantine, removes the markers, un-expires the victim
account, truncates `alerts.log` to its pre-drill size, and re-runs the gate. The
student meets a freshly provisioned range, never an attacked one. A broken link
fails the deploy naming which one (`LINK 3 BROKEN — rule 100103 never
correlated…`) and writes `validation/REHEARSAL_REPORT.md`.

**`puc2_preflight` — the static gate.** Runs last, on `ng-siem`, `victim`,
`docker-server` and `kali`, and fails the play if any graded answer is
unobtainable. `roles/puc2_preflight/README.md` maps each hands-on level to the
check that proves it.

### What the gate can and cannot decide

The two are not redundant. Rules `100100`/`100101` key on syscheck events, which
the FIM daemon raises internally — no log line can synthesise one, so
`wazuh-logtest` can only ever exercise `100102`. That asymmetry is exactly how
the 2026-09-10 build shipped green with the entire detection chain unexercised:
analysisd had only been asked about one of the four rules.

So the gate proves what is *decidable* — the rules are on disk, the CDB
watchlist is compiled, newer than its source and carries the payload hash,
analysisd discarded none of `100100`-`100103`, an endpoint agent is enrolled,
containment is wired to `100103` alone, kali reaches all four dashboards — and
the rehearsal proves what only firing can. Skip the rehearsal and half the proof
goes with it.

### Things a deploy now refuses to do quietly

Each of these shipped green at least once:

| Silent failure | What catches it now |
|---|---|
| The CDB compile step reports success while compiling nothing (`wazuh-makelists` is absent from this image; analysisd is what actually compiles the lists) | the `.cdb` is asserted to exist, be newer than its source list and contain the payload hash — the artefact, not a tool's exit code |
| analysisd silently DISCARDS a rule whose CDB list failed to load | any `WARNING` naming `1001xx` fails the gate |
| The Wazuh agent installs, starts, and never enrols, so no FIM telemetry ever arrives | the manager is asked which agents it holds, not the endpoint whether its service is up |
| `kali` has no browser, no desktop, or no route to the dashboards | asserted per dashboard from kali itself |
| Nodes disagree about the clock (kali ran two hours ahead) | every node is put on UTC before anything timestamps, and asserted |
| A diagnostic reads `ossec.log` without `grep -a` and reports the image's build date as this run's state | `-a` throughout, and startup sections scoped to today |

---

## Running the exercise

Provisioning already fired this whole chain once, in the rehearsal, and undid
it — so the sandbox you are handed is both **proven** and **pristine**: no PUC2
alerts in the manager, no markers, empty quarantine, payload staged but not
delivered. Every step below starts from that state.

```bash
# 1. Provision the sandbox (the platform does this from topology.yml)
# 2. Kick off the scenario — UML steps 1-2. The Cyber Range injects into the
#    endpoint; ordinary provisioning never fires this by itself:
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
`*_linear-training-definition.json`, kept in the repository root **locally
only**: `.gitignore` excludes it, because it is uploaded to the platform by hand
and must never reach the remote. Treat the copy in the root as the single source
of truth and version it in the filename (`V5_…`). `validation/
validate_training.sh` checks that every graded answer in it is actually
obtainable in the built sandbox — matching on API *fields* (for example
`case_soc_id`) rather than on level prose, so rewording a level never breaks it.

---

## Access paths — console and dashboard

**Terminology.** The **GUI** is the CyberRangeCZ web platform. From it
(*Topology* → `Generate console URL`) you attach to a node and get either a
**console** — a command-line terminal in a new window — or a **graphical
desktop**, depending on what that node's image ships and what the tooling needs.
Console and desktop are both reached *through* the GUI; they are not alternatives
to it. `Get SSH Access` is also a platform button; it hands you keys to connect
from your own terminal, so it is another thing the GUI gives you, not a way
around it.

Every hands-on level is answerable **from a console**, so the training never
depends on a graphical desktop being available. The dashboards remain a valid
route where a desktop is present.

**Where the desktop is.** The SOC dashboards live on internal testnet IPs, so a
browser must run *inside* the sandbox. Per `diagnostics/ACCESS-MATRIX.md`, the
only node that can serve as the analyst workstation is **kali (10.0.16.50)** —
which in this scenario also plays the simulated C2. That the C2 address doubles
as the analyst desktop is deliberate and stated in L1.

Whether the kali image actually ships a desktop and a browser is **no longer a
question this repo leaves open**: `puc2_preflight` asserts it on every deploy,
along with a live TCP route from kali to each of the four dashboards, and fails
the deployment if any of it is missing. It used to say here that this was "not
knowable from this repo" and to point at an opt-in probe — which meant the claim
L1 makes to every trainee rested on a check nobody ran.

The probe still exists, as a *diagnostic* rather than a gate: it reports browser,
desktop and per-dashboard HTTP status for **every** node and writes
`diagnostics/ACCESS-PROBE-RESULTS.md`, filling the "CONFIRM IN SANDBOX" cells of
`ACCESS-MATRIX.md`. Use it when you want the whole picture, not a pass/fail:

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
> public in the upstream substrate and the IRIS key is in this repo's history —
> and **this repository is public**. All three must be rotated;
> `validation/SECURITY_ROTATION.md` has the steps.
>
> **Supplying the Docker Hub PAT.** Authenticated pulls are required in practice:
> without them the range hits Docker Hub's anonymous rate limit and the DFIR-IRIS
> images fail to pull with a 429. A local `group_vars/vault.yml` will not do it —
> it is git-ignored, so the sandbox, which deploys by cloning this repo, never
> receives it. Pass it on the deployment command instead:
>
> ```bash
> ansible-playbook provisioning/playbook.yml \
>   -e vault_dockerhub_pat=dckr_pat_NEW... -e vault_dockerhub_user=demongsoc
> ```
