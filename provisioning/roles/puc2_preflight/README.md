# puc2_preflight — the deployment's QA gate

Every graded answer of the 30-level PUC2 2c training definition must be
obtainable in the sandbox the moment provisioning ends. This role proves that,
and **fails the play** when it cannot: a range that cannot answer its own
training never gets handed over.

```bash
# runs automatically at the end of every provisioning run, or on its own:
ansible-playbook provisioning/playbook.yml --tags puc2-preflight
```

Read-only. It arms the scenario — `--arm` is the injection script's read-only
mode — and reads back the live services. It never fires the attack and never
contains the endpoint.

**What this gate can and cannot decide.** It proves statically that every graded
answer is *obtainable*. It cannot prove that a rule *fires*: rules 100100 and
100101 key on syscheck events, which the FIM daemon raises internally and no log
line can synthesise, so `wazuh-logtest` can only ever exercise 100102. The
runtime half — 100101 alerting, 100103 correlating, containment writing the
markers — belongs to `puc2_rehearsal`, which fires the real scenario and
self-cleans immediately before this gate runs. Neither is optional; a build that
skips the rehearsal ships with that half unproven and says so in the log.

Hosts: `ng-siem`, `victim`, `docker-server` **and `kali`** — the analyst
workstation is in the gate because the access primer sends every trainee there
for the four SOC dashboards, and it is the only node whose image ships a desktop.

## Coverage of the 15 hands-on levels

Of the 30 levels, 15 are hands-on and 8 informational + 7 assessment do not
depend on the environment. **No entry below is closed by a human looking at a
dashboard.**

| Level | Answer | Proven by | Where |
|---|---|---|---|
| L1 | (no answer — access primer) | kali has a browser, a graphical session, and a live TCP route to all four dashboards; every node's login user has a set password and passwordless sudo | `kali_access.yml`, `node_access.yml` |
| L4 | `puc2-2c-armed` | token printed by an `--arm` run in which every check passed | `victim.yml` |
| L5 | `invoice.exe` | `--arm` verifies the lure is staged and the mail delivered, **and** the mail really carries an `href=` naming the payload — which is the route the level prescribes | `victim.yml` |
| L8 | `44d88612…abb02f` | hash on the NG-SIEM CDB watchlist **and** on the MISP event | `ng_siem.yml`, `docker_server.yml` |
| L9 | `T1566.001` | tag read back off the live MISP event | `docker_server.yml` |
| L10 | `100101` | rule present in `local_rules.xml`, analysisd reports having discarded none of 100100-100103, the CDB watchlist is compiled fresh and carries the payload hash, and an endpoint agent is enrolled to feed it — **fired for real by `puc2_rehearsal`** | `ng_siem.yml` + rehearsal |
| L11 | `targeted` | derivable from the level text — no environment dependency | — |
| L14 | `CASE-PUC2-2C` | case matched on its `case_soc_id` **field** in DFIR-IRIS | `docker_server.yml` → `cicms_2c/find_case.yml` |
| L15 | `c2.puc2-training.lab` | domain IOC on the live MISP event | `docker_server.yml` |
| L18 | `isolate_host` | playbook present in the NG-SOAR library | `docker_server.yml` |
| L19 | `isolated` | the deployed active response writes it to the marker's first line | `victim.yml` |
| L20 | `10.0.16.50` | the C2 address on the MISP event matches the range's actual C2, **and** the range's C2 is the literal address the level grades | `docker_server.yml`, `training_contract.yml` |
| L21 | `eradicated` | the deployed active response writes it to the marker's first line | `victim.yml` |
| L24 | `NG-SOC-PUC2` | sharing group present **and** the event is published | `docker_server.yml` |
| L25 | `phishing` | derivable from the level text — no environment dependency | — |
| L26 | `T1204.002` | tag read back off the live MISP event | `docker_server.yml` |

Plus, not graded but load-bearing: rules 100102/100103 must exist or L12 has no
correlation evidence (`ng_siem.yml`); containment must fire from 100103 **only**
or the C2 beacon is blocked before the firewall logs it; the endpoint must stay
reachable over SSH after containment or L20/L21 cannot be answered at all.

## The contract with the training text (`training_contract.yml`)

Correct content in the wrong place still blocks a trainee. The training
definition is uploaded to CyberRangeCZ separately and hardcodes what the
sandbox only resolves at deploy time, so the gate compares the two:

- **Addresses.** Level 10b grades the literal `10.0.16.50`. The overlay derives
  that from kali's inventory facts. If kali comes up elsewhere, the trainee
  reads the right value off MISP and the firewall log, submits it, and is marked
  wrong — and no content check notices. Same for the dashboard URLs the access
  primer and six levels send them to (`10.0.16.70`, `10.0.16.60:8443/:8083/:8080`).
- **Services.** NG-SOAR must answer on 8080; MISP and IRIS are already proved by
  `puc2_keys` to answer an *authenticated* call, which is stronger than a port
  check.
- **Helpers named by absolute path.** `share_intel.sh` (L24),
  `ngsoar_trigger.sh` (L18), `collect_evaluation.sh` (L25) and
  `inject_scenario.sh` (L4) must exist and be executable — the levels instruct
  trainees to run them by path.

When this fails, fix the addressing. **Do not edit the training definition to
match**: it is graded as it stands, and it is deliberately not kept in this
repository.

## The failure this gate is built around

Its first real verdict was wrong. The three CTI-SS/CICMS reads omitted
`return_content: true`, so `ansible.builtin.uri` returned no body, `content |
default('')` was the empty string, and every membership test was False against a
sandbox nobody had actually queried. It failed a build for three resources it
had never looked at, and it would have failed an intact one identically.

Consequences for how the checks are written now:

- **A read that did not happen is not a resource that is missing.** Reads accept
  only HTTP 200 and the assert reports `body returned` separately, so a rejected
  key or a container that is not answering names itself instead of being
  reported as absent content.
- **The credentials are proved, not assumed.** `puc2_keys` elects one key per
  service — the IRIS one from `iris_db`, where `docker_server` itself goes when
  the hardcoded key is rejected — publishes it under the canonical names so
  create and verify cannot diverge, and fails the deployment if either service
  rejects it.
- **Fields, not substrings.** The case is matched on `case_soc_id`; the old
  substring test over the whole list body would have matched the id appearing
  in any field of any case.
- **Every read is total.** `regex_search(...) | first` raises on no match, which
  would replace the actionable message with a stack trace exactly when
  something is missing. Guarded throughout.

When something is missing, the assert names the level, the resource, the HTTP
status and the command to re-run. For evidence without a dashboard:

```bash
ansible-playbook provisioning/playbook.yml --tags puc2_diag --limit docker-server
```
