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

## Coverage of the 15 hands-on levels

Of the 30 levels, 15 are hands-on and 8 informational + 7 assessment do not
depend on the environment. **No entry below is closed by a human looking at a
dashboard.**

| Level | Answer | Proven by | Where |
|---|---|---|---|
| L4 | `puc2-2c-armed` | token printed by an `--arm` run in which every check passed | `victim.yml` |
| L5 | `invoice.exe` | `--arm` verifies the lure is staged and the mail delivered | `victim.yml` |
| L8 | `44d88612…abb02f` | hash on the NG-SIEM CDB watchlist **and** on the MISP event | `ng_siem.yml`, `docker_server.yml` |
| L9 | `T1566.001` | tag read back off the live MISP event | `docker_server.yml` |
| L10 | `100101` | rule loaded in `local_rules.xml` | `ng_siem.yml` |
| L11 | `targeted` | derivable from the level text — no environment dependency | — |
| L14 | `CASE-PUC2-2C` | case matched on its `case_soc_id` **field** in DFIR-IRIS | `docker_server.yml` → `cicms_2c/find_case.yml` |
| L15 | `c2.puc2-training.lab` | domain IOC on the live MISP event | `docker_server.yml` |
| L18 | `isolate_host` | playbook present in the NG-SOAR library | `docker_server.yml` |
| L19 | `isolated` | the deployed active response writes it to the marker's first line | `victim.yml` |
| L20 | `10.0.16.50` | the C2 address on the MISP event matches the range's actual C2 | `docker_server.yml` |
| L21 | `eradicated` | the deployed active response writes it to the marker's first line | `victim.yml` |
| L24 | `NG-SOC-PUC2` | sharing group present **and** the event is published | `docker_server.yml` |
| L25 | `phishing` | derivable from the level text — no environment dependency | — |
| L26 | `T1204.002` | tag read back off the live MISP event | `docker_server.yml` |

Plus, not graded but load-bearing: rules 100102/100103 must exist or L12 has no
correlation evidence (`ng_siem.yml`); containment must fire from 100103 **only**
or the C2 beacon is blocked before the firewall logs it; the endpoint must stay
reachable over SSH after containment or L20/L21 cannot be answered at all.

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
