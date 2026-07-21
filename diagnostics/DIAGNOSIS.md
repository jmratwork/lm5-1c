# Diagnosis — PUC2 2c preflight gate: three False verdicts that were never about MISP

**Phase 0. Status: root cause identified and proven from source; live confirmation PENDING.**

## Honest limit of this document

The live probes this phase calls for **were not run**. This workstation cannot
reach the sandbox and cannot act as an Ansible controller:

| Check | Result |
|---|---|
| `ping 10.0.16.60` | `UNREACHABLE` (100 % loss) |
| `ansible --version` | traceback — `ModuleNotFoundError: No module named 'fcntl'` |
| `ansible-core` installed | 2.20.5, but Ansible has **no Windows controller support** |
| `OS_*` / sandbox credentials in the environment | none |

So `puc2_diag` was **written and statically exercised**, not executed. Section
"Live confirmation" gives the single command that fills in the live half, and
`puc2_diag` overwrites this diagnosis with real API evidence when it runs.

What follows is nonetheless not speculation: the root cause is established from
the Ansible source shipped on this machine, and it accounts for every symptom in
the build log, including the paradox.

## The finding

**`ansible.builtin.uri` does not return the response body unless
`return_content: true` is set. None of the gate's three reads set it.**

`ansible/modules/uri.py`, the exit path (lines 770-779 of the installed 2.20.5):

```python
if resp['status'] not in status_code:
    ...
    if return_content:
        module.fail_json(content=u_content, **uresp)
    else:
        module.fail_json(**uresp)
elif return_content:
    module.exit_json(content=u_content, **uresp)
else:
    module.exit_json(**uresp)          # <-- no `content` key at all
```

`return_content` defaults to `False` (line 599). In
[provisioning/roles/puc2_preflight/tasks/docker_server.yml](provisioning/roles/puc2_preflight/tasks/docker_server.yml)
all three reads omit it, and the gate then does:

```yaml
puc2_pf_event:  "{{ puc2_pf_misp_event.content  | default('') | string }}"   # -> ''
puc2_pf_groups: "{{ puc2_pf_misp_groups.content | default('') | string }}"   # -> ''
puc2_pf_cases:  "{{ puc2_pf_iris_cases.content  | default('') | string }}"   # -> ''
```

`'T1566.001' in ''` is False. So is every other membership test. The gate was
**not reading MISP and IRIS at all** — it was testing substrings against three
empty strings, and it would have reported exactly the same three Falses against
a perfectly provisioned sandbox.

The NG-SOAR check is the control that proves it: it is the only one of the four
that uses `find` instead of `uri`, and it is the only one that passed.

## Why this explains the paradox, and nothing else does

The creation tasks reported success **and** the read-back reported absence
because the same missing `content` breaks both halves:

| Symptom | Explained by |
|---|---|
| Gate: event, sharing group, case all False | `.content` absent → `default('')` → every `in` test False |
| Gate: NG-SOAR library OK | uses `find`, not `uri` — unaffected |
| `cti_ss_2c` seeds the event `changed: true` on every run | its idempotency guard is `when: puc2_payload_md5 not in (puc2_misp_existing.content \| default(''))` → `not in ''` → always True → **always re-seeds** |
| Sharing group `changed: true` on every run | same guard, same empty string |
| IRIS case create ran and returned 200/201 | same guard on `puc2_iris_cases.content` → always re-creates |
| "FAIL if the scenario case could not be created" was skipped | its second condition is `status not in [200, 201]`; the POST returned 200, so the task correctly skipped — **it never checked the body** |

Every reported observation falls out of one defect. That is the test a root
cause has to pass.

Note the collateral damage: because the guards never see content, provisioning
has been **re-creating the MISP event on every run**. Expect duplicate events in
CTI-SS proportional to the number of builds.

## The four hypotheses in the brief

Assessed against the code; none is the primary cause, three are still real
hardening work and one is a live question.

| # | Hypothesis | Assessment |
|---|---|---|
| (a) | Event not published → invisible to read-back | **Not the cause.** The event is indeed created unpublished (`misp_event_puc2_malware.json.j2` sets no `published`, and `cti_ss_2c` never calls `/events/publish`), but `restSearch` shows an org's own unpublished events to its own key. It would have been found. Still worth fixing: publishing is what training level L24's sharing step models, and an unpublished event is invisible to *other* orgs. |
| (b) | Verify uses a different key than create | **Not the cause, but unverified.** Both resolve `puc2_misp_api_key` / `puc2_iris_api_key` from the same `group_vars/puc2_2c.yml` lines, so they cannot diverge *within a run*. They can diverge from the **live** key: `docker_server` falls back to reading the real key out of `iris_db` when the hardcoded one is rejected (which it was — the 404 probe), and whether that fact survived into the overlay play is exactly what `puc2_diag` fingerprints. |
| (c) | 200 with an error body, trusted blindly | **Live and untested.** `changed_when: status in [200, 201]` with no body inspection is precisely this exposure. MISP answers `{"errors": ...}` and IRIS `{"status": "error"}` at HTTP 200. Because `content` was never fetched, **nobody has ever looked at these bodies** — including the "FAIL if case" guard. |
| (d) | IRIS case searched by name, not `soc_id` | **Partly real.** The check is `puc2_case_soc_id not in content`, a substring test over the whole list body — not by name, but not by field either: it would match `CASE-PUC2-2C` appearing in any field of any case. Worse, `/manage/cases/list` may not return `case_soc_id` at all in this IRIS version, in which case a correct case is unfindable by that route. `puc2_diag` prints the field list of a real case row to settle it. |

## Classification

| Resource | Gate verdict | Actual state | Classification |
|---|---|---|---|
| MISP event `T1566.001` / `T1204.002` / `c2.puc2-training.lab` | False | unknown | **FALSO NEGATIVO del gate — confirmado.** Existence pending. |
| Sharing group `NG-SOC-PUC2` | False | unknown | **FALSO NEGATIVO del gate — confirmado.** Existence pending. |
| IRIS case `CASE-PUC2-2C` | False | unknown | **FALSO NEGATIVO del gate — confirmado.** Existence pending. |
| NG-SOAR library | True | present | OK (file-based, unaffected) |

The distinction that matters: **the gate's failure is proven to be its own; the
underlying resources are not thereby proven to exist.** The gate never looked,
so nothing is known about them either way. Two defects can coexist — a blind
gate and a create that trusts a 200 — and the fix must not assume the second
away. That is why Phase 1 hardens creation as well as verification.

## Also found while reading

1. **The gate is blind by construction, not by accident of one flag.** Three
   reads, one shared idiom, no test that the idiom returns anything. A gate that
   cannot fail for the right reason is worse than no gate: this one passed
   builds for as long as it happened not to be reached, and its first real
   verdict was wrong.
2. **`no_log: true` is on every one of these tasks.** It did not cause the bug,
   but it is why a whole build cycle was spent on a defect that one visible
   response body would have exposed. Phase 1 keeps `no_log` on anything carrying
   a key and moves the *bodies* out from under it.
3. **`regex_search(...) | first` appears in
   [ng_siem.yml:12-15](provisioning/roles/puc2_preflight/tasks/ng_siem.yml#L12-L15)**
   with no guard: if `<rules_id>` is ever absent from `ossec.conf`,
   `regex_search` returns `None` and `None | first` raises a templating error
   instead of failing the assert with its actionable message. Same class of
   defect — an unhandled shape from a read. Phase 2 fixes it.

## Live confirmation — one command

From a Linux controller with the sandbox inventory:

```bash
ansible-playbook provisioning/playbook.yml --tags puc2_diag --limit docker-server
```

`puc2_diag` ([provisioning/roles/puc2_diag/](provisioning/roles/puc2_diag/)) is
read-only, tagged `never` so no build can pick it up, and it:

- resolves the IRIS key from `iris_db` and the MISP key from `/etc/misp-mcp.env`
  — the values the running services actually accept — and fingerprints every
  candidate as `sha256[:12]/length`, so the report answers "did create and
  verify use the same key?" without printing one;
- issues the gate's exact request twice, once as shipped and once with
  `return_content: true`, and reports whether `content` came back each time.
  This turns the root cause above into an observation;
- reads `/events/restSearch`, `/events/index`, `/sharing_groups/index`,
  `/api/ping` and `/manage/cases/list` with bodies, and reports for each
  resource: exists, HTTP status, and the API's own error text;
- matches the case by the `case_soc_id` **field** and separately reports whether
  the string appears anywhere in the body, so hypothesis (d) is answered rather
  than assumed, and prints the field list of a real case row;
- classifies each resource FALSO NEGATIVO / FALLO REAL / FALLO DE ACCESO and
  overwrites `diagnostics/DIAGNOSIS.md` with the result.

Credentials never leave the host: bodies are passed through a redaction pass
built from every key in play before any of them is printed or written.

### What was verified statically

- YAML parse of the new role and of the modified `playbook.yml`: OK.
- Jinja parse of the report template: OK.
- The reductions and the verdict logic were rendered against three simulated
  API worlds — resource present, resource absent, and an IRIS list without
  `case_soc_id` — and classified them FALSO NEGATIVO / FALLO REAL / FALSO
  NEGATIVO respectively, with no templating error. The shipped gate's
  expression returns False in all three, which is the defect restated.
