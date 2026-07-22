# Diagnosis — `cicms_2c` fails registering the PUC2 2c case template

**Task:** `Register the PUC2 2c case template in CICMS`
(`POST /manage/case-templates/add`, `roles/cicms_2c/tasks/main.yml:63`)
**HEAD:** a815104

> Written here rather than in `DIAGNOSIS.md` on purpose: that file is now a
> **generated artefact** — the `puc2_diag` role rewrites it from
> `roles/puc2_diag/templates/DIAGNOSIS.md.j2` on every run — and it currently
> holds the previous phase's finding (`uri` returning no body without
> `return_content`). Hand-writing this there would have destroyed that record
> and been overwritten by the next diagnostic run.

## Honest limit on this document

**I could not run the re-execution.** This workstation has no Ansible
controller (the `ansible` entry point tracebacks on Windows: no `fcntl`) and no
route to `10.0.16.x`. The literal instruction — re-run with `no_log: false` and
paste IRIS's response body — was not performed, and **no line below is an
observation from the live sandbox.**

What follows is the template in the working tree checked against the official
DFIR-IRIS case-template schema (`docs.dfir-iris.org/operations/case_templates/`,
retrieved for this analysis). That names the defects with confidence, because
they are violations visible without running anything. Which one IRIS reports
*first* is not established here.

**This does not stay unresolved.** The Phase 2 change makes the deployment print
IRIS's own error body on the next build — no operator action, no `no_log`
toggling. The real body arrives in the log by itself.

## Already established, from your build log

- `GET /manage/case-templates/list` → 200. **The key is valid and the endpoint
  is reachable. This is not authentication.**
- `failed_when` fired on `{"status": "error"}`, so IRIS answered HTTP 200 and
  refused in the body. **IRIS is rejecting the template document itself.**

## Three schema violations, all in the template

| # | Field | Sent | Schema requires |
|---|---|---|---|
| 1 | `tasks[].tags` | `"step-7"` (string), ×7 | **array of strings** — `["step-7"]` |
| 2 | top-level `note_directories` | `note_directories` | **`note_groups`** — `note_directories` is not in the schema at all |
| 3 | `classification` | `"malware"` | a lowercase name **matching an existing IRIS classification**, e.g. `malicious-code:malware` |

### 1. `tasks[].tags` is a string, must be a list

The documented example is `"tags": ["identify"]`. All seven tasks send a bare
string. Task 4 is the clearest tell: `"tags": "step-9,step-10"` is a
comma-separated string standing in for what the schema models as two elements.

### 2. `note_directories` is not a field — the key is `note_groups`

Worth checking rather than assuming, and the check changes the answer: the
schema has **no** `note_directories`. IRIS validates with marshmallow, which
rejects unknown fields outright rather than ignoring them, so this alone is
sufficient to produce the refusal even if everything else were correct.

### 3. `classification` must name an existing IRIS classification

`"malware"` is a plain word, not a taxonomy entry; IRIS entries look like
`malicious-code:malware`. If the deployed instance does not carry that exact
entry, the field is refused again.

The fix **drops the field entirely**. It is optional, no training level
references the case classification, and keeping it means keeping a dependency on
a taxonomy list nobody has read back from this instance — trading a known defect
for an unverifiable one.

## Which one is IRIS reporting?

Not determinable without the body. Most likely #2 (unknown field, rejected
before type checks under marshmallow's default `RAISE`), then #1, then #3.
Operationally it does not matter: **all three are wrong and all three get
fixed**, so the ordering is a curiosity rather than a blocker.

## The defect that actually matters is not in the template

The template is cosmetic — the training definition never mentions
`PUC2-2C-Malware`. The real fault is structural:

> **A cosmetic resource was allowed to abort the play.**

Because the task is `failed_when`-fatal, its failure stopped
**`Create the PUC2 2c scenario case`** from ever running — and that creates
`CASE-PUC2-2C`, which level 7 (L14) grades — and stopped the `puc2_preflight`
gate from running at all, so nothing reported what was missing.

A trainee would have reached level 7 to find no case, and the build's own safety
net never got the chance to say so, because a decorative task killed the play
first.

Fixing the schema alone would leave that trap armed for the next optional
resource IRIS happens to dislike. Phase 2 addresses it: the template becomes
non-fatal and self-reporting, and hard failure is reserved for what the trainee
actually needs — the gate's job.

## To capture the real body before the fix (optional)

Phase 2 makes this unnecessary, but if you want the body first:

```bash
ansible-playbook provisioning/playbook.yml --limit docker-server --tags cicms -vv
```

with `no_log: false` set temporarily on that one task only. Mask the
`Authorization` header before pasting anything.
