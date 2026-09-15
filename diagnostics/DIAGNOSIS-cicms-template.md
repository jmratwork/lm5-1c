> **Status (2026-09-15): resolved and confirmed by a deploy.** The 08:46 build
> registered the template (`d7de819`).
> The Phase 2 change below landed: the template is non-fatal and reports IRIS's
> own body, and `CASE-PUC2-2C` is created and gated on its own. With the body
> visible, two faults turned out to stack, and **section 2 below is wrong for the
> deployed IRIS**.
>
> 1. *Transport.* The endpoint (`add_case_template`, iris-web v2.4.29 and master)
>    does `json.loads(data.get('case_template_json'))`, so it needs a JSON
>    *string*. Ansible 2.16's `convert_data=True` defeated that twice. That
>    setting is the default for task arguments and for `lookup('template')`, and
>    it passes any rendered text starting with `{` to `ast.literal_eval`.
>    - 2026-09-14 15:26, body built inline: `the JSON object must be str, bytes or
>      bytearray, not dict`.
>    - 2026-09-15, body rendered to a file with `lookup('template', …) | trim`:
>      the lookup returned a dict, `trim` turned it into its Python repr, and IRIS
>      answered `Expecting property name enclosed in double quotes: line 1
>      column 2 (char 1)`. The file was 2725 bytes against the template's 3017; an
>      escaped JSON string would have been larger.
>
>    The first fix blamed `jinja2_native`. That was wrong: the runner has no
>    `ansible.cfg` (`No config file found; using defaults`), so native mode is off,
>    and the conversion happens in either mode. The lookup now passes
>    `convert_data=False`, the body is serialised with `to_json` and POSTed with
>    `uri src=… remote_src=true`. Verified with the real ansible-core 2.16.14
>    Templar, which reproduces the 2026-09-15 error verbatim before the change and
>    yields a valid string after it, native off and on.
> 2. *Schema.* The deployed zip carries the migrations
>    `35c095f8be2b_case_templates_note_groups_to_…` and
>    `c29ef01617f5_migrate_notes_directories`, so it is IRIS 2.4 or later. Its
>    validator answers `note_groups` with "Note groups has been replaced by
>    note_directories." Section 2 below followed older documentation (v2.3.x
>    really does use `note_groups`) and led the template the wrong way. It now
>    sends `note_directories`.
>
> Verified statically: the rendered body keeps `case_template_json` as a string,
> and iris-web v2.4.29's own `validate_case_template` accepts the template (and
> rejects the previous one with the message above).
>
> **Confirmed against the deployed IRIS.** The 2026-09-15 08:46 build logged
> `CICMS case template 'PUC2-2C-Malware' registered — confirmed present in IRIS's
> own template list, not merely accepted by the POST`. That line comes from a
> second `GET /manage/case-templates/list`, not from the POST's answer. MISP
> seeding, whose body was hardened in the same commit, still logged `event seeded
> (id 1, published)`. The template remains cosmetic: no training level depends on
> it.

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
