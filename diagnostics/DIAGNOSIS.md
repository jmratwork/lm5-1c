# Diagnosis — PUC2 2c sandbox build failure (project p0000000094, sandbox s0000000522)

## Status: **PENDIENTE DE CONFIRMAR** (second failed attempt analysed)

`OPENSTACK_UNAVAILABLE`. The workstation this analysis ran on has no
`openstack` client, no `nova`, no `terraform`/`tofu`, and zero `OS_*`
environment variables. **No diagnostic command could be executed**, so
everything below is derived from the two build logs. It must be confirmed with
`RUNBOOK-operator.md` before any fix is applied.

Nothing in this file is an observation from the live cloud. Where a statement is
inference, it says so.

## Two attempts, two different failure sets

| Instance | Flavor | Image | Attempt A | Attempt B (this log) |
|---|---|---|---|---|
| ng-siem | standard.ngsiem | siemng | **ERROR** | ACTIVE `35151302-6889-4281-b769-9f6c47d5d2dc` |
| router | standard.small | debian-12 | ACTIVE | ACTIVE `36da7bd6-7c8b-47ed-a74c-7f53a7f68e0f` |
| kali | standard.xmedium | kali | ACTIVE | **ERROR** `42e70192-2bff-48af-8cbc-8e8b1e3202de` (deploy.tf:299) |
| docker-server | standard.xmedium | ubuntu-noble | **ERROR** | **ERROR** `bce799d6-a33d-4d22-aa79-08516a3c2205` (deploy.tf:320) |
| victim | standard.small | ubuntu-noble | ACTIVE | **ERROR** `fa7bc839-5fcf-49eb-8b94-e3503080cc82` (deploy.tf:362) |
| man | standard.small | debian-12 | ACTIVE | **ERROR** `dc8b8a8a-c8de-4edc-aa2e-4fda948b4512` (deploy.tf:421) |
| | | | **2 ERROR** | **4 ERROR** |

Both attempts: all network resources (testnet/wan/man, subnets, ports) created
without error. Both attempts fail compute-only, with the same message:

```
Error waiting for instance (<uuid>) to become ready:
unexpected state 'ERROR', wanted target 'ACTIVE'. last error: %!s(<nil>)
```

`%!s(<nil>)` is not the fault — it is the **absence** of one. The Go provider
rendered a nil `fault` field with `%s`. Nova reported `status=ERROR` and the
provider read no populated fault. **The real reason is not in either log and
cannot be recovered from them.** Retrieving it is step 1 of the runbook.

## What the comparison rules out — this is the decisive evidence

The failing set **changed between attempts**, and it changed in a way that
kills every host-, image- and flavour-specific explanation:

- **Not the `standard.ngsiem` flavour or the `siemng` image.** They failed in
  attempt A and **succeeded in attempt B** — the largest instance of the six
  built fine while two `standard.small` did not.
- **Not `standard.xmedium`, not `standard.small`.** Each flavour appears on
  both sides of the line across the two attempts.
- **Not `ubuntu-noble-x86_64`, not `debian-12-x86_64`, not `kali`.** Same.
- **Not a single sick compute host.** A host-local fault would not reshuffle
  which four of six instances fail.
- **Not networking, not the repository.** Terraform planned and created every
  network resource; provisioning never started, so no Ansible role — and
  therefore nothing in the 2c overlay — can be implicated in either attempt.

What remains is a **shared, exhaustible resource consumed in creation order**:
whichever instances are scheduled while headroom lasts become ACTIVE, the rest
fail. That is quota or capacity, and only the live cloud can say which.

## The aggravating hypothesis: orphans from attempt A

Failures went **2 → 4** between attempts. The scenario that explains an
escalation is that attempt A's two ERROR instances (and possibly its whole
stack) were never reaped, so attempt B started against a project that had
already lost that headroom. Under that reading, **cleanup is the root fix, not
housekeeping**, and no quota increase is needed at all.

This is a hypothesis with a cheap test: `openstack server list --long` and
`openstack server list --status ERROR` will show whether attempt A's instances
(`c08fea99-…` docker-server, `24743039-…` ng-siem) are still there consuming
allocation. Until that inventory is run, nothing here is established.

Note also that both attempts are recorded under sandbox **s0000000522**. If
that is literal rather than a transcription artefact, attempt A's resources may
still exist under the same names, which is worth confirming while taking the
inventory.

## Candidate verdicts (fill in after running the runbook)

| Verdict | Confirm when |
|---|---|
| `QUOTA-ORPHANS` | `server list --status ERROR` shows instances from previous attempts; `limits show` headroom recovers after they are removed |
| `QUOTA-RAM/CORES` | fault or `server event list` mentions quota; or `totalRAMUsed + <needed>` exceeds `maxTotalRAMSize` (likewise cores, gigabytes) |
| `QUOTA-INSTANCES` | `maxTotalInstances` reached — this fits attempt B well, where two `standard.small` failed while the largest flavour succeeded: a **count** ceiling is size-blind |
| `CAPACITY` | fault or scheduler says `No valid host was found` **and** quota has headroom |
| `IMAGE/VOLUME` | `siemng` not `active`; or `min_disk`/`min_ram` > flavour; or volumes in `error` / volume quota hit |
| `OTRO` | anything else — transcribe the fault verbatim, do not paraphrase |

`QUOTA-INSTANCES` deserves particular attention this time: in attempt B the
resource-hungry instance built and the two smallest did not, which is what a
per-count limit looks like and is **not** what a RAM ceiling usually looks like.

**Result: _____________ (to be completed by the operator)**

**Fault verbatim:**

```
(paste `openstack server show <id> -f value -c fault` output here)
```

## Why no fix is pre-applied

Right-sizing the flavours in `topology.yml` would plausibly make the build pass
under QUOTA or CAPACITY, which makes it a tempting blind fix. It is the wrong
first move, and after attempt B it is also unsupported by the evidence:

- The failing set is **not** correlated with size. `ng-siem` — the instance
  right-sizing would target — built successfully in the failing attempt.
- `topology.yml` is vendored **byte-identical** from the `integrations`
  substrate. Editing it breaks that guarantee for a cause nobody has confirmed.
- `standard.ngsiem` exists because the Wazuh indexer plus the SPHYNX stack need
  the RAM. Shrinking it trades a hard failure for a soft one: OOM kills, an
  indexer that never becomes ready, degraded detection — surfacing later as
  training levels that mysteriously fail.

If the cause is orphaned resources or an extendable quota, the correct fix is
operational and the repository does not change at all.
