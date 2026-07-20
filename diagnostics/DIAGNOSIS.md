# Diagnosis — PUC2 2c sandbox build failure (project p0000000094, sandbox s0000000522)

## Status: **PENDIENTE DE CONFIRMAR**

`OPENSTACK_UNAVAILABLE`. The workstation this analysis ran on has no
`openstack` client, no `nova`, no `terraform`/`tofu`, and zero `OS_*`
environment variables. **No diagnostic command could be executed**, so the root
cause below is a hypothesis derived from the build log alone. It must be
confirmed with the runbook in `RUNBOOK-operator.md` before any fix is applied.

Nothing in this file is an observation from the live cloud. Where a statement
is inference, it says so.

## What the log actually shows

| Instance | Flavor | Image | Result |
|---|---|---|---|
| kali | standard.xmedium | kali | ACTIVE after 10s |
| victim | standard.small | ubuntu-noble-x86_64 | ACTIVE after 10s |
| man | standard.small | debian-12-x86_64 | ACTIVE after 10s |
| router | standard.small | debian-12-x86_64 | ACTIVE after 10s |
| **docker-server** | **standard.xmedium** | **ubuntu-noble-x86_64** | **ERROR** |
| **ng-siem** | **standard.ngsiem** | **siemng** | **ERROR** |

All 26 network resources were created without error. Both failures are compute
only, and both surfaced as:

```
Error waiting for instance (<uuid>) to become ready:
unexpected state 'ERROR', wanted target 'ACTIVE'. last error: %!s(<nil>)
```

Failed instance IDs:
- docker-server `c08fea99-2b8f-46b2-b784-88aa35b56dc6` (deploy.tf:320)
- ng-siem `24743039-03b2-4168-9939-6b12ab630830` (deploy.tf:341)

### `%!s(<nil>)` is not the fault — it is the absence of one

That string is a Go formatting artefact: the provider tried to render a nil
value with `%s`. It means nova reported `status=ERROR` but the provider read no
populated `fault` field. **The real reason is not in this log and cannot be
recovered from it.** Retrieving it is step 1 of the runbook.

## What the evidence rules out

This is the useful part of the log, and it narrows the field considerably:

- **Not the `xmedium` flavor.** `kali` is also `standard.xmedium` and became
  ACTIVE. A flavor that is definitionally unschedulable would have failed there
  too.
- **Not the `ubuntu-noble-x86_64` image.** `victim` used it and became ACTIVE.
- **Not networking.** Every port, subnet and network reached
  `Creation complete`, including the ports carrying the fixed IPs of both
  failed hosts (`10.0.16.60`, `10.0.16.70`).
- **Not the repository.** Terraform generated a plan of 26 resources from the
  topology without error; provisioning never started, so no Ansible role — and
  therefore nothing added by the 2c overlay — can be implicated.

## Leading hypothesis (unconfirmed): cumulative resource ceiling

The two failures are **the two largest instances**, and they are the **last two
scheduled** — the log shows `kali`, `victim`, `man`, `router` entering creation
first and completing, with `ng-siem` and `docker-server` entering creation last
and failing. That ordering is what a cumulative ceiling looks like: the first
allocations succeed and consume headroom, the largest remaining ones cannot be
placed.

Two variants remain, and the log cannot distinguish them:

- **QUOTA** — the project's RAM / vCPU / disk allowance is exhausted. Would
  normally surface a `quota exceeded` fault or a 403 at the API.
- **CAPACITY** — quota has headroom but no single compute host can fit
  `standard.ngsiem`. Surfaces as `No valid host was found`.

A third possibility is not excluded and is cheap to check: **IMAGE/VOLUME** —
the `siemng` image is custom and large; if `min_disk`/`min_ram` exceed the
`standard.ngsiem` flavor, or boot-from-volume hits the volume quota, the build
fails at exactly this point. This would explain `ng-siem` but not
`docker-server`, so on its own it is a weaker fit.

## Classification criteria (fill in after running the runbook)

| Verdict | Confirm when |
|---|---|
| `QUOTA` | fault or `server event list` mentions quota; or `limits show --absolute` shows `totalRAMUsed + <needed>` exceeding `maxTotalRAMSize` (likewise cores / volume gigabytes) |
| `CAPACITY` | fault or scheduler log says `No valid host was found` **and** quota has headroom |
| `IMAGE/VOLUME` | `siemng` not `active`; or `min_disk`/`min_ram` > flavor; or block device mapping / volume-quota failure |
| `OTRO` | anything else — transcribe the fault verbatim, do not paraphrase |

**Result: _____________ (to be completed by the operator)**

**Fault verbatim:**

```
(paste `openstack server show <id> -f value -c fault` output here)
```

## Why the fix is deliberately not pre-applied

Right-sizing the flavors in `topology.yml` would make the build succeed under
*either* QUOTA or CAPACITY, which makes it a tempting blind fix. It is the
wrong first move:

- `topology.yml` is vendored **byte-identical** from the `integrations`
  substrate (see README, "Reuse of the integrations substrate"). Editing it
  breaks that guarantee for a cause nobody has confirmed.
- `standard.ngsiem` exists because the Wazuh indexer plus the SPHYNX stack need
  the RAM. Shrinking it trades a hard failure for a soft one: OOM kills,
  an indexer that never becomes ready, and degraded detection — which would
  surface much later, as training levels that mysteriously fail.

If the cause is QUOTA and the quota is extendable, or CAPACITY resolvable by
scheduling into an AZ/aggregate with room, the correct fix is operational and
the repository does not change at all. Right-sizing is the last resort, not the
first.
