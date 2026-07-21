# Operator runbook — confirm and resolve the PUC2 2c build failure

Run these on a host with the OpenStack client and credentials for project
`p0000000094`. Everything in step 1 is **read-only**.

```bash
mkdir -p diagnostics

# Attempt B (latest build) — four instances in ERROR
export B_KALI=42e70192-2bff-48af-8cbc-8e8b1e3202de   # kali,          deploy.tf:299
export B_DS=bce799d6-a33d-4d22-aa79-08516a3c2205     # docker-server, deploy.tf:320
export B_VICTIM=fa7bc839-5fcf-49eb-8b94-e3503080cc82 # victim,        deploy.tf:362
export B_MAN=dc8b8a8a-c8de-4edc-aa2e-4fda948b4512    # man,           deploy.tf:421

# Attempt A (earlier build) — check whether these still exist. If they do,
# they are consuming allocation and are the prime suspect for the escalation
# from 2 to 4 failures.
export A_DS=c08fea99-2b8f-46b2-b784-88aa35b56dc6     # docker-server
export A_NS=24743039-03b2-4168-9939-6b12ab630830     # ng-siem
```

## Step 1 — Get the real fault (read-only, do this first)

```bash
for id in "$B_KALI" "$B_DS" "$B_VICTIM" "$B_MAN"; do
  echo "== $id =="
  openstack server show "$id" -f value -c name -c status -c fault 2>&1
  openstack server event list "$id" 2>&1
done | tee diagnostics/faults.txt

# Full detail for the two that failed in BOTH attempts
openstack server show "$B_DS" -f json > diagnostics/docker-server.json
# then, for the failing request-id of any of them:
openstack server event show "$B_DS" <request-id>
```

## Step 1b — Inventory of orphans (the aggravating hypothesis)

Failures went 2 → 4 between attempts. If attempt A's instances were never
reaped, attempt B started with less headroom — which would make cleanup the
root fix rather than housekeeping. This inventory settles it:

```bash
openstack server list --long                          | tee diagnostics/servers.txt
openstack server list --status ERROR -f value -c ID -c Name \
                                                      | tee diagnostics/servers_error.txt
openstack stack list 2>/dev/null                      | tee diagnostics/stacks.txt
openstack volume list --status error 2>/dev/null      | tee diagnostics/volumes_error.txt

# Are attempt A's instances still alive?
openstack server show "$A_DS" -f value -c name -c status 2>&1
openstack server show "$A_NS" -f value -c name -c status 2>&1
```

Read `servers.txt` for instances belonging to sandboxes that are no longer in
use, not only for `ERROR` ones: a leftover *ACTIVE* sandbox consumes the same
allocation and is easier to miss.

Quota and capacity:

```bash
openstack limits show --absolute          # totalRAMUsed vs maxTotalRAMSize, cores, instances
openstack quota show p0000000094 2>/dev/null || openstack quota show
openstack hypervisor stats show           # needs admin; free_ram_mb / vcpus_used
```

Image and flavours:

```bash
openstack image show siemng -f value -c status -c min_disk -c min_ram -c size
openstack flavor show standard.ngsiem
openstack flavor show standard.xmedium
openstack flavor show standard.small
```

Sanity check to perform by hand — do **all six** instances of one sandbox fit in
the *real* free margin (max − used − orphans)?

```
                    max      used    orphans    free    needed (6 VMs)
ram (MB)          ______   ______   _______   ______   ______
cores             ______   ______   _______   ______   ______
gigabytes         ______   ______   _______   ______   ______
instances         ______   ______   _______   ______        6
```

If `needed > free`, the verdict is **QUOTA** — and if `orphans` alone closes the
gap, it is `QUOTA-ORPHANS` and no quota increase is required.

Pay attention to the **instances** row. In attempt B the largest flavour built
while two `standard.small` failed; a per-count ceiling behaves exactly like
that, a RAM ceiling normally does not.

Record the verdict and the verbatim fault in `DIAGNOSIS.md`.

## Step 2 — Clean up the failed attempt

Instances stuck in ERROR still consume quota and will block the retry.

**Preferred — via CyberRangeCZ.** Delete the *sandbox* from the pool (or the
whole pool) in the UI/API. The platform owns the Terraform/Heat state, so this
tears down the entire stack consistently. Deleting individual OpenStack
resources behind the platform's back leaves its state file believing they still
exist, which causes confusing failures on the next build.

**Only if the platform cannot clean up** — and after confirming nothing else
depends on them:

```bash
# This attempt's failures
openstack server delete "$B_KALI" "$B_DS" "$B_VICTIM" "$B_MAN"

# Anything else left in ERROR — REVIEW diagnostics/servers_error.txt FIRST,
# it may contain instances belonging to other people's sandboxes
openstack server delete <ids from servers_error.txt>

# Orphaned volumes, if any
openstack volume delete <ids from volumes_error.txt>

openstack server list --status ERROR      # must come back empty
```

> Destructive. Do not run without confirming the sandbox is not in use.

Then re-measure and prove the headroom came back — this is what tells you
whether cleanup alone fixes the build:

```bash
openstack limits show --absolute | tee diagnostics/limits-after-cleanup.txt
```

## Step 3 — Apply the fix that matches the verdict

### If QUOTA and the quota can be raised (preferred)

No repository change. Request an increase for `p0000000094`, sized from the
figures gathered in step 1 — ask for the deficit plus headroom for at least one
concurrent sandbox:

```
ram        (MB)  : current max ____  needed ____
cores            : current max ____  needed ____
gigabytes        : current max ____  needed ____
instances        : current max ____  needed ____  (6 per sandbox)
```

### If CAPACITY

No repository change. Find where `standard.ngsiem` fits and pin the build
there:

```bash
openstack availability zone list
openstack aggregate list
openstack host list          # admin
```

Then have the platform schedule into that AZ/aggregate. Escalate to the cloud
admin if no host can fit the flavour — that is an infrastructure sizing problem,
not a sandbox problem.

### If IMAGE/VOLUME

```bash
openstack image show siemng          # status must be 'active'
openstack volume list                # boot-from-volume?
openstack quota show | grep -i volume
```

Fix the image or the volume quota. Only touch the repository if the mismatch is
in a reference the repository actually owns — `topology.yml` names the image
`siemng` and the flavour `standard.ngsiem`, nothing more.

### Last resort — right-sizing (degrades the range)

Only if quota cannot be raised and no host has capacity. See `VALIDATION.md`
for the before/after record this must produce. Keep `ng-siem` as large as
possible: the Wazuh indexer plus the SPHYNX stack are the memory consumers, and
an undersized SIEM fails later and less obviously — OOM kills mid-exercise
rather than a clean build failure.

## Step 4 — Rebuild

Deploy with **pool size = 1**. A pool of N multiplies every figure in step 1 by
N, and this build already failed at N sandboxes' worth of load. Confirm all six
instances reach ACTIVE before letting Ansible run.

```bash
openstack server list --name 'default-p0000000094-*'
```

Then verify provisioning finished with `failed=0`, and run
`validation/validate_training.sh` (see phase 3).
