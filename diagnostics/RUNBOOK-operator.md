# Operator runbook — confirm and resolve the PUC2 2c build failure

Run these on a host with the OpenStack client and credentials for project
`p0000000094`. Everything in step 1 is **read-only**.

```bash
mkdir -p diagnostics
export DS=c08fea99-2b8f-46b2-b784-88aa35b56dc6   # docker-server
export NS=24743039-03b2-4168-9939-6b12ab630830   # ng-siem
```

## Step 1 — Get the real fault (read-only, do this first)

```bash
openstack server show "$DS" -f json > diagnostics/docker-server.json
openstack server show "$NS" -f json > diagnostics/ng-siem.json

# THE decisive output — the log hid this behind %!s(<nil>)
openstack server show "$DS" -f value -c fault
openstack server show "$NS" -f value -c fault

openstack server event list "$DS"
openstack server event list "$NS"
# then, for the failing request-id:
openstack server event show "$DS" <request-id>
```

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

Sanity check to perform by hand: does
`ram(standard.ngsiem) + ram(standard.xmedium)` fit inside
`maxTotalRAMSize - totalRAMUsed`? Same for vCPUs and disk. If not, the verdict
is **QUOTA**.

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
openstack server delete "$DS" "$NS"
openstack server list --status ERROR      # must come back empty
```

> Destructive. Do not run without confirming the sandbox is not in use.

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
