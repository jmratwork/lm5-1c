# Security follow-up — credential rotation

**Status: action required from an operator with access to the running sandbox.**

Three secrets are covered here. All three were committed in cleartext and must
be treated as compromised; removing them from the tree does not un-publish them.

| Secret | Was in | Now | Exposure |
|---|---|---|---|
| DFIR-IRIS API key | 3 dead task files of `docker_server` | removed | this repo's git history, build logs |
| Docker Hub PAT | `roles/docker_server` (and the deleted `roles/kali`) | `vault_dockerhub_pat` | **public on GitHub** in the upstream substrate |
| `ubuntu` password hash | `roles/docker_server`, `roles/victim` | `vault_ubuntu_password_hash` | **public on GitHub** in the upstream substrate |

The last two are worse than the first: they are public in
`NG-SOC-eu/ng-soc-ansible@integrations`, so rotating them here is not enough —
they must also be fixed upstream, or every sandbox built from that substrate
keeps shipping them.

## Docker Hub PAT and the ubuntu password hash

Both are now read from ansible-vault and both degrade safely when unset:

- **Docker Hub** — the login task is skipped when `vault_dockerhub_pat` is empty,
  and images are then pulled anonymously. **On this range that is not merely
  slower — it fails the build.** A deployment run with no PAT died pulling
  `rabbitmq:3.8-management` for DFIR-IRIS with `429 Too Many Requests`; the
  anonymous limit is reached here in practice. So: revoke the exposed PAT
  (`dckr_pat_OzOR…`) on the `demongsoc` account **and issue a replacement**, then
  put it in `vault_dockerhub_pat`. Treat it as required, not optional. The role
  now warns explicitly when it is missing, because the 429 surfaces deep inside a
  compose task and says nothing about the skipped login.
- **`ubuntu` password** — the task omits the password when
  `vault_ubuntu_password_hash` is empty, so the account's existing password is
  left alone rather than blanked. **Set one if trainees log in at the graphical
  console prompt**; SSH-key access is unaffected either way. Generate with
  `mkpasswd --method=yescrypt`.

### Getting a secret to the sandbox at all

`vault.yml` is git-ignored, so it **never reaches the deployment**: the range
clones this repository and receives only `vault.yml.example`, with its empty
values. Writing a PAT into a local `vault.yml` therefore fixes nothing on the
sandbox. And this repository is **public**, so committing a plaintext secret is
not an option either. Two routes actually work:

1. **Extra var at deploy time — CHOSEN ROUTE.** Pass it to the run rather than
   storing it anywhere:

   ```bash
   ansible-playbook provisioning/playbook.yml \
     -e vault_dockerhub_pat=dckr_pat_NEW... \
     -e vault_dockerhub_user=demongsoc
   ```

   Nothing lands in the repo, and no code change was needed: every consumer
   reads the value with `| default('')`, and Ansible gives `-e` the highest
   precedence, above `vars_files`. The same mechanism carries
   `vault_ubuntu_password_hash` if a console password is wanted. It needs the
   CyberRangeCZ job to accept extra vars — if it turns out it cannot, fall back
   to route 2.
2. **Commit an ansible-vault ENCRYPTED `vault.yml`** — encrypted files are safe
   in a public repo — and supply the vault password to the job
   (`--vault-password-file` or `ANSIBLE_VAULT_PASSWORD_FILE`). This needs
   `vault.yml` removed from `.gitignore`, and it is only safe once the file is
   confirmed encrypted.

Either way, **rotate first**. The exposed PAT is public in the upstream
substrate; re-using it just moves a burnt credential around.

## DFIR-IRIS API key

## What happened

A DFIR-IRIS (CICMS) API key was committed to this repository in cleartext and
also appeared in build/deployment logs. It lived in three dead task files of the
`docker_server` role — `debug_main.yml`, `main-old.yml`, and
`main-with-old-mcp.yml` — none of which is referenced by any play, include or
import (Ansible auto-loads only `main.yml`). The active `main.yml` had already
been refactored to resolve the key at run time (bootstrap key that must still
authenticate, else read from the IRIS database) with `no_log: true`, so the live
code path did not carry the literal.

The three dead files have been removed on this branch. **That scrubs the working
tree only.** The key remains recoverable from:

- this repository's **git history** (every commit before the removal), and
- any retained **build logs** (the deployment `log.txt` and equivalents).

A secret that has been in git history and in logs must be treated as
**compromised**. Removing the file is necessary but not sufficient.

## Required actions (operator, against the live sandbox)

1. **Rotate the key in DFIR-IRIS.** Log into CICMS (`https://10.0.16.60:8083`),
   revoke the exposed key for the service/user it belongs to, and issue a new
   one. The exposed value must stop authenticating.

2. **Store the new key in ansible-vault, never in a task file.**
   ```bash
   cp provisioning/group_vars/vault.yml.example provisioning/group_vars/vault.yml
   $EDITOR provisioning/group_vars/vault.yml         # set vault_iris_bootstrap_key
   ansible-vault encrypt provisioning/group_vars/vault.yml
   ```
   `vault.yml` is already git-ignored. The overlay prefers the live fact the
   `docker_server` role discovers at provision time and falls back to this vault
   value, so on a normal run nothing else is needed.

3. **Treat the build logs as secret material.** The deployment logs are kept
   local and untracked by policy; shred the ones that captured the old key
   (`shred -u log.txt` or equivalent) rather than archiving them. Do not add them
   to the repository to "keep a record" — that reintroduces the exposure.

4. **Decide on git history.** The old key is still in historical commits. Options,
   in order of increasing disruption:
   - Accept it, on the strength of step 1 having made the key useless. **Note
     that `jmratwork/lm5-1c` is a PUBLIC repository**, so "nobody will look" is
     not part of the argument: every historical commit is world-readable and
     indexable. Accepting is only defensible once the key is genuinely revoked.
   - Purge it from history with `git filter-repo` (or BFG) and force-push. This
     rewrites shared history and must be coordinated with everyone who has a
     clone — do it deliberately, not as a side effect of this change.

## Preventing a recurrence

- Keys resolve at run time into `no_log: true` facts; keep it that way. A key
  should never appear as a literal in a task, a default, or a template.
- `ansible-vault` holds any value that must be seeded ahead of provisioning.
- Dead role variants (`*-old.yml`, `debug_*.yml`) are where secrets rot after
  the live path is cleaned. Remove them rather than leaving them beside the code.
