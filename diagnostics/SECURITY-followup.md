# Security follow-up — credentials in this repository

Phase 4 of the preflight work. **Non-blocking for the training**: nothing here
stops a trainee completing the 30 levels. All of it is live-credential hygiene.

## Done

| Item | Change |
|---|---|
| IRIS key printed in cleartext by the build | `docker_server` had **no `no_log` at all**. The three tasks whose `stdout` *is* a credential (`cake user change_authkey`, both `psql` reads) and the tasks that set the facts now carry `no_log: true`. The failure message that printed both DB columns verbatim now reports their **length**. |
| Hardcoded DFIR-IRIS key in the active role | Removed from `roles/docker_server/tasks/main.yml`. Replaced by `iris_bootstrap_api_key`, empty by default and settable from vault. The probe is skipped when empty, so the role goes straight to `iris_db` — which is what already happened, one wasted 404 later. |
| Reintroduction of that key | `puc2_keys` fails the deployment if the elected IRIS key matches its SHA-256, and separately if either service rejects the elected key. |
| Overlay logging | Every task in the 2c overlay that carries a credential has `no_log: true`; `puc2_diag` prints response **bodies** only, redacted against every key in play, and reports keys as `sha256[:12]/length`. |

## Still to do — needs access this workstation does not have

### 1. Rotate the DFIR-IRIS key (it is in a build log in cleartext)

`no_log` protects future builds. It does nothing for the log already produced.
Treat that log as a secret and rotate:

```sql
-- on docker-server
docker exec iris_db psql -U postgres -d iris_db -c \
  "UPDATE \"user\" SET api_key = <new> WHERE name = 'administrator';"
```

Then re-run `--limit docker-server`: `docker_server` republishes the fact,
`/etc/iris-mcp.env` is rewritten, and `puc2_keys` re-elects and re-proves it.
Nothing needs editing.

### 2. Rotate the Docker Hub PAT, then move it to vault

```
provisioning/roles/docker_server/tasks/main.yml:146
provisioning/roles/kali/tasks/main.yml:461
```

`dckr_pat_…` in cleartext, on the active path, in both this repo's history and
the upstream `ng-soc-ansible@integrations`.

**It was not migrated here, deliberately.** Removing it from the working tree
does not un-compromise a token that is already in git history and upstream —
only rotation does — while changing the `docker login` path *can* break the
build this work exists to make green: anonymous pulls are rate-limited and this
deployment pulls a lot of images. The order that works is rotate first, then
migrate:

1. revoke `dckr_pat_OzOR…` in Docker Hub, issue a replacement;
2. put it in `group_vars/vault.yml` as `vault_dockerhub_token` and
   `ansible-vault encrypt` it (the file is already git-ignored);
3. replace both literals with `"{{ vault_dockerhub_token }}"`;
4. run a full build to confirm the pulls still authenticate.

Step 1 is what makes the repo safe. Steps 2-4 are what keep it that way.

### 3. Three dead task files still carry both secrets

```
provisioning/roles/docker_server/tasks/debug_main.yml
provisioning/roles/docker_server/tasks/main-old.yml
provisioning/roles/docker_server/tasks/main-with-old-mcp.yml
provisioning/roles/kali/tasks/main-old.yml
```

Nothing includes them — they are superseded copies — and they carry the stale
IRIS key and the Docker Hub PAT. They are **left in place pending a decision**:
deleting files was not something to do unasked. Deleting them is the
recommendation; they are recoverable from git history, which is also why
deleting them is not by itself a remediation for the credentials in them.
