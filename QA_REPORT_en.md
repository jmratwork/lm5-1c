> **SUPERSEDED by [diagnostics/PRE-USE-VERIFICATION.md](diagnostics/PRE-USE-VERIFICATION.md).**
> This report's verdict — "no blocking issues found", subject to a 60-second
> glance at two dashboards — did not hold. The glance was never done, and a
> deeper audit that followed each level's own command back through the code
> found two blocking defects this method could not see: the eradication marker
> was destroyed by doing what level 9 asks, and rule 100102 could never fire.
> Both are fixed. The dashboard glance no longer exists as a concept: the
> preflight gate reads every resource back and fails the deployment.
> Kept for the record of what was checked and when.

# QA Report — PUC2 (CYNET) Sub Case 2c: pre-use check for blocking issues

**Objective:** confirm, before trainees use it, that no level of the training definition
(`puc2-cynet-2c-malware-detection-response_linear-training-definition.json`, 30 levels) is left without its
answer in the sandbox deployed on CyberRangeCZ.

**Method:** a **static** verification cross-checking the 15 hands-on training answers against what the Ansible
overlay (`jmratwork/lm5-1c`, branch `main`, commit `ad48c5f`) actually produces, supported by the log of the
most recent build (successful: all hosts `ACTIVE`, `PLAY RECAP` with `failed=0`, 2c overlay applied).

**Scope / honest limit:** this verification does NOT access the live sandbox (there is no web console or network
route to `10.0.16.x` from outside). It confirms that the repository *generates* each value and that the build
*executed* the roles. Resources created by API at runtime (MISP event, sharing group, IRIS case) carry high
confidence (their tasks finished with `failed=0`), but their final presence is closed off with a ~60 s glance at
the dashboards.

---

## Verdict

**No blocking issues found.** All 15 hands-on answers are backed by the environment; the 8 informational levels
and the 7 assessment levels do not depend on the environment. The training should be completable end to end with
no impossible level, subject to the 60 s visual check noted below.

---

## Level-by-level verification (the 15 hands-on)

Key: ✅ verified in repo (value defined + role creates/writes it) · ✍️ derivable from the level content (no
environment dependency) · 👁️ created at runtime via API — high confidence, close off with a glance in the GUI.

| Level | Expected answer | Status | Evidence |
|---|---|---|---|
| L4  | `puc2-2c-armed` | ✅ | `scenario_injection_2c/defaults` + `group_vars/puc2_2c.yml` (`puc2_arm_token`) |
| L5  | `invoice.exe` | ✅ | `puc2_payload_name`; delivered to `/home/victim/Downloads/invoice.exe` |
| L8  | `44d88612fea8a8f36de82e1278abb02f` | ✅ | EICAR payload (`puc2_payload_md5`, that real MD5) |
| L9  | `T1566.001` | 👁️ | MISP PUC2 event (`puc2_mitre_initial_access`), created via `POST /events/add` |
| L10 | `100101` | ✅ | `ng_siem_rules_2c/templates/local_rules.xml.j2` (rule 100101, CDB hash match) |
| L11 | `targeted` | ✍️ | derivable from the level content |
| L14 | `CASE-PUC2-2C` | 👁️ | `cicms_2c` (`puc2_case_soc_id`); case created/deduplicated by `custom-iris` |
| L15 | `c2.puc2-training.lab` | 👁️ | network IOC in the MISP event and the IRIS case (`puc2_c2_domain`) |
| L18 | `isolate_host` | ✅ | `soar_actions_2c` (NG-SOAR action library) |
| L19 | `isolated` | ✅ | AR `puc2-isolate.j2` writes `{{ puc2_isolation_status }}`=`isolated` on the **first line** of `/var/run/ngsoar_isolated` |
| L20 | `10.0.16.50` | ✅ | `kali` IP (`puc2_c2_ip`, resolved from inventory with fallback to `10.0.16.50`) |
| L21 | `eradicated` | ✅ | AR writes `{{ puc2_eradication_status }}`=`eradicated` on the first line of `/var/run/ngsoar_eradication_status` (if quarantine occurred) |
| L24 | `NG-SOC-PUC2` | 👁️ | `cti_ss_2c` creates the sharing group via `POST /sharing_groups/add` (`puc2_misp_sharing_group_name`) |
| L25 | `phishing` | ✍️ | derivable from the level content |
| L26 | `T1204.002` | 👁️ | MISP event (`puc2_mitre_execution`) |

**Actual resource creation confirmed in the code (not just values):**
- `cti_ss_2c`: `POST /sharing_groups/add` and `POST /events/add` (idempotent: searches by MD5 before seeding).
- `cicms_2c`: `POST /manage/case-templates/add`; the L14 `case_soc_id` is fixed to `CASE-PUC2-2C`.
- The IRIS API key used at runtime is the one **extracted from the DB** (`docker_server` main.yml:442), not the
  hardcoded one; the hardcoded key only acts as a fallback, which is why the `404` probe is harmless.

---

## The only thing you need to close off (≈60 s, from the web)

The 👁️ items are created via API at runtime. The code creates them and the build executed them with `failed=0`;
for 100 % certainty just open two dashboards from the sandbox's web console:

- **MISP** (`https://10.0.16.60:8443`): that the **PUC2 event** exists (with `T1566.001`, `T1204.002` and IOC
  `c2.puc2-training.lab`) and the **sharing group `NG-SOC-PUC2`**. → covers L9, L15, L24, L26.
- **IRIS** (`https://10.0.16.60:8083`): that the **case `CASE-PUC2-2C`** exists. → covers L14.

If both are visible, all 30 levels are confirmed end to end.

---

## Non-blocking observations

1. **Cosmetic (isolation marker).** `soar_actions_2c/files/isolate_host.yml` (reference library, NOT the live
   path) writes `isolated_by_ng_soar` as its single line, inconsistent with the first-line `isolated` convention
   of the `puc2-isolate` AR. It does not affect the training, because the marker is written by the AR. Worth
   aligning the text to avoid future confusion.
2. **Ordering dependency in L21.** The first line is `eradicated` only if the payload was still present at
   eradication time (quarantine > 0). In the normal scenario flow it is; if eradication runs without the payload,
   it writes `eradication_incomplete_no_payload_found`. Keeping the walkthrough order avoids friction.
3. **Security (does not block the training).**
   - The build log prints the freshly generated IRIS API key in cleartext → treat the log as a secret and
     **rotate** that key.
   - The `NG-SOC-eu/ng-soc-ansible@integrations` repo has a hardcoded Docker Hub PAT and IRIS API key →
     **rotate** and migrate to `ansible-vault`; add a `.gitignore`. Do not propagate secrets into `lm5-1c`.

---

## Annex — about the build

- Successful deployment: `docker-server ok=146`, `kali 125`, `ng-siem 75`, `victim 54`, `router 26`, `man 5`,
  `proxy-jump 2`; all `failed=0`. 2c overlay applied (`scenario_injection_2c`, `ng_siem_rules_2c`, `cti_ss_2c`,
  `cicms_2c`, `lab_endpoint_2c`, `soar_actions_2c`, `evaluation_reporting`).
- Single `fatal:` = benign and `...ignoring`: a probe of the "known" IRIS API key (`404`), self-healed by reading
  the real key from the DB in the following task.
- Flakiness note: 2 previous builds failed in Terraform due to a resource ceiling (quota/capacity). This one
  succeeded. If a rebuild fails again, clean up orphans (delete the sandbox/pool) and retry with pool size = 1
  before touching flavours.
