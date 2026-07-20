# Training definition vs. what the sandbox actually produces

Source: `puc2-cynet-2c-malware-detection-response_linear-training-definition.json`
(30 levels, 15 of them `TRAINING_LEVEL` with a graded `answer`).

Checked statically against the overlay on `main` (commit `82a890d`). **No level
was executed** — the sandbox has never built successfully — so every "OK" below
means "the overlay is written to emit this value", not "observed".

## Summary

| Verdict | Count |
|---|---|
| OK as-is | 6 |
| Fixable in the overlay (the stated preference) | 8 |
| **Architectural conflict — needs a decision** | 1 |

## Per-level detail

| Level | Expected answer | What the repo produces | Verdict |
|---|---|---|---|
| L4 `order 4` | `puc2-2c-armed` from `/opt/puc2/inject_scenario.sh --arm` | script lives at `/opt/scenario-injection/inject_scenario.sh`, has **no `--arm` mode** and prints **no token** | **FIX overlay** — add `--arm`, print `token=puc2-2c-armed`, move root to `/opt/puc2` |
| L5 `order 5` | `invoice.exe` | `puc2_payload_name: invoice.exe` ✔ — but the level tells the trainee to read `/var/mail/victim` and fetch from `http://10.0.16.50:8000/`; the email is at `/home/victim/phishing_email.eml` and **no web server exists** | **FIX overlay** (mail spool) + see conflict below |
| L8 `order 8` | `44d88612fea8a8f36de82e1278abb02f` | identical, and guarded by a provisioning assertion | OK |
| L9 `order 9` | `T1566.001` | MISP event tags `"Phishing - T1566"` — **the sub-technique is absent** | **FIX overlay** |
| L10 `order 10` | `100101` | rule 100101 is the CTI hash match | OK |
| L11 `order 11` | `targeted` | content-derivable; but the level hangs it on a connection to **`c2.puc2-training.lab`**, and the beacon targets the **IP** `10.0.16.50`, with the domain never resolving pre-containment | **FIX overlay** — sinkhole the domain so a real name-based attempt is observable |
| L14 `order 14` | `CASE-PUC2-2C` | the substrate's `custom-iris` builds `case_soc_id = WAZUH-{rule}-{ip}-{user}-{sha256}`; `open_case.sh` builds `PUC2-2C-OPERATOR-<timestamp>` | **FIX overlay** — `cicms_2c` must pre-create/normalise a case with this exact SOC id. **`custom-iris` is a substrate file and must not be edited** |
| L15 `order 15` | `c2.puc2-training.lab` | present as a MISP domain IOC | OK |
| L18 `order 18` | `isolate_host` | playbook named `isolate_host.yml` | OK |
| L19 `order 19` | `isolated` in `/var/run/ngsoar_isolated` | file's first line is `isolated_by=ng_soar/puc2-isolate` — `cat` does not show `isolated` | **FIX overlay** — make the first line exactly `isolated` |
| L20 `order 20` | `10.0.16.50` | `puc2_c2_ip: 10.0.16.50` | OK |
| L21 `order 21` | `eradicated` in `/var/run/ngsoar_eradication_status` | writes `status=eradicated`, **and falls back to `isolated_no_payload_found`** when nothing was quarantined | **FIX overlay** — first line exactly `eradicated`; make the quarantine path deterministic |
| L24 `order 24` | `NG-SOC-PUC2` | sharing group is `PUC2-CYNET-Training` | **FIX overlay** — rename |
| L25 `order 25` | `phishing` | content-derivable | OK |
| L26 `order 26` | `T1204.002` | MISP tags `"User Execution - T1204"` — sub-technique absent | **FIX overlay** |

### Assessment levels with graded answers

| Level | Item | Status |
|---|---|---|
| `order 6` | "From which host was the payload served? → 10.0.16.50" | **conflict** (below) |
| `order 12` | rule id `100101` | OK |
| `order 27` | MD5, C2 domain | OK |
| `order 27` | EMI "Kali → Malware delivery" | **conflict** (below) |

## The one thing I cannot fix in the overlay

**The training definition assumes an architecture this repo deliberately
removed.**

Levels `order 5`, `order 6` and `order 27` state that the payload is *served
from Kali at `http://10.0.16.50:8000/`* and map **Kali → malware delivery**.
Commit `82a890d` (F9) deleted exactly that: the Python `http.server` on `kali`
was a software component present in neither the UML diagram nor the
`integrations` substrate, and it was removed on your instruction that the
scenario employ only UML components. The Cyber Range now injects directly onto
the endpoint, and `10.0.16.50` survives solely as a simulated C2 IOC.

So the two documents disagree about what the range *is*:

| | Training definition | Repo after F9 |
|---|---|---|
| Payload origin | Kali web server `:8000` | Cyber Range → endpoint |
| Kali's role | attacker / delivery host | provisioned by the substrate, **unused** |
| UML compliance | introduces a non-UML component | exact UML component set |

I cannot satisfy both. The options:

- **A — keep F9, amend the three levels.** Reword `order 5`/`order 6` around
  the Cyber Range injection and change the `order 27` EMI so "malware delivery"
  maps to the Cyber Range rather than Kali. Keeps the UML rule intact. Costs
  three edits to the JSON, against your stated preference for fixing the
  overlay instead.
- **B — revert F9's delivery channel.** Reinstate the payload server on Kali so
  every level works verbatim. Costs the UML component rule, which would need to
  be relaxed and the README's "Component scope rule" rewritten.

Everything else in this document is overlay work and needs no decision.
