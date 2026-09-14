# NG-SIEM Correlation Guide - PUC2 Sub Case 2c

Use this guide on the Wazuh (NG-SIEM) dashboard to work UML steps 3-6.

The dashboard starts **empty of PUC2 alerts**: the deployment fires the scenario
once to prove it, then removes its own alerts. Everything you find here comes from
the attack fired in this session.

## 1. Telemetry ingestion (UML step 3)
The endpoint runs the Wazuh agent enrolled by the substrate `victim` role;
file-integrity monitoring on `/home/victim/Downloads` and `/tmp` (added by role
`lab_endpoint_2c`) emits **file-hash** events the moment the payload lands.

- Dashboard → *Agents* → confirm the endpoint agent is **Active**. It is named
  after the sandbox allocation (`victim<id>`, e.g. `victim617`), not `victim`, and
  it may show a management-network address rather than 10.0.16.100.
- *Security events* → filter `syscheck.path: "/home/victim/Downloads/*"`.

## 2. CTI enrichment (UML step 4)
The observed hash is checked against the CTI-SS (MISP) IOC list (`cti-malware-hashes`).
A match raises **rule 100101** (level 12) — *file hash matches CTI-SS malware IOC*.

- Filter `rule.id: 100101`.
- Pivot the hash into MISP (CTI-SS) for malware family + TTPs.

## 3. Malware-detected alert (UML step 5)
Rules fire in this chain:

| Rule | Level | Meaning |
|------|-------|---------|
| 100100 | 8 | Suspicious payload file created |
| 100101 | 12 | Hash matches CTI IOC → **MALWARE DETECTED** |
| 100102 | 10 | Blocked outbound C2/exfil (from the endpoint's egress filter) |
| 100103 | 14 | **Targeted attack confirmed** (payload + IOC + C2) |

The level-12/14 alerts are what notify the SOC Analyst.

## 4. Log correlation & confirmation (UML step 6)
Build the holistic view across sources:

1. *Security events* → group by `agent.name` to see all affected endpoints.
2. Correlate FIM (payload) + firewall drops (rule 100102) + the campaign window.
   The firewall source is real: the endpoint carries a pre-staged iptables
   LOG+DROP rule for tcp/4444, its `kern.log` is ingested by the agent, and
   Wazuh's built-in kernel decoder parses it into the `firewall` group with
   `srcip`, `dstip`, `srcport`, `dstport` and `protocol` populated. Filter
   `rule.id: 100102` to see the payload's blocked C2 beacon.
3. The delivery is multi-stage, so **rule 100101 fires three times**; that
   repetition inside 600 s is exactly what rule 100103 correlates.
4. When **rule 100103** fires, the attack is confirmed as **targeted** — attach this
   view to the CICMS case (step 7).

## 5. Automated containment (UML steps 9-11)
Only rule **100103** is wired to the `puc2-isolate` active response, which runs
on the affected agent (`location=local`). Rule 100101 fires on the first payload
drop, seconds into a delivery that takes about a minute; containing there would
sinkhole the C2 before the beacon stage, and rule 100102 could never fire.
Containment follows the *targeted attack confirmed* verdict instead. After it
fires:

- *Security events* → the agent keeps reporting: isolation deliberately keeps
  `10.0.16.0/24` reachable so telemetry survives containment.
- On the endpoint, `/var/run/ngsoar_isolated` and
  `/var/run/ngsoar_eradication_status` carry the step-11 status, and
  `/var/ossec/logs/active-responses.log` carries the audit trail.

## UEBA / advanced detections
UEBA, APT detection, exfiltration prevention and phishing detection described in the
scenario are represented by the rule chain + FIM above. Capabilities not natively
present are listed as *simulated / out of scope* in `VALIDATION.md`.
