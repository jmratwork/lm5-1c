# NG-SIEM Correlation Guide - PUC2 Sub Case 2c

Use this guide on the Wazuh (NG-SIEM) dashboard to work UML steps 3-6.

## 1. Telemetry ingestion (UML step 3)
Endpoints run the Wazuh agent (role `lab_endpoint`). File-integrity monitoring on
`/home/victim/Downloads` and `/tmp` emits **file-hash** events the moment the
payload lands.

- Dashboard → *Agents* → confirm `endpoint-1` / `endpoint-2` are **Active**.
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
| 100102 | 10 | Blocked outbound C2/exfil |
| 100103 | 14 | **Targeted attack confirmed** (payload + IOC + C2) |

The level-12/14 alerts are what notify the SOC Analyst.

## 4. Log correlation & confirmation (UML step 6)
Build the holistic view across sources:

1. *Security events* → group by `agent.name` to see all affected endpoints.
2. Correlate FIM (payload) + firewall drops (rule 100102) + the campaign window.
3. When **rule 100103** fires, the attack is confirmed as **targeted** — attach this
   view to the CICMS case (step 7).

## UEBA / advanced detections
UEBA, APT detection, exfiltration prevention and phishing detection described in the
scenario are represented by the rule chain + FIM above. Capabilities not natively
present are listed as *simulated / out of scope* in `VALIDATION.md`.
