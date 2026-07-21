# Pre-use verification — can a trainee complete all 30 levels?

**Method.** For each graded level I followed the command the level text actually
tells the trainee to run, back through the code that produces its answer, and
asked whether that command returns that answer. Not "the value is defined
somewhere" — the mechanism.

**Verdict: two blocking defects found. Both fixed. Neither was visible to any
check that existed before, including the preflight gate.**

## The two blockers

### 1. Level 11 (`eradicated`) is destroyed by following level 9

`puc2-isolate` derived the eradication status from how many files *this run*
moved:

```bash
$([ "${QUARANTINED}" -gt 0 ] && echo "eradicated" || echo "eradication_incomplete_no_payload_found")
```

Containment runs more than once by design. Level 9 tells the trainee to fire it
again — `sudo /opt/NG-SOAR/playbooks/ngsoar_trigger.sh isolate_host 10.0.16.100`
— and the Phase 4 text promises that "running containment when the host is
already contained is safe and idempotent". Rule 100103 can also match again.

On that second run there is nothing left to move, `QUARANTINED` is 0, and the
marker is **rewritten** to `eradication_incomplete_no_payload_found`. Level 11
grades the first line of that file as `eradicated`. The trainee does exactly
what level 9 asks and loses the answer to level 11, permanently — there is no
way back short of re-running the injection.

Reproduced by executing the marker logic twice:

```
SHIPPED 1st run: eradicated
SHIPPED 2nd run: eradication_incomplete_no_payload_found   <-- answer lost
FIXED   1st run: eradicated
FIXED   2nd run: eradicated
```

**Fix.** Eradication is a state, not an event: the status is now derived from
whether the payload is *held* in `/var/quarantine`, whoever put it there. The
`incomplete` value survives for the one case where it is honest — the injection
never ran. The preflight gate now asserts the deployed action carries this
logic, so it cannot regress.

### 2. Rule 100102 could never fire, under any circumstances

Wazuh tries sibling child decoders **in order and stops at the first match**.
The firewall telemetry was split across two of them:

```xml
<decoder name="puc2-iptables-addresses">  ... <order>srcip,dstip</order>
<decoder name="puc2-iptables-ports">      ... <order>protocol,srcport,dstport</order>
```

`-addresses` always matched first, so `-ports` never ran and `dstport` was never
populated — and rule 100102 required `<field name="dstport">`. The rule was
unreachable. Every other check passed it, because the rule *exists* in
`local_rules.xml`; existence was all anyone verified.

Cost: level 6 (`targeted`) sends the trainee to "the blocked outbound attempt to
the C2 host (rule 100102)", and the correlation evidence for UML step 6 is not
there. The level survives on its documented `grep PUC2-FW-DROP /var/log/kern.log`
fallback and on the answer being conceptual — which is why this reads as
degraded rather than fatal — but the primary evidence path the level describes
was dead.

**Fix.** One child decoder extracting all five fields, verified against a real
`iptables` LOG line (`srcip`, `dstip`, `protocol`, `srcport`, `dstport` all
captured). Rule 100102 no longer depends on field extraction at all: the
endpoint's LOG rule carries the `PUC2-FW-DROP` prefix on tcp/4444 and nothing
else, so every line the decoder sees *is* a blocked C2 beacon and the port test
added no selectivity.

## Level-by-level

| Level | Answer | Mechanism verified |
|---|---|---|
| L4 | `puc2-2c-armed` | `--arm` prints `SCENARIO ARMED: token=puc2-2c-armed` only after 8 readiness checks pass; any `[FAIL]` exits non-zero |
| L5 | `invoice.exe` | lure has `<a href="…/invoice.exe">invoice.exe</a>` written to `/var/mail/victim`; gate now checks the rendered mail, not just that the spool is non-empty |
| L8 | `44d886…b02f` | payload generated from the EICAR string, hash **checked against the IOC at provision time with a hard fail**; `/opt/puc2/invoice.exe` is *not* in the quarantine sweep, so the level's "always present" fallback holds |
| L9 | `T1566.001` | tag on the MISP event; read back live by the gate |
| L10 | `100101` | 100100 (`if_sid 550,554` + `.exe`) → 100101 (`md5_after` in the CDB list); FIM is `realtime="yes" check_all="yes"` on both drop directories, so events arrive in seconds |
| L11 | `targeted` | conceptual; evidence = 100103 + 100102 — **100102 was dead, now fixed** |
| L14 | `CASE-PUC2-2C` | case matched on its `case_soc_id` field |
| L15 | `c2.puc2-training.lab` | domain IOC on the event |
| L18 | `isolate_host` | 4 playbooks + `ngsoar_trigger.sh` present and executable |
| L19 | `isolated` | first line written unconditionally; `<timeout_allowed>no</timeout_allowed>` and no `<timeout>`, so Wazuh never issues the rollback that would delete the marker |
| L20 | `10.0.16.50` | IOC on the event **and** the range's resolved C2 must equal the literal the level grades |
| L21 | `eradicated` | **was blocker 1** |
| L24 | `NG-SOC-PUC2` | sharing group live; event published at provision time; `share_intel.sh` re-publishes idempotently |
| L25 | `phishing` | conceptual |
| L26 | `T1204.002` | tag on the event |

The detection chain has margin: the injection drops three payloads, so 100101
fires three times against `frequency="2"` on 100103. Containment fires after the
delivery completes, not during it, so the C2 beacon reaches the egress filter
before isolation — which is what keeps L11's evidence alive.

After containment: the sandbox subnet stays reachable so the Wazuh agent keeps
reporting, and tcp/22 is explicitly preserved so a *new* SSH session still works
and L19/L21 remain answerable from the console.

## What this verification does not establish

It is a code audit. It cannot tell you that MISP and DFIR-IRIS behave as their
API docs say, that `/manage/cases/list` returns `case_soc_id` on this build, or
that the elected keys authenticate. Those are live questions.

The reason that is acceptable: **every one of them now fails the build rather
than the trainee.** If an assumption here is wrong, the deployment stops with a
message naming the level and the HTTP status. The failure mode points at the
operator, which is the whole design.

Run it, and if the build goes green the range is ready:

```bash
ansible-playbook provisioning/playbook.yml
```

For the two runtime behaviours no provisioning-time check can reach — that the
rules actually fire and the markers actually get written — fire the scenario
once on a throwaway sandbox:

```bash
./validation/validate_training.sh --with-attack   # DESTRUCTIVE: isolates the endpoint
```

That is the only check that exercises 100101/100102/100103 firing and the
post-containment markers. It is worth one disposable sandbox before a cohort.
