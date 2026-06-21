# PUC2 Sub Case 2c - Training Evaluation & Lessons Learned (UML step 13)

**Exercise:** Malware Attack Detection & Response Training
**Date:** ____________  **Trainees:** ____________

## Response timeline (fill from NG-SIEM / CICMS timestamps)
| UML step | Action | Expected | Actual time | Score (0-5) |
|----------|--------|----------|-------------|-------------|
| 3-5 | Telemetry -> NG-SIEM alert | < 5 min from payload exec | | |
| 6 | Log correlation / attack confirmed | < 15 min | | |
| 7-8 | CICMS case opened + CTI enrichment | < 20 min | | |
| 9-11 | NG-SOAR containment + eradication | < 30 min | | |
| 12 | Intel shared via CTI-SS | same day | | |

## Detection effectiveness
- [ ] Phishing payload detected (FIM / rule 100100)
- [ ] Hash matched against CTI IOC (rule 100101)
- [ ] C2/exfil attempt blocked (rule 100102)
- [ ] Targeted-attack correlation fired (rule 100103)

## Response effectiveness
- [ ] Host isolated (NG-SOAR isolate_host)
- [ ] Malicious IP/domain blocked
- [ ] Credentials reset
- [ ] Endpoint quarantined + patched
- [ ] Containment status reported to analyst

## Entry point / root cause
_____________________________________________

## Improvement recommendations
_____________________________________________
