#!/usr/bin/env bash
# =============================================================================
# validate_training.sh — PUC2 (CYNET) Sub Case 2c
#
# Verifies that every graded answer in
#   puc2-cynet-2c-malware-detection-response_linear-training-definition.json
# is actually obtainable in the built sandbox, so no trainee meets a blocking
# level. Run it from a host that can SSH to the sandbox (typically the
# CyberRangeCZ jump host) AFTER provisioning has finished.
#
#   ./validate_training.sh                 # checks everything except post-attack state
#   ./validate_training.sh --with-attack   # also fires the injection, then checks
#                                          # the containment levels (L19/L21).
#                                          # DESTRUCTIVE: isolates the endpoint.
#
# Exit code 0 only if every check passes. Any FAIL is a potential blocker.
#
# SSH: set SSH_OPTS / SSH_CONFIG for the sandbox key material, e.g.
#   export SSH_CONFIG=~/.ssh/pool-id-*-sandbox-id-*-user-config
# =============================================================================
set -uo pipefail

VICTIM_IP="${VICTIM_IP:-10.0.16.100}"
NGSIEM_IP="${NGSIEM_IP:-10.0.16.70}"
DOCKER_IP="${DOCKER_IP:-10.0.16.60}"
C2_IP="${C2_IP:-10.0.16.50}"
MGMT_USER="${MGMT_USER:-ubuntu}"
SSH_CONFIG="${SSH_CONFIG:-}"
SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes}"
WITH_ATTACK=0
[ "${1:-}" = "--with-attack" ] && WITH_ATTACK=1

PASS=0; FAIL=0; SKIP=0
declare -a FAILURES=()

ssh_to() {  # ssh_to <ip> <command>
    local ip="$1"; shift
    if [ -n "${SSH_CONFIG}" ]; then
        # shellcheck disable=SC2086
        ssh -F "${SSH_CONFIG}" ${SSH_OPTS} "${ip}" "$@" 2>/dev/null
    else
        # shellcheck disable=SC2086
        ssh ${SSH_OPTS} "${MGMT_USER}@${ip}" "$@" 2>/dev/null
    fi
}

# check <level-label> <expected> <actual>
check() {
    local label="$1" expected="$2" actual="$3"
    if [ "${actual}" = "${expected}" ]; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> %s\n' "${label}" "${actual}"
        PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s expected %-28s got %s\n' \
               "${label}" "'${expected}'" "'${actual:-<empty>}'"
        FAIL=$((FAIL+1)); FAILURES+=("${label}: expected '${expected}', got '${actual:-<empty>}'")
    fi
}

# check_contains <level-label> <needle> <haystack>
check_contains() {
    local label="$1" needle="$2" hay="$3"
    if printf '%s' "${hay}" | grep -qF -- "${needle}"; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> contains %s\n' "${label}" "${needle}"
        PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s missing %s\n' "${label}" "${needle}"
        FAIL=$((FAIL+1)); FAILURES+=("${label}: missing '${needle}'")
    fi
}

skip() {
    printf '  \033[33m[SKIP]\033[0m %-58s %s\n' "$1" "$2"
    SKIP=$((SKIP+1))
}

echo "==========================================================================="
echo " PUC2 2c — training answerability check"
echo "==========================================================================="

# ---------------------------------------------------------------------------
echo
echo "-- Infrastructure: the six VMs respond ------------------------------------"
for host_spec in "victim:${VICTIM_IP}" "ng-siem:${NGSIEM_IP}" "docker-server:${DOCKER_IP}" "kali:${C2_IP}"; do
    name="${host_spec%%:*}"; ip="${host_spec##*:}"
    if ssh_to "${ip}" true >/dev/null 2>&1; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> reachable\n' "${name} (${ip})"; PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s unreachable over SSH\n' "${name} (${ip})"
        FAIL=$((FAIL+1)); FAILURES+=("${name} (${ip}) unreachable")
    fi
done

echo
echo "-- SOC services are up ----------------------------------------------------"
svc_check() {  # svc_check <label> <url>
    local label="$1" url="$2" code
    code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 15 "${url}" 2>/dev/null || echo 000)
    if [ "${code}" != "000" ]; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> HTTP %s\n' "${label}" "${code}"; PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s no response\n' "${label}"
        FAIL=$((FAIL+1)); FAILURES+=("${label} not responding")
    fi
}
svc_check "NG-SIEM (Wazuh)   https://${NGSIEM_IP}"        "https://${NGSIEM_IP}"
svc_check "CTI-SS  (MISP)    https://${DOCKER_IP}:8443"   "https://${DOCKER_IP}:8443"
svc_check "CICMS   (IRIS)    https://${DOCKER_IP}:8083"   "https://${DOCKER_IP}:8083"
svc_check "NG-SOAR           http://${DOCKER_IP}:8080"    "http://${DOCKER_IP}:8080"

# ---------------------------------------------------------------------------
echo
echo "-- Phase 1: kickoff (L4, L5) ---------------------------------------------"

arm_out=$(ssh_to "${VICTIM_IP}" "sudo /opt/puc2/inject_scenario.sh --arm")
token=$(printf '%s' "${arm_out}" | sed -n 's/.*token=\([A-Za-z0-9-]*\).*/\1/p' | head -n1)
check "L4  arm token" "puc2-2c-armed" "${token}"
if [ -z "${token}" ]; then
    echo "        --arm output was:"; printf '%s\n' "${arm_out}" | sed 's/^/        /'
fi

mail_href=$(ssh_to "${VICTIM_IP}" "sudo grep -io 'href=\"[^\"]*\"' /var/mail/victim | head -n1")
check_contains "L5  phishing mail carries an href in /var/mail/victim" "href=" "${mail_href}"
check_contains "L5  payload file name in the lure" "invoice.exe" "${mail_href}"

# ---------------------------------------------------------------------------
echo
echo "-- Phase 2: detection (L8, L9, L10, L11) ----------------------------------"

staged_md5=$(ssh_to "${VICTIM_IP}" "sudo md5sum /opt/puc2/invoice.exe | cut -d' ' -f1")
check "L8  payload MD5" "44d88612fea8a8f36de82e1278abb02f" "${staged_md5}"

# The active response must fire on the CORRELATION rule only. With 100101 in the
# trigger set, containment interrupts the delivery and rule 100102 never fires.
ar_rules=$(ssh_to "${NGSIEM_IP}" "sudo sed -n '/PUC2-2C DETECTION AND RESPONSE/,/END ANSIBLE/p' /var/ossec/etc/ossec.conf | sed -n 's:.*<rules_id>\(.*\)</rules_id>.*:\1:p' | tr -d ' '")
check "L18 active response triggers on 100103 only" "100103" "${ar_rules}"

rules=$(ssh_to "${NGSIEM_IP}" "sudo grep -o 'id=\"1001[0-9][0-9]\"' /var/ossec/ruleset/rules/9999-puc2-2c.xml | sort -u | tr -d '\n'")
for rid in 100100 100101 100102 100103; do
    check_contains "L10 rule ${rid} present in 9999-puc2-2c.xml" "${rid}" "${rules}"
done

cdb=$(ssh_to "${NGSIEM_IP}" "sudo grep -c '44d88612fea8a8f36de82e1278abb02f' /var/ossec/etc/lists/cti-malware-hashes")
check "L10 payload hash on the CTI watchlist" "1" "${cdb}"

# Ask analysisd to decode a line shaped exactly like the one the endpoint's
# iptables LOG+DROP rule writes, and report the rule it matched. This replaced a
# check that grepped a custom decoder file for its own name: that file passed on
# every run while being unreachable — analysisd never consults a prematch-only
# decoder for an event carrying a program_name — so it proved nothing about
# whether 100102 can fire. Only a live match does.
PROBE_LINE="Jul 22 08:24:29 victim kernel: [12345.678901] PUC2-FW-DROP: IN= OUT=ens4 SRC=${VICTIM_IP} DST=${C2_IP} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=54321 DPT=4444 WINDOW=64240 RES=0x00 SYN URGP=0"
probe=$(ssh_to "${NGSIEM_IP}" "printf '%s\n' '${PROBE_LINE}' | sudo /var/ossec/bin/wazuh-logtest -v 2>&1")
if printf '%s' "${probe}" | grep -q "100102"; then
    printf '  \033[32m[ OK ]\033[0m %-58s -> analysisd matched rule 100102\n' "L11 blocked-C2 line fires rule 100102"; PASS=$((PASS+1))
else
    matched=$(printf '%s' "${probe}" | sed -n "s/.*id: '\([0-9]*\)'.*/\1/p" | tail -1)
    printf '  \033[31m[FAIL]\033[0m %-58s matched rule %s — 100102 never fires\n' \
        "L11 blocked-C2 line fires rule 100102" "${matched:-none}"
    FAIL=$((FAIL+1)); FAILURES+=("L11 firewall line does not reach rule 100102 (matched ${matched:-none})")
fi

sinkhole=$(ssh_to "${VICTIM_IP}" "getent hosts c2.puc2-training.lab | awk '{print \$1}'")
check "L11 C2 domain resolves (sinkhole, pre-containment)" "${C2_IP}" "${sinkhole}"

# ---------------------------------------------------------------------------
echo
echo "-- CTI-SS content (L9, L15, L24, L26) -------------------------------------"

# Resolve the keys from the sandbox itself rather than asking an operator to
# export them. A check that is skipped by default is a check that reports "no
# blockers found" while never having looked — which is how the MISP and IRIS
# content went unverified through two builds. Same sources the puc2_keys role
# uses: the credential files docker_server writes, and the IRIS database.
if [ -z "${MISP_KEY:-}" ]; then
    MISP_KEY=$(ssh_to "${DOCKER_IP}" \
        "sudo sed -n 's/^MISP_API_KEY=//p' /etc/misp-mcp.env" | tr -d '\r')
fi
if [ -z "${IRIS_KEY:-}" ]; then
    IRIS_KEY=$(ssh_to "${DOCKER_IP}" \
        "sudo docker exec iris_db psql -U postgres -d iris_db -t -A -c \
         \"SELECT api_key FROM \\\"user\\\" WHERE name = 'administrator' LIMIT 1;\"" | tr -d '\r')
fi

if [ -z "${MISP_KEY:-}" ]; then
    skip "L9/L15/L24/L26 MISP content" \
         "could not read MISP_API_KEY from /etc/misp-mcp.env on ${DOCKER_IP}"
else
    misp() { curl -sk -H "Authorization: ${MISP_KEY}" -H 'Accept: application/json' \
                  -H 'Content-Type: application/json' --max-time 20 "$@"; }
    event=$(misp -X POST "https://${DOCKER_IP}:8443/events/restSearch" \
                 --data '{"value":"44d88612fea8a8f36de82e1278abb02f","returnFormat":"json"}')
    check_contains "L9  MISP tags initial access T1566.001"  "T1566.001"            "${event}"
    check_contains "L26 MISP tags execution T1204.002"       "T1204.002"            "${event}"
    check_contains "L15 MISP holds the C2 domain IOC"        "c2.puc2-training.lab" "${event}"
    check_contains "L20 MISP holds the C2 address IOC"       "${C2_IP}"             "${event}"
    groups=$(misp "https://${DOCKER_IP}:8443/sharing_groups/index")
    check_contains "L24 MISP sharing group NG-SOC-PUC2"      "NG-SOC-PUC2"          "${groups}"
fi

# ---------------------------------------------------------------------------
echo
echo "-- CICMS content (L14) ----------------------------------------------------"

if [ -z "${IRIS_KEY:-}" ]; then
    skip "L14 IRIS case SOC id" \
         "could not read the api_key column from the iris_db container on ${DOCKER_IP}"
else
    cases=$(curl -sk -H "Authorization: Bearer ${IRIS_KEY}" -H 'Content-Type: application/json' \
                 --max-time 20 "https://${DOCKER_IP}:8083/manage/cases/list")
    # Matched on the case_soc_id FIELD, not as a substring of the whole list:
    # the id appearing in some other case's description is not this case.
    soc_hit=$(printf '%s' "${cases}" \
        | tr ',' '\n' | grep -c '"case_soc_id"[[:space:]]*:[[:space:]]*"CASE-PUC2-2C"' || true)
    if [ "${soc_hit}" -gt 0 ]; then
        check "L14 IRIS case CASE-PUC2-2C (by case_soc_id)" "1" "1"
    elif printf '%s' "${cases}" | grep -q 'case_soc_id'; then
        check "L14 IRIS case CASE-PUC2-2C (by case_soc_id)" "1" "0"
    else
        # This IRIS build's list endpoint does not return the SOC id at all, so
        # absence here proves nothing. The playbook gate reads each case to
        # settle it; say so rather than reporting a pass or a failure.
        skip "L14 IRIS case SOC id" \
             "/manage/cases/list on this build does not return case_soc_id — \
run: ansible-playbook provisioning/playbook.yml --tags puc2_diag --limit docker-server"
    fi
fi

# ---------------------------------------------------------------------------
echo
echo "-- Phase 4: response library (L18) ----------------------------------------"

books=$(ssh_to "${DOCKER_IP}" "ls /opt/NG-SOAR/playbooks/ 2>/dev/null | tr '\n' ' '")
for pb in isolate_host block_malicious_ip reset_credentials quarantine_and_patch; do
    check_contains "L18 playbook ${pb}.yml in the NG-SOAR library" "${pb}.yml" "${books}"
done

ar=$(ssh_to "${VICTIM_IP}" "test -x /var/ossec/active-response/bin/puc2-isolate && echo yes || echo no")
check "L19 active response puc2-isolate deployed" "yes" "${ar}"

# ---------------------------------------------------------------------------
echo
echo "-- Phase 4: containment state (L19, L21) ----------------------------------"

if [ "${WITH_ATTACK}" -eq 1 ]; then
    echo "  firing the injection (this isolates the endpoint) ..."
    ssh_to "${VICTIM_IP}" "sudo /opt/puc2/inject_scenario.sh" >/dev/null 2>&1
    echo "  waiting 120s for the detection chain and active response ..."
    sleep 120
    iso=$(ssh_to "${VICTIM_IP}" "sudo head -n1 /var/run/ngsoar_isolated")
    era=$(ssh_to "${VICTIM_IP}" "sudo head -n1 /var/run/ngsoar_eradication_status")
    check "L19 /var/run/ngsoar_isolated first line"            "isolated"   "${iso}"
    check "L21 /var/run/ngsoar_eradication_status first line"  "eradicated" "${era}"
    alerts=$(ssh_to "${NGSIEM_IP}" "sudo grep -c '\"id\":\"100101\"' /var/ossec/logs/alerts/alerts.json")
    if [ "${alerts:-0}" -ge 1 ]; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> %s alert(s)\n' "L5  rule 100101 fired" "${alerts}"; PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s no 100101 alerts\n' "L5  rule 100101 fired"
        FAIL=$((FAIL+1)); FAILURES+=("rule 100101 never fired")
    fi
    corr=$(ssh_to "${NGSIEM_IP}" "sudo grep -c '\"id\":\"100103\"' /var/ossec/logs/alerts/alerts.json")
    if [ "${corr:-0}" -ge 1 ]; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> %s alert(s)\n' "L11 rule 100103 correlation fired" "${corr}"; PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s no 100103 alerts\n' "L11 rule 100103 correlation fired"
        FAIL=$((FAIL+1)); FAILURES+=("rule 100103 never fired — L11 unanswerable")
    fi

    # L12 asks the analyst to correlate the blocked C2 beacon. If containment
    # ran before the beacon stage, the sinkhole is already 0.0.0.0 and this
    # alert never exists — exactly the regression the 100103-only trigger fixes.
    c2fw=$(ssh_to "${NGSIEM_IP}" "sudo grep -c '\"id\":\"100102\"' /var/ossec/logs/alerts/alerts.json")
    if [ "${c2fw:-0}" -ge 1 ]; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> %s alert(s)\n' "L12 rule 100102 blocked-C2 fired" "${c2fw}"; PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s no 100102 alerts\n' "L12 rule 100102 blocked-C2 fired"
        FAIL=$((FAIL+1)); FAILURES+=("rule 100102 never fired — L12 has no correlation evidence")
    fi

    # The trainee must be able to come BACK to the endpoint after containment to
    # read the markers (L20, L22). This is a fresh connection, so it exercises
    # the admin channel the isolation action preserves.
    if ssh_to "${VICTIM_IP}" true >/dev/null 2>&1; then
        printf '  \033[32m[ OK ]\033[0m %-58s -> reachable\n' "L20 victim still reachable AFTER containment"; PASS=$((PASS+1))
    else
        printf '  \033[31m[FAIL]\033[0m %-58s isolation cut the admin channel\n' "L20 victim still reachable AFTER containment"
        FAIL=$((FAIL+1)); FAILURES+=("victim unreachable after containment — L20/L22 unanswerable over SSH")
    fi

    # L22 sends the trainee to the quarantine directory; make sure the artefact
    # is really there and readable with sudo.
    quar=$(ssh_to "${VICTIM_IP}" "sudo md5sum /var/quarantine/invoice.exe 2>/dev/null | cut -d' ' -f1")
    check "L22 quarantined payload readable" "44d88612fea8a8f36de82e1278abb02f" "${quar}"
else
    skip "L19/L21 containment markers"  "re-run with --with-attack"
    skip "L5/L11/L12 alert firing"      "re-run with --with-attack"
    skip "L20 post-containment access"  "re-run with --with-attack"
    skip "L22 quarantined payload"      "re-run with --with-attack"
fi

# ---------------------------------------------------------------------------
echo
echo "==========================================================================="
printf ' PASS %d   FAIL %d   SKIP %d\n' "${PASS}" "${FAIL}" "${SKIP}"
echo "==========================================================================="
if [ "${FAIL}" -gt 0 ]; then
    echo
    echo "Blocking issues — a trainee would be stuck on these levels:"
    printf '  - %s\n' "${FAILURES[@]}"
    echo
    echo "Fix the OVERLAY so the environment emits the value; only adjust the"
    echo "training JSON if the value genuinely cannot be produced."
    exit 1
fi
echo "All checked levels are answerable."
exit 0
