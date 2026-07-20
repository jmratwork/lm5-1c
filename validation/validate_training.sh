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

rules=$(ssh_to "${NGSIEM_IP}" "sudo grep -o 'id=\"1001[0-9][0-9]\"' /var/ossec/etc/rules/local_rules.xml | sort -u | tr -d '\n'")
for rid in 100100 100101 100102 100103; do
    check_contains "L10 rule ${rid} present in local_rules.xml" "${rid}" "${rules}"
done

cdb=$(ssh_to "${NGSIEM_IP}" "sudo grep -c '44d88612fea8a8f36de82e1278abb02f' /var/ossec/etc/lists/cti-malware-hashes")
check "L10 payload hash on the CTI watchlist" "1" "${cdb}"

decoder=$(ssh_to "${NGSIEM_IP}" "sudo grep -c 'puc2-iptables' /var/ossec/etc/decoders/puc2_local_decoder.xml")
if [ "${decoder:-0}" -gt 0 ]; then
    printf '  \033[32m[ OK ]\033[0m %-58s -> firewall decoder present\n' "L11 puc2-iptables decoder"; PASS=$((PASS+1))
else
    printf '  \033[31m[FAIL]\033[0m %-58s absent — rule 100102 can never fire\n' "L11 puc2-iptables decoder"
    FAIL=$((FAIL+1)); FAILURES+=("L11 firewall decoder absent")
fi

sinkhole=$(ssh_to "${VICTIM_IP}" "getent hosts c2.puc2-training.lab | awk '{print \$1}'")
check "L11 C2 domain resolves (sinkhole, pre-containment)" "${C2_IP}" "${sinkhole}"

# ---------------------------------------------------------------------------
echo
echo "-- CTI-SS content (L9, L15, L24, L26) -------------------------------------"

if [ -z "${MISP_KEY:-}" ]; then
    skip "L9/L15/L24/L26 MISP content" "set MISP_KEY=<api key> to check"
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
    skip "L14 IRIS case SOC id" "set IRIS_KEY=<api key> to check"
else
    cases=$(curl -sk -H "Authorization: Bearer ${IRIS_KEY}" -H 'Content-Type: application/json' \
                 --max-time 20 "https://${DOCKER_IP}:8083/manage/cases/list")
    check_contains "L14 IRIS case CASE-PUC2-2C exists" "CASE-PUC2-2C" "${cases}"
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
else
    skip "L19/L21 containment markers" "re-run with --with-attack"
    skip "L5/L11 alert firing"          "re-run with --with-attack"
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
