#!/usr/bin/env bash
# ============================================================
#  SIEMForge — SIEM Detection Rule Builder
#  Author  : Dinesh Patel
#  GitHub  : github.com/dinesh8123/SIEMForge
#  Version : 2.0.0
# ============================================================

set -euo pipefail
export TERM="${TERM:-xterm}"

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m';    GREEN='\033[0;32m';  YELLOW='\033[1;33m'
BLUE='\033[0;34m';   CYAN='\033[0;36m';   BOLD='\033[1m'
DIM='\033[2m';       WHITE='\033[1;37m';   RESET='\033[0m'

# ── Directories ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="$SCRIPT_DIR/rules"
OUTPUT_DIR="$SCRIPT_DIR/output"
LIBRARY_DIR="$SCRIPT_DIR/rule_library"
LOG_FILE="$SCRIPT_DIR/siemforge.log"

mkdir -p "$RULES_DIR" "$OUTPUT_DIR" "$LIBRARY_DIR"

# ── Logger ───────────────────────────────────────────────────
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

# ── MITRE ATT&CK Tactic Registry ─────────────────────────────
declare -A TACTIC_MAP=(
  ["TA0001"]="Initial Access"       ["TA0002"]="Execution"
  ["TA0003"]="Persistence"          ["TA0004"]="Privilege Escalation"
  ["TA0005"]="Defense Evasion"      ["TA0006"]="Credential Access"
  ["TA0007"]="Discovery"            ["TA0008"]="Lateral Movement"
  ["TA0009"]="Collection"           ["TA0010"]="Exfiltration"
  ["TA0011"]="Command and Control"  ["TA0040"]="Impact"
)

# ── CVSS Helpers ─────────────────────────────────────────────
cvss_label() {
  local s=$1
  (( $(echo "$s >= 9.0" | bc -l) )) && { echo "CRITICAL"; return; }
  (( $(echo "$s >= 7.0" | bc -l) )) && { echo "HIGH";     return; }
  (( $(echo "$s >= 4.0" | bc -l) )) && { echo "MEDIUM";   return; }
  echo "LOW"
}

sev_color() {
  case "$1" in
    CRITICAL) printf '%s' "${RED}${BOLD}"    ;;
    HIGH)     printf '%s' "${YELLOW}${BOLD}" ;;
    MEDIUM)   printf '%s' "${CYAN}"          ;;
    *)        printf '%s' "${GREEN}"         ;;
  esac
}

# ── Banner ───────────────────────────────────────────────────
banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  echo "   ██████╗██╗███████╗███╗   ███╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗"
  echo "  ██╔════╝██║██╔════╝████╗ ████║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝"
  echo "  ╚█████╗ ██║█████╗  ██╔████╔██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  "
  echo "   ╚═══██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  "
  echo "  ██████╔╝██║███████╗██║ ╚═╝ ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗"
  echo "  ╚═════╝ ╚═╝╚══════╝╚═╝     ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
  echo -e "${RESET}"
  echo -e "  ${WHITE}${BOLD}     SIEM Detection Rule Builder v2.0.0  —  by Dinesh Patel${RESET}"
  echo -e "  ${DIM}     github.com/dinesh8123/SIEMForge${RESET}"
  echo -e "  ${CYAN}  ═══════════════════════════════════════════════════════════════════${RESET}\n"
}

pause() { printf "\n  ${DIM}Press [Enter] to continue...${RESET}"; read -r; }

hr() { echo -e "  ${DIM}───────────────────────────────────────────────────────────────────${RESET}"; }

# ════════════════════════════════════════════════════════════
#  RULE LIBRARY  — 50+ MITRE ATT&CK Mapped Rules
# ════════════════════════════════════════════════════════════
LIBRARY_RULES=(
  # fname | title | tactic | technique | logsource | field | op | value | cvss | fp | description
  "brute_force_rdp|RDP Brute Force Attempt|TA0006|T1110|windows_event_log|EventID|equals|4625|7.5|3|Multiple failed RDP login attempts from single source"
  "powershell_encoded|PowerShell Encoded Command Execution|TA0002|T1059.001|windows_event_log|CommandLine|contains|encodedcommand|8.1|4|Base64-encoded PowerShell execution detected"
  "mimikatz_lsass|Mimikatz LSASS Memory Access|TA0006|T1003.001|windows_event_log|TargetObject|contains|lsass|9.0|2|Credential dumping via LSASS process memory"
  "new_local_admin|New Local Administrator Account Created|TA0003|T1136.001|windows_event_log|EventID|equals|4720|7.2|3|New privileged user account created locally"
  "lateral_psexec|PsExec Lateral Movement Detected|TA0008|T1021.002|windows_event_log|ServiceName|contains|psexec|8.5|3|PsExec service installation on remote host"
  "scheduled_task_new|Suspicious Scheduled Task Created|TA0003|T1053.005|windows_event_log|EventID|equals|4698|6.8|5|Persistence via newly created scheduled task"
  "wmi_spawn|WMI Spawning Suspicious Process|TA0002|T1047|windows_event_log|ParentImage|contains|wmiprvse.exe|7.8|4|Suspicious child process spawned from WMI provider"
  "shadow_copy_delete|Shadow Copy Deletion — Ransomware Indicator|TA0040|T1490|windows_event_log|CommandLine|contains|vssadmin delete shadows|9.8|1|Ransomware indicator — backup removal via vssadmin"
  "reg_run_key|Registry Run Key Persistence|TA0003|T1547.001|windows_event_log|TargetObject|contains|CurrentVersion\\Run|7.5|4|Autorun registry key modification for persistence"
  "dcsync|DCSync Attack — Directory Replication Abuse|TA0006|T1003.006|windows_event_log|EventID|equals|4662|9.5|1|Domain controller replication rights abused for credential theft"
  "kerberoast|Kerberoasting — RC4 SPN Ticket Request|TA0006|T1558.003|windows_event_log|EventID|equals|4769|8.8|2|Service principal name ticket requested with RC4 encryption"
  "pass_the_hash|Pass-the-Hash NTLM Lateral Movement|TA0008|T1550.002|windows_event_log|EventID|equals|4624|9.0|3|NTLM authentication used for lateral movement"
  "wdigest_enable|WDigest Plaintext Credential Storage Enabled|TA0006|T1112|windows_event_log|TargetObject|contains|WDigest|9.0|1|Plaintext credential caching re-enabled in registry"
  "amsi_bypass|AMSI Bypass Attempt Detected|TA0005|T1562.001|windows_event_log|CommandLine|contains|AmsiScanBuffer|8.5|2|Antimalware scan interface bypass technique used"
  "defender_disabled|Windows Defender Real-Time Protection Disabled|TA0005|T1562.001|windows_event_log|EventID|equals|5001|9.0|1|Windows Defender real-time protection turned off"
  "uac_bypass|UAC Bypass via EventVwr|TA0004|T1548.002|windows_event_log|CommandLine|contains|eventvwr.exe|7.8|3|User Account Control bypassed using EventViewer hijack"
  "lolbas_regsvr32|LOLBin — RegSvr32 Proxy Execution|TA0005|T1218.010|windows_event_log|CommandLine|contains|regsvr32 /u /s /i:|7.8|3|Living-off-the-land regsvr32 abuse for code execution"
  "lolbas_certutil|LOLBin — CertUtil Remote File Download|TA0002|T1105|windows_event_log|CommandLine|contains|certutil -urlcache|7.5|4|CertUtil used to download remote payload"
  "bloodhound_enum|BloodHound Active Directory Enumeration|TA0007|T1069|windows_event_log|CommandLine|contains|SharpHound|8.0|2|BloodHound/SharpHound AD enumeration tool detected"
  "masquerading_svchost|Process Masquerading as Svchost|TA0005|T1036.005|windows_event_log|Image|contains|svchost|7.0|3|Non-system process masquerading as legitimate svchost.exe"
  "process_injection|Cross-Process Memory Injection|TA0005|T1055|windows_event_log|EventID|equals|10|8.8|2|Cross-process memory write detected — possible injection"
  "dll_sideload|DLL Side-Loading from Temp Directory|TA0005|T1574.002|windows_event_log|ImageLoaded|contains|\\Temp\\|7.5|4|DLL loaded from user temp directory — possible side-load"
  "rdp_enabled|RDP Enabled via Registry Modification|TA0008|T1021.001|windows_event_log|EventID|equals|4688|6.5|5|Remote Desktop Protocol enabled through registry change"
  "winrm_lateral|WinRM Used for Lateral Movement|TA0008|T1021.006|windows_event_log|CommandLine|contains|winrm invoke|7.5|3|Windows Remote Management used to execute remote commands"
  "pass_spray|Password Spray Attack Detected|TA0006|T1110.003|windows_event_log|EventID|equals|4648|8.0|3|Single source authenticating to multiple accounts"
  "net_user_add|Net User Add via Command Line|TA0003|T1136|windows_event_log|CommandLine|contains|net user /add|7.0|4|New local user created via net.exe command"
  "ssh_bruteforce|SSH Brute Force Authentication Failure|TA0006|T1110|syslog|message|contains|Failed password for|7.5|4|Multiple SSH authentication failures from single host"
  "reverse_shell_bash|Bash Reverse Shell Attempt|TA0011|T1059.004|syslog|CommandLine|contains|/dev/tcp/|9.0|2|Bash built-in TCP redirection used for reverse shell"
  "python_exec_shell|Python Interactive Shell Spawn|TA0002|T1059.006|syslog|CommandLine|contains|python -c import pty|8.5|3|Python used to spawn interactive PTY shell"
  "iptables_flush|IPTables Firewall Rules Flushed|TA0005|T1562.004|syslog|CommandLine|contains|iptables -F|7.0|3|All iptables rules cleared — firewall bypassed"
  "sudo_su_root|Sudo Privilege Escalation to Root|TA0004|T1548.003|syslog|CommandLine|contains|sudo su|6.0|5|User escalated to root shell via sudo"
  "crontab_modify|Crontab Modified for Persistence|TA0003|T1053.003|syslog|CommandLine|contains|crontab -e|6.5|5|Cron schedule modified — possible persistence mechanism"
  "curl_wget_download|Curl/Wget Payload Download|TA0002|T1105|syslog|CommandLine|contains|curl http|6.5|6|Remote file download using curl or wget"
  "data_staged_zip|Data Staged in ZIP Archive|TA0009|T1074.001|syslog|CommandLine|contains|zip -r /tmp/|7.0|4|Bulk data archived to temp — possible pre-exfiltration staging"
  "nmap_scan|Nmap Network Port Scan|TA0007|T1046|zeek|service|contains|nmap|6.0|6|Network port scanning activity detected"
  "dns_exfil|DNS Exfiltration — Oversized Query|TA0010|T1048.003|zeek|query_length|equals|>200|8.0|3|Abnormally long DNS query — possible data exfiltration"
  "zeek_c2_beacon|C2 Beaconing — Regular Outbound Pattern|TA0011|T1071.001|zeek|interval_stddev|equals|<5|9.0|2|Highly regular periodic outbound connections — likely C2"
  "tlsdomain_dga|Domain Generation Algorithm Traffic|TA0011|T1568.002|zeek|query|contains|xn--|7.5|4|Possible DGA domain in DNS traffic"
  "icmp_tunnel|ICMP Tunnelling — Large Payload|TA0011|T1095|zeek|proto|equals|icmp|8.0|3|Unusually large ICMP payload — possible covert channel"
  "tor_exit_node|TOR Exit Node Communication|TA0011|T1090.003|zeek|ip|equals|tor_exit_list|9.0|2|Outbound connection to known TOR exit node IP"
  "exfil_over_https|Large Data Exfiltration Over HTTPS|TA0010|T1048.002|zeek|bytes_out|equals|>10MB|8.0|3|Unusually large outbound encrypted data transfer"
  "aws_root_login|AWS Root Account Login Detected|TA0001|T1078.004|aws_cloudtrail|userIdentity.type|equals|Root|9.5|1|AWS root account used — should never occur in production"
  "aws_s3_public|S3 Bucket ACL Set to Public|TA0010|T1530|aws_cloudtrail|requestParameters.acl|equals|public-read|9.0|2|S3 bucket made publicly accessible"
  "cloudtrail_stopped|AWS CloudTrail Logging Disabled|TA0005|T1562.008|aws_cloudtrail|eventName|equals|StopLogging|9.5|1|AWS audit trail logging stopped — blind spot created"
  "iam_key_created|New AWS IAM Access Key Created|TA0003|T1098.001|aws_cloudtrail|eventName|equals|CreateAccessKey|7.0|4|New programmatic access key provisioned"
  "sg_open_all|Security Group Opens All Ports to Internet|TA0005|T1562|aws_cloudtrail|requestParameters.ipPermissions.ipRanges|equals|0.0.0.0/0|9.0|2|Overly permissive inbound rule added"
  "lambda_unusual|Unusual Lambda Function Invocation|TA0002|T1648|aws_cloudtrail|eventName|equals|InvokeFunction|5.5|6|Serverless function invoked from unexpected source"
  "azure_mfa_fail|Azure MFA Failure Spike|TA0006|T1110.001|azure_activity_log|ResultType|equals|500121|7.5|4|Multiple multi-factor authentication failures"
  "azure_impossible_travel|Azure Impossible Travel Sign-In|TA0001|T1078|azure_activity_log|RiskEventType|equals|ImpossibleTravel|8.8|2|Sign-in from geographically impossible location pair"
  "azure_vm_disk_export|Azure VM Disk Snapshot Exported|TA0009|T1537|azure_activity_log|operationName|equals|Microsoft.Compute/disks/export|8.5|2|Virtual machine disk exported — possible data theft"
  "o365_mail_forward|O365 Mail Auto-Forward Rule to External|TA0009|T1114.003|azure_activity_log|Operation|equals|Set-InboxRule|8.0|3|Email auto-forwarding rule set to external address"
)

# ── Seed library from array ───────────────────────────────────
seed_library() {
  local count; count=$(find "$LIBRARY_DIR" -name '*.yml' 2>/dev/null | wc -l)
  [[ $count -ge 50 ]] && return

  local seeded=0
  for entry in "${LIBRARY_RULES[@]}"; do
    IFS='|' read -r fname title tactic technique logsrc field op value cvss fp desc <<< "$entry"
    local severity; severity=$(cvss_label "$cvss")
    local tname="${TACTIC_MAP[$tactic]:-Unknown}"
    local fpath="$LIBRARY_DIR/${fname}.yml"
    cat > "$fpath" <<YAML
title: "$title"
id: "$(printf '%08x-%04x-%04x-%04x-%012x' $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM)"
status: stable
description: "$desc"
author: "Dinesh Patel"
date: "$(date -u '+%Y-%m-%d')"
references:
  - "https://attack.mitre.org/techniques/$technique/"
tags:
  - "attack.$tactic"
  - "attack.$technique"
logsource:
  product: "$logsrc"
detection:
  selection:
    ${field}|${op}: "$value"
  condition: selection
falsepositives:
  - "FP Score: $fp/10"
level: "$(echo "$severity" | tr '[:upper:]' '[:lower:]')"
custom:
  cvss_score: $cvss
  severity: "$severity"
  mitre_tactic: "$tname"
  mitre_tactic_id: "$tactic"
  mitre_technique: "$technique"
  fp_score: $fp
YAML
    seeded=$(( seeded + 1 ))
  done
  log "Seeded $seeded library rules"
}

# ════════════════════════════════════════════════════════════
#  MODULE 1 — BUILD NEW RULE
# ════════════════════════════════════════════════════════════
build_rule() {
  banner
  echo -e "  ${BOLD}[ BUILD NEW DETECTION RULE ]${RESET}\n"

  # Basic metadata
  printf "  ${CYAN}Rule Title       :${RESET} "; read -r rule_title
  [[ -z "$rule_title" ]] && { echo -e "\n  ${RED}Title cannot be empty.${RESET}"; pause; return; }
  printf "  ${CYAN}Description      :${RESET} "; read -r rule_desc
  printf "  ${CYAN}Author           :${RESET} "; read -r rule_author
  rule_author="${rule_author:-Dinesh Patel}"
  printf "  ${CYAN}References / URL :${RESET} "; read -r rule_ref
  rule_ref="${rule_ref:-https://attack.mitre.org/}"

  # MITRE Tactic
  echo -e "\n  ${BOLD}MITRE ATT&CK Tactic:${RESET}"
  local tactic_keys=(); local i=1
  for k in "${!TACTIC_MAP[@]}"; do
    printf "    ${CYAN}%2d)${RESET} %-8s — %s\n" "$i" "$k" "${TACTIC_MAP[$k]}"
    tactic_keys+=("$k"); i=$(( i + 1 ))
  done
  printf "\n  Select [1-%d] : " "${#tactic_keys[@]}"; read -r tch
  tch=$(( ${tch:-1} - 1 ))
  local tactic_id="${tactic_keys[$tch]:-TA0001}"
  local tactic_name="${TACTIC_MAP[$tactic_id]}"

  printf "  ${CYAN}Technique ID (e.g. T1059.001) :${RESET} "; read -r technique_id
  technique_id="${technique_id:-T1059}"

  # Log source
  echo -e "\n  ${BOLD}Log Source:${RESET}"
  echo "    1) Windows Event Log    2) Syslog (Linux)"
  echo "    3) AWS CloudTrail       4) Azure Activity Log"
  echo "    5) Zeek / Bro           6) Custom"
  printf "  Select : "; read -r src
  case "$src" in
    1) log_source="windows_event_log" ;;
    2) log_source="syslog" ;;
    3) log_source="aws_cloudtrail" ;;
    4) log_source="azure_activity_log" ;;
    5) log_source="zeek" ;;
    *) printf "  Custom source name : "; read -r log_source ;;
  esac

  # Detection conditions
  echo -e "\n  ${BOLD}Detection Conditions${RESET}"
  echo -e "  ${DIM}Format:  field | operator | value"
  echo -e "  Operators: equals  contains  startswith  endswith"
  echo -e "  Example:  EventID | equals | 4688       CommandLine | contains | mimikatz${RESET}\n"
  local conditions=()
  while true; do
    printf "  Condition %d (blank to finish) : " "$(( ${#conditions[@]} + 1 ))"
    read -r cond
    [[ -z "$cond" ]] && break
    conditions+=("$cond")
  done
  [[ ${#conditions[@]} -eq 0 ]] && conditions=("EventID|equals|0000")

  # Scoring
  echo -e "\n  ${BOLD}Scoring${RESET}"
  printf "  CVSS Score [0.0–10.0]         : "; read -r cvss_score; cvss_score="${cvss_score:-5.0}"
  printf "  FP Score   [0=rare  10=noisy] : "; read -r fp_score;   fp_score="${fp_score:-5}"
  printf "  Status     [experimental/stable/test] : "; read -r rule_status; rule_status="${rule_status:-experimental}"

  # Additional tags
  printf "  Extra Tags (comma-separated)  : "; read -r raw_tags

  # Generate rule
  local severity; severity=$(cvss_label "$cvss_score")
  local ts; ts=$(date -u '+%Y-%m-%d')
  local rule_id; rule_id=$(printf '%08x-%04x-%04x-%04x-%012x' $RANDOM $RANDOM $RANDOM $RANDOM $RANDOM)
  local safe; safe=$(echo "$rule_title" | tr ' ' '_' | tr -cd '[:alnum:]_-' | tr '[:upper:]' '[:lower:]')
  local outfile="$RULES_DIR/${safe}.yml"

  {
    echo "title: \"$rule_title\""
    echo "id: \"$rule_id\""
    echo "status: $rule_status"
    echo "description: \"$rule_desc\""
    echo "author: \"$rule_author\""
    echo "date: \"$ts\""
    echo "references:"
    echo "  - \"$rule_ref\""
    echo "tags:"
    echo "  - attack.$tactic_id"
    echo "  - attack.$technique_id"
    if [[ -n "$raw_tags" ]]; then
      IFS=',' read -ra taglist <<< "$raw_tags"
      for tag in "${taglist[@]}"; do echo "  - \"$(echo "$tag" | xargs)\""; done
    fi
    echo "logsource:"
    echo "  product: $log_source"
    echo "detection:"
    echo "  selection:"
    for cond in "${conditions[@]}"; do
      IFS='|' read -r f op v <<< "$cond"
      f=$(echo "$f" | xargs); op=$(echo "$op" | xargs); v=$(echo "$v" | xargs)
      echo "    ${f}|${op}: \"$v\""
    done
    echo "  condition: selection"
    echo "falsepositives:"
    echo "  - \"FP Score: $fp_score/10 — review before production deployment\""
    echo "level: \"$(echo "$severity" | tr '[:upper:]' '[:lower:]')\""
    echo "custom:"
    echo "  cvss_score: $cvss_score"
    echo "  severity: \"$severity\""
    echo "  mitre_tactic: \"$tactic_name\""
    echo "  mitre_tactic_id: \"$tactic_id\""
    echo "  mitre_technique: \"$technique_id\""
    echo "  fp_score: $fp_score"
  } > "$outfile"

  log "Built rule: $rule_title -> $outfile"

  echo ""
  hr
  local sc; sc=$(sev_color "$severity")
  echo -e "  ${GREEN}${BOLD}✔  Rule saved:${RESET}  $outfile"
  echo -e "  ${BOLD}Severity :${RESET}  ${sc}${severity}${RESET}  (CVSS $cvss_score)"
  echo -e "  ${BOLD}FP Score :${RESET}  $fp_score / 10"
  echo -e "  ${BOLD}Tactic   :${RESET}  $tactic_name  [$tactic_id]"
  hr
  pause
}

# ════════════════════════════════════════════════════════════
#  MODULE 2 — RULE LIBRARY BROWSER
# ════════════════════════════════════════════════════════════
browse_library() {
  seed_library
  while true; do
    banner
    echo -e "  ${BOLD}[ RULE LIBRARY — 50+ MITRE ATT&CK Mapped Rules ]${RESET}\n"

    local files=("$LIBRARY_DIR"/*.yml)
    local existing=()
    for f in "${files[@]}"; do [[ -f "$f" ]] && existing+=("$f"); done

    # Filter options
    echo -e "  ${BOLD}Filter by tactic:${RESET}  [1] All  [2] Credential Access  [3] Persistence"
    echo -e "  [4] Defense Evasion   [5] Lateral Movement  [6] Exfiltration"
    echo -e "  [7] Cloud (AWS/Azure) [8] C2 & Network      [9] Impact"
    printf "\n  Filter choice [1]: "; read -r filt

    declare -A FILT_MAP=(
      ["2"]="Credential Access" ["3"]="Persistence"    ["4"]="Defense Evasion"
      ["5"]="Lateral Movement"  ["6"]="Exfiltration"   ["7"]="TA004"
      ["8"]="Command and Control" ["9"]="Impact"
    )
    local filt_tactic="${FILT_MAP[$filt]:-}"

    echo ""
    hr
    printf "  ${CYAN}${BOLD}  %-4s %-11s %-6s %-5s %-24s %s${RESET}\n" "#" "SEVERITY" "CVSS" "FP" "TACTIC" "RULE TITLE"
    hr

    local shown=() ; local i=1
    for f in "${existing[@]}"; do
      local title; title=$(grep '^title:' "$f" | sed 's/title: *//' | tr -d '"')
      local cvss;  cvss=$(grep 'cvss_score:' "$f" | sed 's/.*cvss_score: *//')
      local fp;    fp=$(grep 'fp_score:' "$f" | sed 's/.*fp_score: *//')
      local tac;   tac=$(grep 'mitre_tactic:' "$f" | sed 's/.*mitre_tactic: *//' | tr -d '"')
      local sev;   sev=$(grep 'severity:' "$f" | sed 's/.*severity: *//' | tr -d '"')
      [[ -n "$filt_tactic" ]] && [[ "$tac" != *"$filt_tactic"* ]] && continue
      local sc; sc=$(sev_color "$sev")
      printf "  ${CYAN}%-4s${RESET} ${sc}%-11s${RESET} %-6s %-5s %-24s %s\n" \
        "$i)" "$sev" "$cvss" "$fp/10" "$tac" "$title"
      shown+=("$f"); i=$(( i + 1 ))
    done

    hr
    echo -e "\n  ${BOLD}[V]${RESET} View YAML  ${BOLD}[A]${RESET} Add to My Rules  ${BOLD}[B]${RESET} Back"
    printf "  Choice : "; read -r action

    case "${action^^}" in
      V|A)
        printf "  Rule number : "; read -r rnum
        local idx=$(( rnum - 1 ))
        local chosen="${shown[$idx]:-}"
        if [[ ! -f "$chosen" ]]; then
          echo -e "  ${RED}Invalid selection.${RESET}"; sleep 1; continue
        fi
        if [[ "${action^^}" == "V" ]]; then
          echo ""; hr; cat "$chosen"; hr
          pause
        else
          local bname; bname=$(basename "$chosen")
          cp "$chosen" "$RULES_DIR/$bname"
          echo -e "  ${GREEN}✔  Added to My Rules: $bname${RESET}"
          log "Copied from library: $bname"
          pause
        fi ;;
      B) break ;;
    esac
  done
}

# ════════════════════════════════════════════════════════════
#  MODULE 3 — MY RULES
# ════════════════════════════════════════════════════════════
my_rules() {
  while true; do
    banner
    echo -e "  ${BOLD}[ MY RULES ]${RESET}\n"

    local files=("$RULES_DIR"/*.yml)
    local existing=()
    for f in "${files[@]}"; do [[ -f "$f" ]] && existing+=("$f"); done

    if [[ ${#existing[@]} -eq 0 ]]; then
      echo -e "  ${YELLOW}No custom rules yet. Build one or copy from the Library.${RESET}"
      pause; return
    fi

    hr
    printf "  ${CYAN}${BOLD}  %-4s %-11s %-6s %-5s %-24s %s${RESET}\n" "#" "SEVERITY" "CVSS" "FP" "TACTIC" "RULE TITLE"
    hr

    local i=1
    for f in "${existing[@]}"; do
      local title; title=$(grep '^title:' "$f" | sed 's/title: *//' | tr -d '"')
      local cvss;  cvss=$(grep 'cvss_score:' "$f" | sed 's/.*cvss_score: *//')
      local fp;    fp=$(grep 'fp_score:' "$f" | sed 's/.*fp_score: *//')
      local tac;   tac=$(grep 'mitre_tactic:' "$f" | sed 's/.*mitre_tactic: *//' | tr -d '"')
      local sev;   sev=$(grep 'severity:' "$f" | sed 's/.*severity: *//' | tr -d '"')
      local sc; sc=$(sev_color "$sev")
      printf "  ${CYAN}%-4s${RESET} ${sc}%-11s${RESET} %-6s %-5s %-24s %s\n" \
        "$i)" "$sev" "$cvss" "$fp/10" "$tac" "$title"
      i=$(( i + 1 ))
    done

    hr
    echo -e "\n  ${BOLD}[V]${RESET} View YAML  ${BOLD}[D]${RESET} Delete  ${BOLD}[B]${RESET} Back"
    printf "  Choice : "; read -r action

    case "${action^^}" in
      V)
        printf "  Rule number : "; read -r rnum
        local chosen="${existing[$(( rnum - 1 ))]:-}"
        [[ -f "$chosen" ]] && { echo ""; hr; cat "$chosen"; hr; pause; } || { echo -e "${RED}  Invalid.${RESET}"; sleep 1; }
        ;;
      D)
        printf "  Rule number to delete : "; read -r rnum
        local chosen="${existing[$(( rnum - 1 ))]:-}"
        if [[ -f "$chosen" ]]; then
          local t; t=$(grep '^title:' "$chosen" | sed 's/title: *//' | tr -d '"')
          rm "$chosen"
          echo -e "  ${GREEN}✔  Deleted: $t${RESET}"
          log "Deleted rule: $t"
          pause
        else
          echo -e "  ${RED}Invalid.${RESET}"; sleep 1
        fi ;;
      B) break ;;
    esac
  done
}

# ════════════════════════════════════════════════════════════
#  MODULE 4 — EXPORT RULES
# ════════════════════════════════════════════════════════════
export_rules() {
  banner
  echo -e "  ${BOLD}[ EXPORT RULES ]${RESET}\n"

  # Collect all rules (custom + library)
  local all_rules=()
  for f in "$RULES_DIR"/*.yml "$LIBRARY_DIR"/*.yml; do
    [[ -f "$f" ]] && all_rules+=("$f")
  done

  if [[ ${#all_rules[@]} -eq 0 ]]; then
    echo -e "  ${YELLOW}No rules found.${RESET}"; pause; return
  fi

  echo -e "  ${BOLD}Export scope:${RESET}"
  echo "  1) My Rules only"
  echo "  2) Full Library  (50+ rules)"
  echo "  3) Both"
  printf "  Scope : "; read -r scope

  local export_list=()
  case "$scope" in
    1) for f in "$RULES_DIR"/*.yml;   do [[ -f "$f" ]] && export_list+=("$f"); done ;;
    2) for f in "$LIBRARY_DIR"/*.yml; do [[ -f "$f" ]] && export_list+=("$f"); done ;;
    *) export_list=("${all_rules[@]}") ;;
  esac

  if [[ ${#export_list[@]} -eq 0 ]]; then
    echo -e "  ${YELLOW}No rules in selected scope.${RESET}"; pause; return
  fi

  echo -e "\n  ${BOLD}Target platform:${RESET}"
  echo "  1) Splunk SPL"
  echo "  2) Microsoft Sentinel KQL"
  echo "  3) IBM QRadar AQL"
  echo "  4) All three platforms"
  printf "  Platform : "; read -r plat

  local ts; ts=$(date '+%Y%m%d_%H%M%S')
  local spl_file="$OUTPUT_DIR/splunk_${ts}.spl"
  local kql_file="$OUTPUT_DIR/sentinel_${ts}.kql"
  local aql_file="$OUTPUT_DIR/qradar_${ts}.aql"

  [[ "$plat" =~ ^[14]$ ]] && printf '/*\n * SIEMForge — Splunk SPL Export\n * Generated : %s\n * Author    : Dinesh Patel\n */\n\n' "$(date)" > "$spl_file"
  [[ "$plat" =~ ^[24]$ ]] && printf '//\n// SIEMForge — Microsoft Sentinel KQL Export\n// Generated : %s\n// Author    : Dinesh Patel\n//\n\n' "$(date)" > "$kql_file"
  [[ "$plat" =~ ^[34]$ ]] && printf '-- SIEMForge — IBM QRadar AQL Export\n-- Generated : %s\n-- Author    : Dinesh Patel\n\n' "$(date)" > "$aql_file"

  local count=0
  for rule_file in "${export_list[@]}"; do
    local title;   title=$(grep '^title:'          "$rule_file" | sed 's/title: *//'           | tr -d '"')
    local level;   level=$(grep '^level:'          "$rule_file" | sed 's/level: *//'           | tr -d '"')
    local cvss;    cvss=$(grep  'cvss_score:'      "$rule_file" | sed 's/.*cvss_score: *//')
    local tactic;  tactic=$(grep 'mitre_tactic:'  "$rule_file" | sed 's/.*mitre_tactic: *//'  | tr -d '"')
    local tech;    tech=$(grep  'mitre_technique:' "$rule_file" | sed 's/.*mitre_technique: *//' | tr -d '"')
    local fp;      fp=$(grep    'fp_score:'        "$rule_file" | sed 's/.*fp_score: *//')
    local logsrc;  logsrc=$(grep 'product:'       "$rule_file" | sed 's/.*product: *//'       | tr -d '"')

    # Extract first detection field/value pair
    local det_field det_value
    det_field=$(awk '/detection:/,/condition:/' "$rule_file" | grep '|' | head -1 | sed 's/|.*//' | xargs)
    det_value=$(awk '/detection:/,/condition:/' "$rule_file" | grep '|' | head -1 | sed 's/.*: *//' | tr -d '"' | xargs)

    # ── Splunk SPL ───────────────────────────────────────────
    if [[ "$plat" =~ ^[14]$ ]]; then cat >> "$spl_file" <<SPL
/* ─────────────────────────────────────────────────────────
 * Rule     : $title
 * Severity : $level  |  CVSS: $cvss  |  FP: $fp/10
 * Tactic   : $tactic [$tech]
 * Source   : $logsrc
 * ───────────────────────────────────────────────────────── */
index=* sourcetype=$logsrc
  $det_field="$det_value"
| eval Severity="$level", CVSS="$cvss", Tactic="$tactic"
| table _time, host, source, Severity, CVSS, Tactic, $det_field, *
| sort -_time

SPL
    fi

    # ── Sentinel KQL ─────────────────────────────────────────
    if [[ "$plat" =~ ^[24]$ ]]; then cat >> "$kql_file" <<KQL
// ─────────────────────────────────────────────────────────────
// Rule     : $title
// Severity : $level  |  CVSS: $cvss  |  FP: $fp/10
// Tactic   : $tactic [$tech]
// Source   : $logsrc
// ─────────────────────────────────────────────────────────────
SecurityEvent
| where TimeGenerated > ago(24h)
| where $det_field == "$det_value"
| extend Severity = "$level", CVSS_Score = "$cvss", Tactic = "$tactic"
| project TimeGenerated, Computer, Account, Activity, EventID, Severity, CVSS_Score, Tactic
| sort by TimeGenerated desc

KQL
    fi

    # ── QRadar AQL ───────────────────────────────────────────
    if [[ "$plat" =~ ^[34]$ ]]; then cat >> "$aql_file" <<AQL
-- ─────────────────────────────────────────────────────────────
-- Rule     : $title
-- Severity : $level  |  CVSS: $cvss  |  FP: $fp/10
-- Tactic   : $tactic [$tech]
-- Source   : $logsrc
-- ─────────────────────────────────────────────────────────────
SELECT DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS "EventTime",
       sourceip, destinationip, username,
       QIDNAME(qid) AS "EventName",
       "$level" AS "Severity",
       "$cvss"  AS "CVSS"
FROM events
WHERE "$det_field" = '$det_value'
ORDER BY "EventTime" DESC
LAST 24 HOURS;

AQL
    fi

    count=$(( count + 1 ))
    local sc; sc=$(sev_color "$(echo "$level" | tr '[:lower:]' '[:upper:]')")
    printf "  ${GREEN}✔${RESET} %-10s  %s\n" "[${sc}$(echo "$level" | tr '[:lower:]' '[:upper:]')${RESET}]" "$title"
  done

  hr
  echo -e "  ${GREEN}${BOLD}✔  $count rule(s) exported${RESET}\n"
  [[ "$plat" =~ ^[14]$ ]] && echo -e "  ${CYAN}Splunk   :${RESET} $spl_file"
  [[ "$plat" =~ ^[24]$ ]] && echo -e "  ${CYAN}Sentinel :${RESET} $kql_file"
  [[ "$plat" =~ ^[34]$ ]] && echo -e "  ${CYAN}QRadar   :${RESET} $aql_file"
  hr
  log "Exported $count rules  platform=$plat"
  pause
}

# ════════════════════════════════════════════════════════════
#  MODULE 5 — ALERT SIMULATION
# ════════════════════════════════════════════════════════════
simulate_alert() {
  banner
  echo -e "  ${BOLD}[ ALERT SIMULATION ]${RESET}\n"

  local all_rules=()
  for f in "$RULES_DIR"/*.yml "$LIBRARY_DIR"/*.yml; do [[ -f "$f" ]] && all_rules+=("$f"); done

  if [[ ${#all_rules[@]} -eq 0 ]]; then
    echo -e "  ${YELLOW}No rules available. Build or browse the Library first.${RESET}"; pause; return
  fi

  hr
  printf "  ${CYAN}${BOLD}  %-4s %-11s %-5s %-24s %s${RESET}\n" "#" "SEVERITY" "FP" "TACTIC" "RULE TITLE"
  hr
  local i=1
  for f in "${all_rules[@]}"; do
    local title; title=$(grep '^title:' "$f" | sed 's/title: *//' | tr -d '"')
    local sev;   sev=$(grep 'severity:' "$f" | sed 's/.*severity: *//' | tr -d '"')
    local fp;    fp=$(grep 'fp_score:' "$f" | sed 's/.*fp_score: *//')
    local tac;   tac=$(grep 'mitre_tactic:' "$f" | sed 's/.*mitre_tactic: *//' | tr -d '"')
    local sc; sc=$(sev_color "$sev")
    printf "  ${CYAN}%-4s${RESET} ${sc}%-11s${RESET} %-5s %-24s %s\n" "$i)" "$sev" "$fp/10" "$tac" "$title"
    i=$(( i + 1 ))
  done
  hr

  printf "\n  Select rule to simulate [1-%d] : " "${#all_rules[@]}"
  read -r sel
  local chosen="${all_rules[$(( sel - 1 ))]:-}"
  [[ ! -f "$chosen" ]] && { echo -e "  ${RED}Invalid selection.${RESET}"; pause; return; }

  local title;  title=$(grep '^title:'         "$chosen" | sed 's/title: *//'         | tr -d '"')
  local cvss;   cvss=$(grep  'cvss_score:'     "$chosen" | sed 's/.*cvss_score: *//')
  local fp;     fp=$(grep    'fp_score:'       "$chosen" | sed 's/.*fp_score: *//')
  local tactic; tactic=$(grep 'mitre_tactic:'  "$chosen" | sed 's/.*mitre_tactic: *//' | tr -d '"')
  local tech;   tech=$(grep  'mitre_technique:' "$chosen" | sed 's/.*mitre_technique: *//' | tr -d '"')
  local sev;    sev=$(grep   'severity:'       "$chosen" | sed 's/.*severity: *//'    | tr -d '"')
  local logsrc; logsrc=$(grep 'product:'       "$chosen" | sed 's/.*product: *//'    | tr -d '"')
  local det_field; det_field=$(awk '/detection:/,/condition:/' "$chosen" | grep '|' | head -1 | sed 's/|.*//' | xargs)
  local det_val;   det_val=$(awk '/detection:/,/condition:/' "$chosen"  | grep '|' | head -1 | sed 's/.*: *//' | tr -d '"' | xargs)
  local sc; sc=$(sev_color "$sev")

  printf "\n  ${BOLD}How many events to simulate [1-20] :${RESET} "; read -r nevents
  nevents="${nevents:-5}"
  [[ "$nevents" -gt 20 ]] && nevents=20

  echo ""
  hr
  echo -e "  ${BOLD}Simulating: ${CYAN}$title${RESET}"
  hr
  echo ""

  local fake_hosts=("DC01" "WS-FINANCE" "SRV-PROD" "LAPTOP-HR" "BUILD-SERVER" "MGMT-01" "JUMP-HOST" "DB-SERVER" "WEB-FRONT" "LOG-COLLECTOR")
  local fake_users=("jsmith" "adavis" "npatil" "tlee" "SYSTEM" "r.chen" "svc_backup" "admin" "m.jones" "l.kumar")
  local verdicts=()
  local tp_count=0 fp_count=0

  for idx in $(seq 1 "$nevents"); do
    local host="${fake_hosts[$(( RANDOM % ${#fake_hosts[@]} ))]}"
    local user="${fake_users[$(( RANDOM % ${#fake_users[@]} ))]}"
    local src_ip="10.$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1))"
    local evt_time; evt_time=$(date -d "-$((RANDOM % 120)) minutes" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')
    local fp_roll=$(( RANDOM % 10 ))
    local verdict verdict_color
    if (( fp_roll < fp )); then
      verdict="FALSE POSITIVE"; verdict_color="${YELLOW}"
      fp_count=$(( fp_count + 1 ))
    else
      verdict="TRUE POSITIVE";  verdict_color="${RED}${BOLD}"
      tp_count=$(( tp_count + 1 ))
    fi
    verdicts+=("$verdict")

    printf "  ${BOLD}Event %-2s${RESET}  %s  ${DIM}%-14s${RESET}  %-16s  %-12s  " \
      "$idx" "$evt_time" "$host" "$src_ip" "$user"
    printf "${verdict_color}[%s]${RESET}\n" "$verdict"
    sleep 0.15
  done

  echo ""
  hr
  echo -e "  ${BOLD}Simulation Summary${RESET}"
  hr
  echo -e "  Rule         : ${CYAN}$title${RESET}"
  echo -e "  Severity     : ${sc}${sev}${RESET}  (CVSS $cvss)"
  echo -e "  Tactic       : $tactic  [$tech]"
  echo -e "  Log Source   : $logsrc"
  echo -e "  Detection    : $det_field = '$det_val'"
  echo -e "  FP Score     : $fp / 10"
  echo ""
  echo -e "  Events Run   : $nevents"
  echo -e "  ${RED}${BOLD}True Positives :${RESET}  $tp_count"
  echo -e "  ${YELLOW}False Positives:${RESET}  $fp_count"
  (( nevents > 0 )) && printf "  Signal Ratio : %.0f%%\n" "$(echo "scale=2; $tp_count / $nevents * 100" | bc -l)"
  hr
  log "Simulated $nevents events for: $title  TP=$tp_count FP=$fp_count"
  pause
}

# ════════════════════════════════════════════════════════════
#  MODULE 6 — STATISTICS DASHBOARD
# ════════════════════════════════════════════════════════════
show_stats() {
  banner
  echo -e "  ${BOLD}[ STATISTICS DASHBOARD ]${RESET}\n"
  seed_library

  local my_count=0 lib_count=0
  local crit=0 high=0 med=0 low=0
  local t_initial=0 t_exec=0 t_persist=0 t_priv=0 t_evasion=0
  local t_cred=0 t_disc=0 t_lateral=0 t_collect=0 t_exfil=0 t_c2=0 t_impact=0

  for f in "$RULES_DIR"/*.yml;   do [[ -f "$f" ]] && my_count=$(( my_count + 1 ));  done
  for f in "$LIBRARY_DIR"/*.yml; do [[ -f "$f" ]] && lib_count=$(( lib_count + 1 )); done

  for f in "$RULES_DIR"/*.yml "$LIBRARY_DIR"/*.yml; do
    [[ ! -f "$f" ]] && continue
    local sev; sev=$(grep 'severity:' "$f" | sed 's/.*severity: *//' | tr -d '"' | tr '[:lower:]' '[:upper:]')
    local tac; tac=$(grep 'mitre_tactic_id:' "$f" | sed 's/.*mitre_tactic_id: *//' | tr -d '"')
    case "$sev" in
      CRITICAL) crit=$(( crit + 1 )) ;; HIGH) high=$(( high + 1 )) ;; MEDIUM) med=$(( med + 1 )) ;; LOW) low=$(( low + 1 )) ;;
    esac
    case "$tac" in
      TA0001) t_initial=$(( t_initial + 1 ))  ;; TA0002) t_exec=$(( t_exec + 1 ))    ;; TA0003) t_persist=$(( t_persist + 1 )) ;;
      TA0004) t_priv=$(( t_priv + 1 ))     ;; TA0005) t_evasion=$(( t_evasion + 1 )) ;; TA0006) t_cred=$(( t_cred + 1 ))    ;;
      TA0007) t_disc=$(( t_disc + 1 ))     ;; TA0008) t_lateral=$(( t_lateral + 1 )) ;; TA0009) t_collect=$(( t_collect + 1 )) ;;
      TA0010) t_exfil=$(( t_exfil + 1 ))    ;; TA0011) t_c2=$(( t_c2 + 1 ))      ;; TA0040) t_impact=$(( t_impact + 1 ))  ;;
    esac
  done

  local total=$(( my_count + lib_count ))
  hr
  printf "  ${BOLD}%-30s${RESET} %s\n" "My Custom Rules:"       "$my_count"
  printf "  ${BOLD}%-30s${RESET} %s\n" "Library Rules:"         "$lib_count"
  printf "  ${BOLD}%-30s${RESET} %s\n" "Total Rules Loaded:"    "$total"
  hr
  echo -e "\n  ${BOLD}Severity Breakdown:${RESET}"
  printf "  ${RED}${BOLD}  CRITICAL${RESET}  %d\n"  "$crit"
  printf "  ${YELLOW}${BOLD}  HIGH    ${RESET}  %d\n"  "$high"
  printf "  ${CYAN}  MEDIUM  ${RESET}  %d\n"  "$med"
  printf "  ${GREEN}  LOW     ${RESET}  %d\n"  "$low"
  hr
  echo -e "\n  ${BOLD}MITRE ATT&CK Coverage:${RESET}"
  printf "  %-30s %d rules\n" "Initial Access:"       "$t_initial"
  printf "  %-30s %d rules\n" "Execution:"            "$t_exec"
  printf "  %-30s %d rules\n" "Persistence:"          "$t_persist"
  printf "  %-30s %d rules\n" "Privilege Escalation:" "$t_priv"
  printf "  %-30s %d rules\n" "Defense Evasion:"      "$t_evasion"
  printf "  %-30s %d rules\n" "Credential Access:"    "$t_cred"
  printf "  %-30s %d rules\n" "Discovery:"            "$t_disc"
  printf "  %-30s %d rules\n" "Lateral Movement:"     "$t_lateral"
  printf "  %-30s %d rules\n" "Collection:"           "$t_collect"
  printf "  %-30s %d rules\n" "Exfiltration:"         "$t_exfil"
  printf "  %-30s %d rules\n" "Command and Control:"  "$t_c2"
  printf "  %-30s %d rules\n" "Impact:"               "$t_impact"
  hr
  pause
}

# ════════════════════════════════════════════════════════════
#  MAIN MENU
# ════════════════════════════════════════════════════════════
main_menu() {
  seed_library
  while true; do
    banner
    local my_count; my_count=$(find "$RULES_DIR"   -name '*.yml' 2>/dev/null | wc -l)
    local lb_count; lb_count=$(find "$LIBRARY_DIR" -name '*.yml' 2>/dev/null | wc -l)

    echo -e "  ${DIM}My Rules: ${BOLD}${my_count}${RESET}${DIM}  │  Library: ${BOLD}${lb_count}${RESET}${DIM}  │  Log: siemforge.log${RESET}\n"
    hr
    echo -e "  ${CYAN}${BOLD}  1)${RESET}  Build New Detection Rule"
    echo -e "  ${CYAN}${BOLD}  2)${RESET}  Browse Rule Library          ${DIM}(50+ MITRE ATT&CK mapped)${RESET}"
    echo -e "  ${CYAN}${BOLD}  3)${RESET}  My Rules                     ${DIM}(view / delete)${RESET}"
    echo -e "  ${CYAN}${BOLD}  4)${RESET}  Export Rules                 ${DIM}(Splunk / Sentinel / QRadar)${RESET}"
    echo -e "  ${CYAN}${BOLD}  5)${RESET}  Alert Simulation             ${DIM}(FP scoring + event replay)${RESET}"
    echo -e "  ${CYAN}${BOLD}  6)${RESET}  Statistics Dashboard"
    echo -e "  ${CYAN}${BOLD}  7)${RESET}  Exit"
    hr
    printf "\n  Select option : "; read -r opt

    case "$opt" in
      1) build_rule      ;;
      2) browse_library  ;;
      3) my_rules        ;;
      4) export_rules    ;;
      5) simulate_alert  ;;
      6) show_stats      ;;
      7) echo -e "\n  ${CYAN}Goodbye, Dinesh. Stay secure.${RESET}\n"; exit 0 ;;
      *) echo -e "  ${RED}Invalid option.${RESET}"; sleep 1 ;;
    esac
  done
}

main_menu
