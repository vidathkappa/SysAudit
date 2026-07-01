#!/usr/bin/env bash
# SysAuditv3.sh - Real-time Ubuntu system audit with tee
set -o pipefail

PROGNAME="$(basename "$0")"
VERSION="3.0"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S %z')"
HOSTNAME="$(hostname --fqdn 2>/dev/null || hostname)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTDIR="$SCRIPT_DIR"
REPORT_FILE="$OUTDIR/system_audit_${HOSTNAME}_$(date '+%Y%m%d_%H%M%S').txt"
JSON_FILE="${REPORT_FILE%.txt}.json"

CRITICAL=0
WARNINGS=0
SCORE=100

### Helper functions
section() { echo -e "\n\n==== $1 ===="; }
subsection() { echo -e "\n-- $1 --"; }
run() { echo "\$ $*"; "$@" 2>&1 | sed 's/^/    /' || true; }
pass() { echo "PASS: $*"; }
warn() { echo "WARN: $*"; WARNINGS=$((WARNINGS+1)); SCORE=$((SCORE-5)); }
fail() { echo "CRITICAL: $*"; CRITICAL=1; SCORE=$((SCORE-15)); }

### Initialization
ensure_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 3
  fi
}

prepare_output() {
  {
    echo "Ubuntu System Audit v$VERSION"
    echo "Hostname: $HOSTNAME"
    echo "Started: $TIMESTAMP"
    echo ""
  } > "$REPORT_FILE"
  # Redirect all output to both terminal and report file
  exec > >(tee -a "$REPORT_FILE") 2>&1
  echo "Report file: $REPORT_FILE"
}

### Sections
system_info() {
  section "System Information"
  run uname -a
  run lsb_release -a 2>/dev/null || run cat /etc/os-release
  run uptime -p
  run cat /etc/machine-id 2>/dev/null || true
  run timedatectl status
  run locale 2>/dev/null || true
  run env | sort | sed -n '1,20p'
  run cat /proc/cmdline
}

packages() {
  section "Package Management"
  if command -v apt >/dev/null; then
    run apt update -y >/dev/null 2>&1 || true
    run apt list --upgradable 2>/dev/null | sed -n '1,20p'
    run dpkg --audit 2>/dev/null || true
    run apt-mark showhold 2>/dev/null || true
    UPDATES=$(apt list --upgradable 2>/dev/null | sed '1d' | sed '/^$/d' | wc -l)
    UPDATES=${UPDATES:-0}
    if [ "$UPDATES" -gt 0 ]; then
      warn "$UPDATES packages upgradable"
    else
      pass "No package upgrades available"
    fi
  else
    warn "APT not available"
  fi
}

boot_analysis() {
  section "Boot Analysis"
  if command -v systemd-analyze >/dev/null; then
    run systemd-analyze
    run systemd-analyze blame | sed -n '1,10p'
    run systemd-analyze critical-chain --no-pager | sed -n '1,20p'
  fi
  FAILED=$(systemctl --failed --no-legend 2>/dev/null | wc -l)
  if [ "$FAILED" -gt 0 ]; then
    warn "$FAILED failed systemd units"
  else
    pass "No failed systemd units"
  fi
}

journal_analysis() {
  section "Journal Analysis"
  ERR_COUNT=$(journalctl -p 3 -xb --no-pager | wc -l)
  run journalctl -p 3 -xb --no-pager | sed -n '1,20p'
  if [ "$ERR_COUNT" -gt 0 ]; then
    warn "Journal contains $ERR_COUNT error lines since last boot"
  else
    pass "No recent journal errors"
  fi
}

cpu_audit() {
  section "CPU Audit"
  run lscpu
  run cat /proc/loadavg
  if command -v sensors >/dev/null; then run sensors | sed -n '1,10p'; fi
}

memory_audit() {
  section "Memory Audit"
  run free -h
  SWAP_TOTAL=$(free -b | awk '/Swap:/ {print $2}')
  SWAP_TOTAL=${SWAP_TOTAL:-0}
  if [ "$SWAP_TOTAL" -eq 0 ]; then
    warn "No swap configured"
  else
    pass "Swap present"
  fi
}

storage_audit() {
  section "Storage Audit"
  run lsblk -o NAME,SIZE,TYPE,MOUNTPOINT
  run df -hT | sed -n '1,20p'
  HIGH=$(df -h --output=pcent,target | awk 'NR>1 {gsub(/%/,""); if ($1+0 >= 90) print $0}' | wc -l)
  if [ "$HIGH" -gt 0 ]; then
    warn "One or more filesystems >=90% usage"
  else
    pass "Filesystem usage within limits"
  fi
}

smart_audit() {
  section "SMART Audit"
  if command -v smartctl >/dev/null; then
    for dev in $(lsblk -ndo NAME,TYPE | awk '$2=="disk"{print $1}' | grep -Ev '^(zram|loop|ram|sr|md|dm-)'); do
      DEV="/dev/$dev"
      run smartctl -H "$DEV" 2>/dev/null || true
      if ! smartctl -H "$DEV" 2>/dev/null | grep -iq "PASSED"; then
        warn "SMART reports issues on $DEV"
      else
        pass "SMART OK on $DEV"
      fi
    done
  else
    echo "smartctl not installed; skipping SMART checks"
  fi
}

firewall_audit() {
  section "Firewall Audit"
  if command -v ufw >/dev/null; then
    run ufw status verbose
    if ufw status | grep -iq inactive; then
      warn "UFW inactive"
    else
      pass "UFW active"
    fi
  fi
}

analysis() {
  section "Analysis Engine and Recommendations"
  if grep -q "filesystem >=90% usage" "$REPORT_FILE"; then
    warn "Root filesystem near capacity; consider cleaning or expanding storage"
  fi
  echo "Recommendation: Keep system updated, enable unattended-upgrades."
  echo "Recommendation: Schedule monthly SMART self-tests and backups."
}

health_score() {
  section "Health Scoring"
  [ "$SCORE" -lt 0 ] && SCORE=0
  [ "$SCORE" -gt 100 ] && SCORE=100
  echo "Overall Health Score: $SCORE / 100"
  echo "Critical issues: $CRITICAL"
  echo "Warnings: $WARNINGS"
}

final_summary() {
  section "Final Summary"
  echo "Finished: $(date '+%Y-%m-%d %H:%M:%S %z')"
  echo "Report: $REPORT_FILE"
  cat > "$JSON_FILE" <<EOF
{
  "hostname": "$HOSTNAME",
  "timestamp": "$TIMESTAMP",
  "score": $SCORE,
  "critical": $CRITICAL,
  "warnings": $WARNINGS,
  "report": "$REPORT_FILE"
}
EOF
  echo "JSON summary: $JSON_FILE"
}

### Main
main() {
  ensure_root
  prepare_output
  system_info
  packages
  boot_analysis
  journal_analysis
  cpu_audit
  memory_audit
  storage_audit
  smart_audit
  firewall_audit
  analysis
  health_score
  final_summary
}

main "$@"
