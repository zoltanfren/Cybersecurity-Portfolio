#!/bin/bash
# =============================================================================
# system_health.sh — Module 1: System Health
# Checks: CPU, Memory, Swap, Disk, Load Average, Zombies, I/O Pressure
# Exit codes: 0 = info | 1 = warning | 2 = critical
#
# This version uses modules/alerting.sh for:
#   - colored console output
#   - structured JSON logging
#   - automatic module name detection
# =============================================================================

set -euo pipefail  # strict error handling

# --- Project paths ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load shared alerting + configuration
# alerting.sh already loads hids.conf and handles LOG_FILE
source "$PROJECT_ROOT/modules/alerting.sh"

OVERALL=0          # tracks worst status seen (0=info, 1=warning, 2=critical)
alerts_triggered=0 # counter for summary report

# =============================================================================
# MODULE START
# =============================================================================
echo ""
echo "=========================================="
echo "  Module 1 — System Health Module"
echo "  $(date +"%Y-%m-%dT%H:%M:%S")"
echo "=========================================="

# -----------------------------------------------------------------------------
# report
# -----------------------------------------------------------------------------
# Sends the message through alerting.sh instead of writing directly to a file.
# Also keeps track of the module status for the final summary and exit code.
report() {
    local severity="$1"
    local metric="$2"
    local message="$3"

    case "$severity" in
        critical)
            print_critical "METRIC=$metric $message"
            OVERALL=2
            (( alerts_triggered++ )) || true
            ;;
        warning)
            print_warning "METRIC=$metric $message"
            [[ $OVERALL -lt 1 ]] && OVERALL=1
            (( alerts_triggered++ )) || true
            ;;
        info)
            print_info "METRIC=$metric $message"
            ;;
    esac
}

# -----------------------------------------------------------------------------
# check
# -----------------------------------------------------------------------------
# Compares a measured value against the configured thresholds.
# Logs structured output like:
#   METRIC=CPU VALUE=72 UNIT=% THRESHOLD=warning LIMIT=70
check() {
    local metric="$1"
    local value="$2"
    local info="$3"
    local warn="$4"
    local crit="$5"
    local unit="$6"

    if [[ "$value" -ge "$crit" ]]; then
        report "critical" "$metric" "VALUE=$value UNIT=$unit THRESHOLD=critical LIMIT=$crit"
    elif [[ "$value" -ge "$warn" ]]; then
        report "warning" "$metric" "VALUE=$value UNIT=$unit THRESHOLD=warning LIMIT=$warn"
    elif [[ "$value" -ge "$info" ]]; then
        report "info" "$metric" "VALUE=$value UNIT=$unit THRESHOLD=info LIMIT=$info"
    fi
}

# =============================================================================
# CHECKS
# =============================================================================
echo ""
echo "[*] Checking CPU, Memory, Swap, Disk, Load Average, Zombies, I/O Pressure..."

# CPU — two /proc/stat snapshots 1 second apart to get usage %
cpu_check() {
    read -r _ u1 n1 s1 i1 w1 _ _ _ < <(grep '^cpu ' /proc/stat)
    sleep 1
    read -r _ u2 n2 s2 i2 w2 _ _ _ < <(grep '^cpu ' /proc/stat)

    local idle=$(( (i2 + w2) - (i1 + w1) ))
    local total=$(( (u2 + n2 + s2 + i2 + w2) - (u1 + n1 + s1 + i1 + w1) ))
    local used=$(( 100 * (total - idle) / total ))

    check "CPU" "$used" "$CPU_INFO" "$CPU_WARN" "$CPU_CRIT" "%"
}

# Memory — MemAvailable is smarter than MemFree (accounts for cache)
mem_check() {
    local total avail used
    total=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
    avail=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
    used=$(( 100 * (total - avail) / total ))

    check "Memory" "$used" "$MEM_INFO" "$MEM_WARN" "$MEM_CRIT" "%"
}

# Swap — skip gracefully if no swap is configured
swap_check() {
    local total free used
    total=$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)
    free=$(awk '/^SwapFree:/  { print $2 }' /proc/meminfo)

    [[ "$total" -eq 0 ]] && return

    used=$(( 100 * (total - free) / total ))
    check "Swap" "$used" "$SWAP_INFO" "$SWAP_WARN" "$SWAP_CRIT" "%"
}

# Disk — df reads /proc/mounts internally
disk_check() {
    local used
    used=$(df --output=pcent / | tail -1 | tr -d ' %')
    check "DiskRoot" "$used" "$DISK_INFO" "$DISK_WARN" "$DISK_CRIT" "%"
}

# Load average — 1-minute value from /proc/loadavg
load_check() {
    local load
    load=$(cut -d'.' -f1 /proc/loadavg)
    check "Load1m" "$load" "$LOAD_INFO" "$LOAD_WARN" "$LOAD_CRIT" ""
}

# Zombies — count processes with State: Z in /proc/<pid>/status
zombie_check() {
    local count=0
    local f

    for f in /proc/[0-9]*/status; do
        grep -q '^State:.*Z' "$f" 2>/dev/null && (( count++ )) || true
    done

    check "Zombies" "$count" "$ZOMBIE_INFO" "$ZOMBIE_WARN" "$ZOMBIE_CRIT" ""
}

# I/O pressure — /proc/pressure/io (kernel 4.20+, skipped if absent)
io_check() {
    [[ ! -f /proc/pressure/io ]] && return

    local avg10
    avg10=$(awk '/^some/ { split($2,a,"="); printf "%d", a[2] }' /proc/pressure/io)

    check "IOPressure" "$avg10" "$IO_INFO" "$IO_WARN" "$IO_CRIT" "%"
}

cpu_check
mem_check
swap_check
disk_check
load_check
zombie_check
io_check

# =============================================================================
# MODULE SUMMARY
# =============================================================================
echo ""
echo "=========================================="
echo "  System Health Check Complete — $(date '+%Y-%m-%d %H:%M:%S')"

if [[ $alerts_triggered -eq 0 ]]; then
    echo -e "  Status : \e[32mCLEAN — no issues detected\e[0m"
else
    echo -e "  Status : \e[31m$alerts_triggered alert(s) triggered\e[0m"
fi

echo "=========================================="
echo ""

exit "$OVERALL"
