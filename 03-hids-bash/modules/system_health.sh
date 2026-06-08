#!/bin/bash
# =============================================================================
# system_health.sh — Module 1: System Health
# Checks: CPU, Memory, Swap, Disk, Load Average, Zombies, I/O Pressure
# Exit codes: 0 = info | 1 = warning | 2 = critical
# =============================================================================

set -euo pipefail  # strict error handling
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/alerting.sh"


# --- Project paths ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$PROJECT_ROOT/lib/common.sh"
source "$PROJECT_ROOT/lib/helpers.sh"
source "$PROJECT_ROOT/config/hids.conf"

LOG_FILE="$PROJECT_ROOT/logs/alerts.log"
OVERALL=0  # tracks worst status seen (0=info, 1=warning, 2=critical)

# --- Logs alerts with timestamp and severity (info/warning/critical) ----------
report() {
    local severity="$1" metric="$2" message="$3"
    # Only print to console for warning/critical (not info)
    if [[ "$severity" != "info" ]]; then
        echo "  [$severity] $metric: $message"
    fi
    # Log to file: [TIMESTAMP] [SEVERITY] [MODULE] MESSAGE
    echo "[$(date '+%Y-%m-%dT%H:%M:%SZ')] [$(printf '%s' "$severity" | tr '[:lower:]' '[:upper:]')] [system_health] $metric: $message" >> "$LOG_FILE"
    # Update OVERALL status (0=info, 1=warning, 2=critical)
    [[ "$severity" == "warning"  ]] && [[ $OVERALL -lt 1 ]] && OVERALL=1
    [[ "$severity" == "critical" ]] && OVERALL=2
}

# --- Picks info / warning / critical based on value vs 3 thresholds ----------
check() {
    local metric="$1" value="$2" info="$3" warn="$4" crit="$5" unit="$6"
    if   [[ "$value" -ge "$crit" ]]; then report "critical" "$metric" "${value}${unit} (critical: ${crit}${unit})"
    elif [[ "$value" -ge "$warn" ]]; then report "warning"  "$metric" "${value}${unit} (warning: ${warn}${unit})"
    elif [[ "$value" -ge "$info" ]]; then report "info"     "$metric" "${value}${unit} (info: ${info}${unit})"
    fi
}

# =============================================================================
# CHECKS
# =============================================================================

# CPU — two /proc/stat snapshots 1 second apart to get usage %
cpu_check() {
    read -r _ u1 n1 s1 i1 w1 _ _ _ < <(grep '^cpu ' /proc/stat)
    sleep 1
    read -r _ u2 n2 s2 i2 w2 _ _ _ < <(grep '^cpu ' /proc/stat)
    local idle=$(( (i2+w2) - (i1+w1) ))
    local total=$(( (u2+n2+s2+i2+w2) - (u1+n1+s1+i1+w1) ))
    local used=$(( 100 * (total - idle) / total ))
    check "CPU" "$used" "$CPU_INFO" "$CPU_WARN" "$CPU_CRIT" "%"
}

# Memory — MemAvailable is smarter than MemFree (accounts for cache)
mem_check() {
    local total avail used
    total=$(awk '/^MemTotal:/    { print $2 }' /proc/meminfo)
    avail=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)
    used=$(( 100 * (total - avail) / total ))
    check "Memory" "$used" "$MEM_INFO" "$MEM_WARN" "$MEM_CRIT" "%"
}

# Swap — skip gracefully if no swap is configured
swap_check() {
    local total free used
    total=$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)
    free=$(awk '/^SwapFree:/  { print $2 }' /proc/meminfo)
    [[ "$total" -eq 0 ]] && return  # silently skip if no swap
    used=$(( 100 * (total - free) / total ))
    check "Swap" "$used" "$SWAP_INFO" "$SWAP_WARN" "$SWAP_CRIT" "%"
}

# Disk — df reads /proc/mounts internally
disk_check() {
    local used
    used=$(df --output=pcent / | tail -1 | tr -d ' %')
    check "Disk(/)" "$used" "$DISK_INFO" "$DISK_WARN" "$DISK_CRIT" "%"
}

# Load average — 1-minute value from /proc/loadavg
load_check() {
    local load
    load=$(cut -d'.' -f1 /proc/loadavg)   # integer part of 1-min average
    check "Load(1m)" "$load" "$LOAD_INFO" "$LOAD_WARN" "$LOAD_CRIT" ""
}

# Zombies — count processes with State: Z in /proc/<pid>/status
zombie_check() {
    local count=0
    for f in /proc/[0-9]*/status; do
        grep -q '^State:.*Z' "$f" 2>/dev/null && (( count++ ))
    done
    check "Zombies" "$count" "$ZOMBIE_INFO" "$ZOMBIE_WARN" "$ZOMBIE_CRIT" ""
}

# I/O pressure — /proc/pressure/io (kernel 4.20+, skipped if absent)
io_check() {
    [[ ! -f /proc/pressure/io ]] && return  # silently skip if not available
    local avg10
    avg10=$(awk '/^some/ { split($2,a,"="); printf "%d", a[2] }' /proc/pressure/io)
    check "I/O Pressure" "$avg10" "$IO_INFO" "$IO_WARN" "$IO_CRIT" "%"
}

# =============================================================================
# MAIN
# =============================================================================
echo "========================================"
echo " System Health — $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

cpu_check
mem_check
swap_check
disk_check
load_check
zombie_check
io_check

echo "----------------------------------------"
case "$OVERALL" in
    0) echo " Result: info" ;;
    1) echo " Result: warning" ;;
    2) echo " Result: critical" ;;
esac
echo "========================================"

exit "$OVERALL"