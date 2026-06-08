#!/bin/bash
# =============================================================================
# system_health.sh — Module 1: System Health
# Part of bash-hids project
# Reads thresholds from config/hids.conf
# Logs alerts to logs/alerts.log
# Uses /proc for all metric reads (no external dependencies)
# Exit codes: 0 = OK, 1 = WARNING, 2 = CRITICAL
# =============================================================================

# --- Locate project root (works wherever the script is called from) ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# --- Source shared libraries -------------------------------------------------
source "$PROJECT_ROOT/lib/common.sh"
source "$PROJECT_ROOT/lib/helpers.sh"

# --- Source config (thresholds live here) ------------------------------------
CONFIG_FILE="$PROJECT_ROOT/config/hids.conf"
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo "[system_health] WARNING: config file not found at $CONFIG_FILE, using built-in defaults."
fi

# --- Default thresholds (overridden by hids.conf if it sets these vars) ------
# Warning / Critical pairs for each metric (percentages or counts)
CPU_WARN=${CPU_WARN:-70}
CPU_CRIT=${CPU_CRIT:-90}

MEM_WARN=${MEM_WARN:-75}
MEM_CRIT=${MEM_CRIT:-90}

SWAP_WARN=${SWAP_WARN:-50}
SWAP_CRIT=${SWAP_CRIT:-80}

DISK_WARN=${DISK_WARN:-75}
DISK_CRIT=${DISK_CRIT:-90}

LOAD_WARN=${LOAD_WARN:-2}      # 1-min load average
LOAD_CRIT=${LOAD_CRIT:-4}

ZOMBIE_WARN=${ZOMBIE_WARN:-5}  # number of zombie processes
ZOMBIE_CRIT=${ZOMBIE_CRIT:-10}

# --- Log file -----------------------------------------------------------------
LOG_FILE="$PROJECT_ROOT/logs/alerts.log"
MODULE="system_health"

# --- Helper: write a line to the alert log ------------------------------------
log_alert() {
    local severity="$1"   # OK / WARNING / CRITICAL
    local metric="$2"
    local message="$3"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$severity] [$MODULE] $metric: $message" >> "$LOG_FILE"
}

# --- Helper: print coloured status to stdout ----------------------------------
print_status() {
    local severity="$1"
    local metric="$2"
    local message="$3"
    case "$severity" in
        OK)       echo "  [  OK  ] $metric — $message" ;;
        WARNING)  echo "  [ WARN ] $metric — $message" ;;
        CRITICAL) echo "  [ CRIT ] $metric — $message" ;;
    esac
}

# --- Tracking overall exit code ----------------------------------------------
# We keep the worst severity seen across all checks.
# 0=OK, 1=WARNING, 2=CRITICAL
OVERALL_STATUS=0

update_status() {
    local new="$1"   # 1 or 2
    if [[ "$new" -gt "$OVERALL_STATUS" ]]; then
        OVERALL_STATUS="$new"
    fi
}

# =============================================================================
# CHECK 1 — CPU usage
# /proc/stat gives cumulative CPU ticks. We take two snapshots 1 second apart
# to calculate the usage percentage over that interval.
# =============================================================================
check_cpu() {
    # Read two lines from /proc/stat, 1 second apart
    local line1 line2
    line1=$(grep '^cpu ' /proc/stat)
    sleep 1
    line2=$(grep '^cpu ' /proc/stat)

    # Fields: cpu user nice system idle iowait irq softirq steal ...
    read -r _ u1 n1 s1 i1 w1 _ _ _ <<< "$line1"
    read -r _ u2 n2 s2 i2 w2 _ _ _ <<< "$line2"

    local idle1=$(( i1 + w1 ))
    local idle2=$(( i2 + w2 ))
    local total1=$(( u1 + n1 + s1 + i1 + w1 ))
    local total2=$(( u2 + n2 + s2 + i2 + w2 ))

    local delta_idle=$(( idle2 - idle1 ))
    local delta_total=$(( total2 - total1 ))

    # Avoid divide-by-zero
    if [[ "$delta_total" -eq 0 ]]; then
        print_status "OK" "CPU" "could not calculate (no tick delta)"
        return
    fi

    local cpu_used=$(( 100 * (delta_total - delta_idle) / delta_total ))

    if [[ "$cpu_used" -ge "$CPU_CRIT" ]]; then
        print_status "CRITICAL" "CPU" "${cpu_used}% used (threshold: ${CPU_CRIT}%)"
        log_alert "CRITICAL" "CPU" "${cpu_used}% used"
        update_status 2
    elif [[ "$cpu_used" -ge "$CPU_WARN" ]]; then
        print_status "WARNING" "CPU" "${cpu_used}% used (threshold: ${CPU_WARN}%)"
        log_alert "WARNING" "CPU" "${cpu_used}% used"
        update_status 1
    else
        print_status "OK" "CPU" "${cpu_used}% used"
    fi
}

# =============================================================================
# CHECK 2 — Memory usage
# /proc/meminfo contains MemTotal, MemAvailable (and others).
# Used = Total - Available  (MemAvailable accounts for caches/buffers)
# =============================================================================
check_memory() {
    local mem_total mem_available
    mem_total=$(awk '/^MemTotal:/ { print $2 }' /proc/meminfo)
    mem_available=$(awk '/^MemAvailable:/ { print $2 }' /proc/meminfo)

    local mem_used=$(( mem_total - mem_available ))
    local mem_pct=$(( 100 * mem_used / mem_total ))

    if [[ "$mem_pct" -ge "$MEM_CRIT" ]]; then
        print_status "CRITICAL" "Memory" "${mem_pct}% used (threshold: ${MEM_CRIT}%)"
        log_alert "CRITICAL" "Memory" "${mem_pct}% used"
        update_status 2
    elif [[ "$mem_pct" -ge "$MEM_WARN" ]]; then
        print_status "WARNING" "Memory" "${mem_pct}% used (threshold: ${MEM_WARN}%)"
        log_alert "WARNING" "Memory" "${mem_pct}% used"
        update_status 1
    else
        print_status "OK" "Memory" "${mem_pct}% used"
    fi
}

# =============================================================================
# CHECK 3 — Swap usage
# /proc/meminfo also has SwapTotal and SwapFree.
# =============================================================================
check_swap() {
    local swap_total swap_free
    swap_total=$(awk '/^SwapTotal:/ { print $2 }' /proc/meminfo)
    swap_free=$(awk '/^SwapFree:/ { print $2 }' /proc/meminfo)

    # If no swap is configured, skip gracefully
    if [[ "$swap_total" -eq 0 ]]; then
        print_status "OK" "Swap" "no swap configured"
        return
    fi

    local swap_used=$(( swap_total - swap_free ))
    local swap_pct=$(( 100 * swap_used / swap_total ))

    if [[ "$swap_pct" -ge "$SWAP_CRIT" ]]; then
        print_status "CRITICAL" "Swap" "${swap_pct}% used (threshold: ${SWAP_CRIT}%)"
        log_alert "CRITICAL" "Swap" "${swap_pct}% used"
        update_status 2
    elif [[ "$swap_pct" -ge "$SWAP_WARN" ]]; then
        print_status "WARNING" "Swap" "${swap_pct}% used (threshold: ${SWAP_WARN}%)"
        log_alert "WARNING" "Swap" "${swap_pct}% used"
        update_status 1
    else
        print_status "OK" "Swap" "${swap_pct}% used"
    fi
}

# =============================================================================
# CHECK 4 — Disk space (root filesystem)
# /proc/mounts lists all mounted filesystems. We use the 'read' built-in with
# df (which itself reads /proc/mounts) — this is the standard POSIX way.
# We target the root mount point "/".
# =============================================================================
check_disk() {
    # df reads kernel data ultimately sourced from /proc/mounts + statfs()
    local disk_pct
    disk_pct=$(df --output=pcent / | tail -1 | tr -d ' %')

    if [[ "$disk_pct" -ge "$DISK_CRIT" ]]; then
        print_status "CRITICAL" "Disk(/)" "${disk_pct}% used (threshold: ${DISK_CRIT}%)"
        log_alert "CRITICAL" "Disk(/)" "${disk_pct}% used"
        update_status 2
    elif [[ "$disk_pct" -ge "$DISK_WARN" ]]; then
        print_status "WARNING" "Disk(/)" "${disk_pct}% used (threshold: ${DISK_WARN}%)"
        log_alert "WARNING" "Disk(/)" "${disk_pct}% used"
        update_status 1
    else
        print_status "OK" "Disk(/)" "${disk_pct}% used"
    fi
}

# =============================================================================
# CHECK 5 — Load average
# /proc/loadavg contains three space-separated values: 1-min, 5-min, 15-min.
# We use the 1-minute load average and compare as an integer for simplicity.
# =============================================================================
check_load() {
    local load_raw load_int
    load_raw=$(cut -d' ' -f1 /proc/loadavg)          # e.g. "1.45"
    load_int=$(echo "$load_raw" | cut -d'.' -f1)      # integer part only

    if [[ "$load_int" -ge "$LOAD_CRIT" ]]; then
        print_status "CRITICAL" "Load(1m)" "${load_raw} (threshold: ${LOAD_CRIT})"
        log_alert "CRITICAL" "Load(1m)" "${load_raw}"
        update_status 2
    elif [[ "$load_int" -ge "$LOAD_WARN" ]]; then
        print_status "WARNING" "Load(1m)" "${load_raw} (threshold: ${LOAD_WARN})"
        log_alert "WARNING" "Load(1m)" "${load_raw}"
        update_status 1
    else
        print_status "OK" "Load(1m)" "${load_raw}"
    fi
}

# =============================================================================
# CHECK 6 — Zombie processes
# /proc/loadavg field 4 is "running/total" processes.
# Each process has a status in /proc/<pid>/status — state "Z" = zombie.
# We count them directly from /proc.
# =============================================================================
check_zombies() {
    local zombie_count=0

    # Loop over every numeric directory in /proc (each is a PID)
    for pid_dir in /proc/[0-9]*/status; do
        # Check if the State line shows Z (zombie)
        if grep -q '^State:.*Z' "$pid_dir" 2>/dev/null; then
            zombie_count=$(( zombie_count + 1 ))
        fi
    done

    if [[ "$zombie_count" -ge "$ZOMBIE_CRIT" ]]; then
        print_status "CRITICAL" "Zombies" "${zombie_count} zombie processes (threshold: ${ZOMBIE_CRIT})"
        log_alert "CRITICAL" "Zombies" "${zombie_count} zombie processes"
        update_status 2
    elif [[ "$zombie_count" -ge "$ZOMBIE_WARN" ]]; then
        print_status "WARNING" "Zombies" "${zombie_count} zombie processes (threshold: ${ZOMBIE_WARN})"
        log_alert "WARNING" "Zombies" "${zombie_count} zombie processes"
        update_status 1
    else
        print_status "OK" "Zombies" "${zombie_count} zombie processes"
    fi
}

# =============================================================================
# CHECK 7 — Disk I/O pressure
# /proc/pressure/io (available on kernels 4.20+) reports the % of time tasks
# stalled waiting on I/O. "some" avg10 = last 10-second average.
# High I/O pressure can indicate crypto-miners, log flooding, or exfiltration.
# =============================================================================
check_io_pressure() {
    local IO_PRESSURE_FILE="/proc/pressure/io"

    if [[ ! -f "$IO_PRESSURE_FILE" ]]; then
        print_status "OK" "I/O Pressure" "not available on this kernel (skipped)"
        return
    fi

    # Line looks like: some avg10=0.50 avg60=0.30 avg300=0.10 total=...
    local avg10
    avg10=$(grep '^some' "$IO_PRESSURE_FILE" | awk -F'avg10=' '{print $2}' | cut -d' ' -f1)

    # Convert float to integer for comparison (drop decimal)
    local avg10_int
    avg10_int=$(echo "$avg10" | cut -d'.' -f1)

    # Reuse disk thresholds or define dedicated ones — using simple defaults here
    local IO_WARN=${IO_WARN:-20}
    local IO_CRIT=${IO_CRIT:-50}

    if [[ "$avg10_int" -ge "$IO_CRIT" ]]; then
        print_status "CRITICAL" "I/O Pressure" "avg10=${avg10}% stalled (threshold: ${IO_CRIT}%)"
        log_alert "CRITICAL" "I/O Pressure" "avg10=${avg10}% stalled"
        update_status 2
    elif [[ "$avg10_int" -ge "$IO_WARN" ]]; then
        print_status "WARNING" "I/O Pressure" "avg10=${avg10}% stalled (threshold: ${IO_WARN}%)"
        log_alert "WARNING" "I/O Pressure" "avg10=${avg10}% stalled"
        update_status 1
    else
        print_status "OK" "I/O Pressure" "avg10=${avg10}% stalled"
    fi
}

# =============================================================================
# MAIN — run all checks and report overall status
# =============================================================================
main() {
    echo "============================================"
    echo " System Health Check — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "============================================"

    check_cpu
    check_memory
    check_swap
    check_disk
    check_load
    check_zombies
    check_io_pressure

    echo "--------------------------------------------"
    case "$OVERALL_STATUS" in
        0) echo " Overall: OK" ;;
        1) echo " Overall: WARNING — review metrics above" ;;
        2) echo " Overall: CRITICAL — immediate attention required" ;;
    esac
    echo "============================================"

    exit "$OVERALL_STATUS"
}

main