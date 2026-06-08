#!/bin/bash
# =============================================================================
# file_integrity.sh — Module 4
# Purpose : Detects unauthorized changes to critical system files by comparing
#           current file hashes against the stored baseline.
#           Also scans for dangerous permission misconfigurations (SUID, world-writable).
# Usage   : sudo bash file_integrity.sh
#           Called automatically by run_hids.sh on each scheduled run
# Depends : data/file_baseline.db must exist (run generate_baseline.sh first)
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURATION
# Paths are relative to the project root (one level up from modules/)
# When called from run_hids.sh, these paths will resolve correctly
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BASELINE_FILE="$SCRIPT_DIR/data/file_baseline.db"
LOG_FILE="$SCRIPT_DIR/logs/alerts.log"

# -----------------------------------------------------------------------------
# ALERT FUNCTION — PLACEHOLDER
# TODO: Replace this entire function with a call to alerting.sh once it is ready
# Expected final form: source "$SCRIPT_DIR/modules/alerting.sh" then call alert()
#
# Current placeholder format matches the agreed team log format:
# TIMESTAMP SEVERITY MODULE MESSAGE
# Example: 2026-04-13T14:32:01 CRITICAL file_integrity Hash mismatch: /etc/passwd
# -----------------------------------------------------------------------------
alert() {
    local severity="$1"   # INFO | WARNING | CRITICAL
    local message="$2"
    local timestamp
    timestamp=$(date +"%Y-%m-%dT%H:%M:%S")
    local log_line="$timestamp $severity file_integrity $message"

    # Write to persistent log file
    echo "$log_line" >> "$LOG_FILE"

    # Print to terminal with color coding
    case "$severity" in
        CRITICAL) echo -e "\e[31m[CRITICAL]\e[0m $message" ;;   # red
        WARNING)  echo -e "\e[33m[WARNING]\e[0m  $message" ;;   # yellow
        INFO)     echo -e "\e[32m[INFO]\e[0m     $message" ;;   # green
    esac
}

# -----------------------------------------------------------------------------
# SAFETY CHECK: root required
# /etc/shadow and other sensitive files are only readable by root
# Without root, sha256sum will return empty hashes and all comparisons will fail
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] file_integrity.sh must be run as root."
    exit 1
fi

# -----------------------------------------------------------------------------
# BASELINE EXISTENCE CHECK
# If the baseline doesn't exist yet, we cannot compare — instruct the user
# -----------------------------------------------------------------------------
if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "[ERROR] No baseline found at: $BASELINE_FILE"
    echo "Run generate_baseline.sh first to create the baseline."
    exit 1
fi

# -----------------------------------------------------------------------------
# DIRECTORY CHECK
# Ensure the logs/ directory exists before we try to write to it
# -----------------------------------------------------------------------------
mkdir -p "$(dirname "$LOG_FILE")"

# =============================================================================
# MODULE START
# =============================================================================
echo ""
echo "=========================================="
echo "  Module 4 — File Integrity Check"
echo "  $(date +"%Y-%m-%dT%H:%M:%S")"
echo "=========================================="

alerts_triggered=0

# =============================================================================
# PART 1 — HASH COMPARISON AGAINST BASELINE
# Read each line from the baseline file, skip comments and SUID entries,
# recompute the hash of each file, and compare with the stored value
# =============================================================================
echo ""
echo "[*] Checking file hashes against baseline..."

while IFS='|' read -r filepath stored_hash stored_perms stored_owner; do

    # Skip comment lines (start with #) and SUID lines and empty lines
    [[ "$filepath" =~ ^#.*$ ]] && continue
    [[ "$filepath" =~ ^SUID ]] && continue
    [[ -z "$filepath" ]] && continue

    # --- FILE EXISTENCE CHECK ---
    # If a critical file has disappeared since baseline, that is itself suspicious
    if [[ ! -f "$filepath" ]]; then
        alert "CRITICAL" "File missing — was present at baseline: $filepath"
        ((alerts_triggered++))
        continue
    fi

    # --- HASH COMPARISON ---
    # Recompute the current SHA-256 hash
    current_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')

    if [[ "$current_hash" != "$stored_hash" ]]; then
        alert "CRITICAL" "Hash mismatch detected: $filepath"
        alert "CRITICAL" "  Expected : $stored_hash"
        alert "CRITICAL" "  Current  : $current_hash"
        ((alerts_triggered++))
    else
        alert "INFO" "OK: $filepath"
    fi

    # --- PERMISSIONS COMPARISON ---
    # Check if permissions have changed since baseline — dangerous if /etc/shadow becomes world-readable
    current_perms=$(stat -c '%a' "$filepath" 2>/dev/null)
    if [[ "$current_perms" != "$stored_perms" ]]; then
        alert "WARNING" "Permissions changed on $filepath (was: $stored_perms, now: $current_perms)"
        ((alerts_triggered++))
    fi

    # --- OWNER COMPARISON ---
    # Check if the file owner has changed — root-owned files being reassigned is suspicious
    current_owner=$(stat -c '%U' "$filepath" 2>/dev/null)
    if [[ "$current_owner" != "$stored_owner" ]]; then
        alert "WARNING" "Owner changed on $filepath (was: $stored_owner, now: $current_owner)"
        ((alerts_triggered++))
    fi

done < "$BASELINE_FILE"

# =============================================================================
# PART 2 — NEW SUID BINARIES
# Compare current SUID binaries against those recorded in the baseline
# Any SUID binary NOT in the baseline is a CRITICAL alert
# Attackers plant SUID binaries to maintain persistent root access
# =============================================================================
echo ""
echo "[*] Checking for new SUID binaries..."

# Extract the baseline SUID list into a temporary array
mapfile -t baseline_suid < <(grep "^SUID|" "$BASELINE_FILE" | cut -d'|' -f2)

# Scan the live system for all current SUID binaries
while read -r current_suid; do

    # Check if this SUID binary was in the baseline
    found=0
    for known in "${baseline_suid[@]}"; do
        if [[ "$current_suid" == "$known" ]]; then
            found=1
            break
        fi
    done

    if [[ $found -eq 0 ]]; then
        alert "CRITICAL" "New SUID binary detected (not in baseline): $current_suid"
        ((alerts_triggered++))
    fi

done < <(find / -perm -4000 -type f 2>/dev/null | sort)

# =============================================================================
# PART 3 — WORLD-WRITABLE FILES IN SENSITIVE DIRECTORIES
# World-writable means any user on the system can modify the file
# We focus on sensitive directories where this would be most dangerous
# =============================================================================
echo ""
echo "[*] Scanning for world-writable files in sensitive directories..."

# Directories where world-writable files are always dangerous
SENSITIVE_DIRS=(/etc /bin /sbin /usr/bin /usr/sbin /root)

for dir in "${SENSITIVE_DIRS[@]}"; do
    if [[ ! -d "$dir" ]]; then
        continue
    fi

    # find files in this directory that are world-writable (-perm -002)
    while read -r ww_file; do
        alert "CRITICAL" "World-writable file in sensitive directory: $ww_file"
        ((alerts_triggered++))
    done < <(find "$dir" -perm -002 -type f 2>/dev/null)
done

# =============================================================================
# PART 4 — RECENTLY MODIFIED FILES IN /etc (last 24 hours)
# This is a secondary check — catches changes to files not in our baseline
# Uses find -mtime -1 (modified within the last 1 day)
# Note: timestamps can be faked by root — this is a supporting signal, not primary
# =============================================================================
echo ""
echo "[*] Checking for recently modified files in /etc (last 24h)..."

while read -r recent_file; do
    # Skip files we already monitor via hash — they are handled above
    alert "WARNING" "File modified in /etc within last 24h: $recent_file"
    ((alerts_triggered++))
done < <(find /etc -mtime -1 -type f 2>/dev/null)

# =============================================================================
# MODULE SUMMARY
# =============================================================================
echo ""
echo "=========================================="
echo "  File Integrity Check Complete"
if [[ $alerts_triggered -eq 0 ]]; then
    echo -e "  Status : \e[32mCLEAN — no issues detected\e[0m"
else
    echo -e "  Status : \e[31m$alerts_triggered alert(s) triggered\e[0m"
fi
echo "  Log    : $LOG_FILE"
echo "=========================================="
echo ""

# Return exit code 1 if any alerts were triggered
# run_hids.sh can use this to know if this module found something
[[ $alerts_triggered -gt 0 ]] && exit 1 || exit 0
