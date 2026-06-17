#!/bin/bash

# ==============================================================================
# generate_baseline.sh
# Creates initial file integrity baseline for HIDS
# Supports --force for non-interactive overwrite (used by install.sh)
# ==============================================================================

# ------------------------------------------------------------------------------
# Project root detection
# ------------------------------------------------------------------------------
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------------------
# Load config + alerting
# ------------------------------------------------------------------------------
source "$PROJECT_ROOT/config/hids.conf"
source "$PROJECT_ROOT/modules/alerting.sh"

# ------------------------------------------------------------------------------
# Arguments
# ------------------------------------------------------------------------------
FORCE=false
if [[ "$1" == "--force" ]]; then
    FORCE=true
fi

# ------------------------------------------------------------------------------
# Resolve paths
# ------------------------------------------------------------------------------
BASELINE_FILE="$PROJECT_ROOT/$FILE_BASELINE_DB"
LOG_FILE="$PROJECT_ROOT/$FILE_ALERT_LOG"

# ------------------------------------------------------------------------------
# Ensure directories exist
# ------------------------------------------------------------------------------
mkdir -p "$PROJECT_ROOT/data"
mkdir -p "$PROJECT_ROOT/logs"

# ------------------------------------------------------------------------------
# Root check
# ------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: generate_baseline.sh must be run as root." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# Overwrite logic
# ------------------------------------------------------------------------------
if [[ -f "$BASELINE_FILE" ]]; then
    if [[ "$FORCE" == true ]]; then
        echo "Force mode enabled — overwriting existing baseline"
        rm -f "$BASELINE_FILE"
    else
        echo "Baseline already exists: $BASELINE_FILE"
        read -rp "Overwrite baseline? (yes/no): " confirm
        [[ "$confirm" != "yes" ]] && {
            echo "Baseline generation cancelled."
            exit 0
        }
        rm -f "$BASELINE_FILE"
    fi
fi

# ------------------------------------------------------------------------------
# Critical files monitored
# ------------------------------------------------------------------------------
CRITICAL_FILES=(
    /etc/passwd
    /etc/shadow
    /etc/group
    /etc/gshadow
    /etc/sudoers
    /etc/ssh/sshd_config
    /etc/pam.d/common-auth
    /etc/pam.d/sshd
    /etc/crontab
    /etc/hostname
    /etc/hosts
    /root/.ssh/authorized_keys
)

# ------------------------------------------------------------------------------
# Create baseline
# ------------------------------------------------------------------------------
echo "Generating file integrity baseline..."

{
    echo "# HIDS File Integrity Baseline"
    echo "# Generated: $(date +%Y-%m-%dT%H:%M:%S)"
    echo "# Format: filepath|sha256|permissions|owner"
} > "$BASELINE_FILE"

recorded=0
skipped=0

for file in "${CRITICAL_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "Skipping missing file: $file"
        ((skipped++))
        continue
    fi

    hash=$(sha256sum "$file" 2>/dev/null | awk '{print $1}')
    perm=$(stat -c '%a' "$file" 2>/dev/null)
    owner=$(stat -c '%U' "$file" 2>/dev/null)

    echo "$file|$hash|$perm|$owner" >> "$BASELINE_FILE"
    ((recorded++))
done

# ------------------------------------------------------------------------------
# SUID baseline
# ------------------------------------------------------------------------------
echo "# SUID_BINARIES" >> "$BASELINE_FILE"

find / -perm -4000 -type f 2>/dev/null | sort | while read -r f; do
    echo "SUID|$f" >> "$BASELINE_FILE"
done

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo ""
echo "================================================"
echo "  Baseline generation complete"
echo "  Files recorded : $recorded"
echo "  Files skipped  : $skipped"
echo "  Saved to       : $BASELINE_FILE"
echo "================================================"
echo ""

echo "Baseline successfully generated ($recorded files)"

exit 0