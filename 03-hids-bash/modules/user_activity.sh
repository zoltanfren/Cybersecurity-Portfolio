#!/bin/bash
# =============================================================================
# user_activity.sh — Module 2: User Activity
# Checks: Impossible timestamps, new users, privilege escalation, unusual IPs
# Exit codes: 0 = info | 1 = warning | 2 = critical
# =============================================================================

set -euo pipefail

# --- Project paths ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$PROJECT_ROOT/config/hids.conf"

LOG_FILE="$PROJECT_ROOT/logs/alerts.log"
OVERALL=0

report() {
    local severity="$1" metric="$2" message="$3"
    if [[ "$severity" != "info" ]]; then
        echo "  [$severity] $metric: $message"
    fi
    echo "[$(date '+%Y-%m-%dT%H:%M:%SZ')] [$(printf '%s' "$severity" | tr '[:lower:]' '[:upper:]')] [user_activity] $metric: $message" >> "$LOG_FILE"
    [[ "$severity" == "warning"  ]] && [[ $OVERALL -lt 1 ]] && OVERALL=1
    [[ "$severity" == "critical" ]] && OVERALL=2
}

# --- 1. Impossible Timestamps ---
# Flags logins that happened outside extended business hours
timestamp_check() {
    local odd_logins
    odd_logins=$(last -F | awk -v start="$BUSINESS_HOURS_START" -v end="$BUSINESS_HOURS_END" '
        /still logged in/ || /logged in/ { next }
        {
            hour = substr($7, 1, 2)
            if (hour+0 < start || hour+0 >= end) print $0
        }
    ' | head -5)

    if [[ -n "$odd_logins" ]]; then
        report "warning" "Impossible Timestamp" "Logins detected outside business hours (before ${BUSINESS_HOURS_START}:00 or after ${BUSINESS_HOURS_END}:00)"
    else
        report "info" "Impossible Timestamp" "All logins within business hours"
    fi
}

# --- 2. New Resident Users ---
# Counts regular users (UID 1000+) and warns if count has increased
user_count_check() {
    local current_count expected_count
    current_count=$(awk -F: '$3 >= 1000 && $3 < 65534 { count++ } END { print count+0 }' /etc/passwd)
    expected_count="${EXPECTED_USER_COUNT:-1}"

    if [[ "$current_count" -gt "$expected_count" ]]; then
        report "critical" "New User Detected" "Expected ${expected_count} user(s), found ${current_count}. A new account may have been created!"
    else
        report "info" "User Count" "${current_count} regular user(s) — normal"
    fi
}

# --- 3. Privilege Escalation (sudo trail) ---
# Looks for sudo usage in systemd journal
sudo_check() {
    local sudo_events
    sudo_events=$(journalctl _COMM=sudo --since "1 hour ago" --no-pager -q 2>/dev/null | wc -l)

    if [[ "$sudo_events" -ge "${CRIT_SUDO_COUNT:-10}" ]]; then
        report "critical" "Privilege Escalation" "High sudo activity: ${sudo_events} sudo events in the last hour!"
    elif [[ "$sudo_events" -ge "${WARN_SUDO_COUNT:-3}" ]]; then
        report "warning" "Privilege Escalation" "${sudo_events} sudo events in the last hour — possible escalation attempt"
    else
        report "info" "Sudo Trail" "${sudo_events} sudo event(s) in last hour — normal"
    fi
}

# --- 4. Unusual Source IPs ---
# Reads SSH login IPs from journal and flags anything outside allowed range
ip_check() {
    local unusual_ips
    unusual_ips=$(journalctl _COMM=sshd --since "1 hour ago" --no-pager -q 2>/dev/null \
        | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" \
        | sort -u \
        | grep -v "^${ALLOWED_IP_RANGE}" || true)

    if [[ -n "$unusual_ips" ]]; then
        report "warning" "Unusual Source IP" "SSH attempts from outside allowed range: $unusual_ips"
    else
        report "info" "Source IPs" "All SSH activity within allowed IP range"
    fi
}

# =============================================================================
# MAIN
# =============================================================================
echo "========================================"
echo " User Activity — $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

timestamp_check
user_count_check
sudo_check
ip_check

echo "----------------------------------------"
case "$OVERALL" in
    0) echo " Result: info" ;;
    1) echo " Result: warning" ;;
    2) echo " Result: critical" ;;
esac
echo "========================================"

exit "$OVERALL"