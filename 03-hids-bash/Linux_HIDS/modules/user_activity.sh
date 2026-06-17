#!/bin/bash
# =============================================================================
# user_activity.sh — Module 2: User Activity
# Purpose : Monitors user logins and system access patterns for suspicious activity.
#           Detects impossible timestamps, new users, privilege escalation, unusual IPs.
# Usage   : bash user_activity.sh
#           Called automatically by run_hids.sh on each scheduled run
# Depends : journalctl (systemd journal), last (login history), /etc/passwd
# =============================================================================

set -uo pipefail

# --- Project paths ---
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/." && pwd)"
source "$PROJECT_ROOT/../config/hids.conf"
source "$PROJECT_ROOT/../config/whitelist.conf"
source "$PROJECT_ROOT/../modules/alerting.sh"  # Source shared alerting module

# --- 1. Impossible Timestamps ---
# Flags logins that happened outside extended business hours
timestamp_check() {
    local odd_logins count=0
    odd_logins=$(last -F | awk -v start="$BUSINESS_HOURS_START" -v end="$BUSINESS_HOURS_END" '
        /^$/ { next }  # skip empty lines
        {
            hour = substr($7, 1, 2)
            if (hour+0 < start || hour+0 >= end) print $1, $3, $7, $8, $9, $10
        }
    ')

    if [[ -n "$odd_logins" ]]; then
        while IFS=' ' read -r user ip date time tz; do
            [[ -z "$user" ]] && continue
            [[ " $WHITELISTED_USERS " == *" $user "* ]] && continue
            print_warning "Impossible Timestamp: User \"$user\" login from $ip at $date $time $tz (outside ${BUSINESS_HOURS_START}:00-${BUSINESS_HOURS_END}:00)"
            (( count++ )) || true
    done <<< "$odd_logins"
        [[ $count -eq 0 ]] && echo "Impossible Timestamp: All logins within business hours"
    else
        echo "Impossible Timestamp: All logins within business hours"
    fi
}

# --- 2. New Resident Users ---
# Counts regular users (UID 1000+) and warns if count has increased
user_count_check() {
    local current_count expected_count
    current_count=$(awk -F: '$3 >= 1000 && $3 < 65534 { count++ } END { print count+0 }' /etc/passwd)
    expected_count="${EXPECTED_USER_COUNT:-1}"

    if [[ "$current_count" -gt "$expected_count" ]]; then
        print_critical "New User Detected: Expected ${expected_count} user(s), found ${current_count}. A new account may have been created!"
    else
        echo "User Count: ${current_count} regular user(s) — normal"
    fi
}

# --- 3. Privilege Escalation (sudo trail) ---
# Looks for sudo usage in systemd journal
sudo_check() {
    local sudo_events
    sudo_events=$(journalctl _COMM=sudo --since "1 hour ago" --no-pager -q 2>/dev/null | wc -l)

    if [[ "$sudo_events" -ge "${CRIT_SUDO_COUNT:-10}" ]]; then
        print_critical "Privilege Escalation: High sudo activity: ${sudo_events} sudo events in the last hour!"
    elif [[ "$sudo_events" -ge "${WARN_SUDO_COUNT:-3}" ]]; then
        print_warning "Privilege Escalation: ${sudo_events} sudo events in the last hour — possible escalation attempt"
    else
        echo "Sudo Trail: ${sudo_events} sudo event(s) in last hour — normal"
    fi
}

# --- 4. Unusual Source IPs ---
# Reads SSH login IPs from journal and flags anything outside allowed range
ip_check() {
    local count=0
    local ssh_entries
    
    ssh_entries=$(journalctl _COMM=sshd --since "1 hour ago" --no-pager 2>/dev/null \
        | grep -E "Accepted|Failed" \
        | grep -oE "user=[^ ]+ from ([0-9]{1,3}\.){3}[0-9]{1,3}" \
        | sort -u || true)

    if [[ -n "$ssh_entries" ]]; then
        while IFS='=' read -r _ rest; do
            local user_and_ip="$rest"
            local user=$(echo "$user_and_ip" | awk '{print $1}')
            local ip=$(echo "$user_and_ip" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
            
            if [[ -n "$ip" && ! "$ip" =~ ^${ALLOWED_IP_RANGE} ]]; then
                print_warning "Unusual Source IP: SSH login from $ip for user \"$user\" (outside allowed range: ${ALLOWED_IP_RANGE}*)"
                (( count++ ))
            fi
        done <<< "$ssh_entries"
        [[ $count -eq 0 ]] && echo "Source IPs: All SSH activity within allowed IP range"
    else
        echo "Source IPs: All SSH activity within allowed IP range"
    fi
}

# =============================================================================
# MODULE START
# =============================================================================
echo ""
echo "=========================================="
echo "  Module 2 — User Activity Check"
echo "  $(date +"%Y-%m-%dT%H:%M:%S")"
echo "=========================================="
echo ""
echo "[*] Scanning for impossible timestamps, new users, privilege escalation, unusual IPs..."
echo ""

timestamp_check
user_count_check
sudo_check
ip_check


# =============================================================================
# MODULE SUMMARY
# =============================================================================
echo ""
echo "=========================================="
echo "  User Activity Check Complete — $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Log : $LOG_FILE"
echo "=========================================="
echo ""

exit 0

