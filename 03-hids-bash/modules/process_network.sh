#!/usr/bin/env bash
#
# suspicious_process_paths.sh
#
# PURPOSE:
#   This script inspects all running processes on a Linux system and flags
#   potentially suspicious ones based on:
#
#   1. Where the executable is located (filesystem analysis)
#   2. How the process was launched (command-line inspection)
#   3. What network activity it performs (network behavior analysis)
#
# WHY THIS MATTERS:
#   Attackers often:
#   - Run binaries from writable locations like /tmp or /dev/shm
#   - Use interpreters (bash, python) to execute payloads
#   - Maintain network connections (C2, reverse shells, exfiltration)
#
#   This script applies simple heuristics to detect these behaviors.
#

set -u  # Fail if undefined variables are used (safer scripting)

# ---------------------------------------------------------
# Resolve script directory (important for portability)
# ---------------------------------------------------------
# This ensures that relative paths work even if the script
# is executed from another directory.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# Load alerting functions (print_info, print_warning, print_critical)
source "${SCRIPT_DIR}/alerting.sh"

# Path to whitelist file (exact executable paths allowed)
WHITELIST_FILE="${SCRIPT_DIR}/../config/whitelist.conf"

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

# Paths that are suspicious because they are writable or ephemeral
# Attackers frequently drop payloads here
SUSPICIOUS_PATHS=(
  "/tmp/"
  "/var/tmp/"
  "/dev/shm/"
  "/run/user/"
  "/home/"
  "/root/"
)

# Trusted system binary locations
# Most legitimate OS binaries live here
TRUSTED_PATHS=(
  "/bin/"
  "/usr/bin/"
  "/usr/sbin/"
  "/usr/local/bin/"
)

# Suspicious command-line patterns
# These indicate inline execution or data transfer tools
SUSPICIOUS_CMD_PATTERNS=(
  "bash -c"
  "sh -c"
  "python -c"
  "curl "
  "wget "
  "nc "
  "base64"
  "/dev/tcp/"
)

# Suspicious ports (often used in C2 or reverse shells)
SUSPICIOUS_PORTS=("4444" "1337" "5555" "8081")

# Threshold for "too many" connections
ESTABLISHED_CONN_THRESHOLD=8

# ---------------------------------------------------------
# WHITELIST LOADING
# ---------------------------------------------------------

# Store allowed executable paths
WHITELIST=()

load_whitelist() {
  local line

  [[ -f "$WHITELIST_FILE" ]] || return

  while IFS= read -r line || [[ -n "$line" ]]; do
    # Ignore empty lines and comments
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    WHITELIST+=("$line")
  done < "$WHITELIST_FILE"
}

# Check if executable is explicitly allowed
is_whitelisted() {
  local exe_path="$1"
  local entry

  for entry in "${WHITELIST[@]}"; do
    [[ "$exe_path" == "$entry" ]] && return 0
  done

  return 1
}

# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

# Check if executable is from trusted system paths
is_trusted_path() {
  local exe="$1"
  for path in "${TRUSTED_PATHS[@]}"; do
    [[ "$exe" == "$path"* ]] && return 0
  done
  return 1
}

# Check if executable is from suspicious locations
is_suspicious_path() {
  local exe="$1"
  for path in "${SUSPICIOUS_PATHS[@]}"; do
    [[ "$exe" == "$path"* ]] && return 0
  done
  return 1
}

# Detect suspicious command-line patterns
is_suspicious_cmdline() {
  local cmd="$1"
  for pattern in "${SUSPICIOUS_CMD_PATTERNS[@]}"; do
    [[ "$cmd" == *"$pattern"* ]] && return 0
  done
  return 1
}

# Extract executable path
get_exe_path() {
  readlink -f "$1/exe" 2>/dev/null
}

# Extract raw symlink (used to detect deleted binaries)
get_exe_link() {
  readlink "$1/exe" 2>/dev/null
}

# Extract command-line (convert null bytes → spaces)
get_cmdline() {
  tr '\0' ' ' < "$1/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//'
}

# ---------------------------------------------------------
# NETWORK ANALYSIS
# ---------------------------------------------------------

# Store per-process network stats
declare -A PID_ESTAB_COUNT
declare -A PID_LISTEN_COUNT

# Collect network activity using ss
collect_network() {
  command -v ss >/dev/null || return

  while read -r line; do
    # Extract PID from ss output
    [[ "$line" =~ pid=([0-9]+) ]] || continue
    pid="${BASH_REMATCH[1]}"

    # Check connection state
    case "$line" in
      LISTEN*)
        PID_LISTEN_COUNT["$pid"]=$(( ${PID_LISTEN_COUNT[$pid]:-0} + 1 ))
        ;;
      ESTAB*)
        PID_ESTAB_COUNT["$pid"]=$(( ${PID_ESTAB_COUNT[$pid]:-0} + 1 ))
        ;;
    esac

  done < <(ss -ntupH 2>/dev/null)
}

# ---------------------------------------------------------
# MAIN LOGIC
# ---------------------------------------------------------

load_whitelist
collect_network

print_info "Analyzing processes..."

for proc_dir in /proc/[0-9]*; do
  pid="${proc_dir##*/}"
  [[ -d "$proc_dir" ]] || continue

  exe="$(get_exe_path "$proc_dir")"
  [[ -n "$exe" ]] || continue

  # Skip trusted processes
  if is_whitelisted "$exe"; then
    continue
  fi

  cmd="$(get_cmdline "$proc_dir")"
  user="$(ps -p "$pid" -o user= | xargs)"
  ppid="$(awk '/^PPid:/ {print $2}' "$proc_dir/status")"

  [[ -z "$cmd" ]] && cmd="$exe"

  score=0
  reasons=()

  # -------------------------
  # PATH-BASED DETECTION
  # -------------------------

  if is_suspicious_path "$exe"; then
    score=$((score+3))
    reasons+=("suspicious_path")
  fi

  if ! is_trusted_path "$exe"; then
    score=$((score+1))
    reasons+=("untrusted_path")
  fi

  # Deleted binary detection
  exe_link="$(get_exe_link "$proc_dir")"
  if [[ "$exe_link" == *"(deleted)"* ]]; then
    score=$((score+5))
    reasons+=("deleted_binary")
  fi

  # Root process from unusual location
  if [[ "$user" == "root" ]] && ! is_trusted_path "$exe"; then
    score=$((score+4))
    reasons+=("root_untrusted")
  fi

  # -------------------------
  # COMMAND-LINE DETECTION
  # -------------------------

  if is_suspicious_cmdline "$cmd"; then
    score=$((score+2))
    reasons+=("suspicious_cmdline")
  fi

  # -------------------------
  # NETWORK DETECTION
  # -------------------------

  estab="${PID_ESTAB_COUNT[$pid]:-0}"
  listen="${PID_LISTEN_COUNT[$pid]:-0}"

  # Untrusted binary with network activity
  if [[ "$estab" -gt 0 ]] && ! is_trusted_path "$exe"; then
    score=$((score+3))
    reasons+=("network_activity_untrusted_binary")
  fi

  # Many outbound connections (possible beaconing or scanning)
  if [[ "$estab" -ge $ESTABLISHED_CONN_THRESHOLD ]]; then
    score=$((score+2))
    reasons+=("many_connections")
  fi

  # Untrusted listener
  if [[ "$listen" -gt 0 ]] && ! is_trusted_path "$exe"; then
    score=$((score+2))
    reasons+=("untrusted_listener")
  fi

  # -------------------------
  # OUTPUT DECISION
  # -------------------------

  [[ $score -gt 0 ]] || continue

  reason_text="$(IFS=,; echo "${reasons[*]}")"

  if [[ $score -ge 7 ]]; then
    print_critical "PID=$pid USER=$user SCORE=$score REASONS=$reason_text EXE=$exe CMD=\"$cmd\""
  elif [[ $score -ge 4 ]]; then
    print_warning "PID=$pid USER=$user SCORE=$score REASONS=$reason_text EXE=$exe CMD=\"$cmd\""
  else
    print_info "PID=$pid USER=$user SCORE=$score REASONS=$reason_text EXE=$exe CMD=\"$cmd\""
  fi
done

print_info "Analysis complete."
