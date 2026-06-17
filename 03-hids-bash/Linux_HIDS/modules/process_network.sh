#!/usr/bin/env bash
#
# suspicious_process_paths.sh
#
# =============================================================================
# PURPOSE
# =============================================================================
# This script inspects all running processes on a Linux system and flags
# potentially suspicious ones based on three main ideas:
#
#   1. Filesystem location of the executable
#      - Is the binary running from a trusted system directory?
#      - Is it running from a suspicious writable directory like /tmp?
#
#   2. Command-line behavior
#      - Does the command line contain known suspicious patterns?
#      - Examples: interpreter abuse, payload execution, reverse-shell style usage
#
#   3. Network behavior
#      - Does the process open listening sockets?
#      - Does it make many outbound connections?
#      - Is a non-trusted process also talking on the network?
#
# =============================================================================
# WHY THIS MATTERS
# =============================================================================
# Attackers often try to avoid detection by:
#
#   - Launching malware from writable folders such as /tmp or /dev/shm
#   - Running payloads with tools like bash, python, or sh
#   - Keeping network connections open to a command-and-control server
#   - Deleting the binary from disk after launch to hide evidence
#
# This script does NOT prove malware exists.
# Instead, it applies lightweight heuristics to highlight processes that deserve
# closer inspection.
#
# =============================================================================
# IMPORTANT DESIGN NOTES
# =============================================================================
# - The script reads process information from /proc.
# - It does NOT execute the binaries it inspects.
# - Kernel threads are skipped because they are not normal user-space programs.
# - Exact-path whitelisting is supported through the whitelist.conf file.
# - More general trust is controlled by TRUSTED_PATHS in hids.conf.
#
# This makes the script safer and reduces false positives.
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------
# Resolve the absolute path of the current script directory.
# ---------------------------------------------------------
# This makes the script portable. It will still find the
# config files correctly even if launched from another folder.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------
# Load alert helpers and shared configuration.
# ---------------------------------------------------------
# alerting.sh provides:
#   - print_info
#   - print_warning
#   - print_critical
#
# It also loads hids.conf, which may define:
#   - TRUSTED_PATHS
#   - SUSPICIOUS_PATHS
#   - SUSPICIOUS_CMD_PATTERNS
#   - ESTABLISHED_CONN_THRESHOLD
source "${SCRIPT_DIR}/alerting.sh"

# ---------------------------------------------------------
# Path to whitelist file.
# ---------------------------------------------------------
# This file contains exact executable paths that should be
# ignored by this module.
#
# Example:
#   /usr/libexec/gvfsd
#   /usr/lib/xorg/Xorg
#
# IMPORTANT:
# This file must be READ line by line.
# It must NOT be sourced as shell code.
WHITELIST_FILE="${SCRIPT_DIR}/../config/whitelist.conf"



# ---------------------------------------------------------
# is_whitelisted
# ---------------------------------------------------------
# Returns success (0) if the executable path exactly matches
# an entry in the whitelist array.
is_whitelisted() {
  local exe_path="$1"
  local entry

  for entry in "${WHITELISTED_PROCESSES[@]}"; do
    [[ "$exe_path" == "$entry" ]] && return 0
  done

  return 1
}

# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------

# ---------------------------------------------------------
# is_trusted_path
# ---------------------------------------------------------
# Checks whether an executable is considered generally trusted.
#
# Trust is decided in two layers:
#   1. exact match in whitelist.conf
#   2. path prefix match against TRUSTED_PATHS from hids.conf
#
# Examples of trusted path prefixes may include:
#   /usr/bin
#   /usr/sbin
#   /usr/lib
#   /usr/libexec
#   /bin
#   /sbin
#
# Note:
# A trusted path does NOT automatically mean a process is safe.
# It simply means its filesystem location is less suspicious.
is_trusted_path() {
  local exe="$1"
  local path

  if is_whitelisted "$exe"; then
    return 0
  fi

  if declare -p TRUSTED_PATHS >/dev/null 2>&1; then
    for path in "${TRUSTED_PATHS[@]}"; do
      [[ "$exe" == "$path"* ]] && return 0
    done
  fi

  return 1
}

# ---------------------------------------------------------
# is_suspicious_path
# ---------------------------------------------------------
# Checks whether an executable is running from a location
# considered suspicious.
#
# Typical suspicious locations:
#   /tmp
#   /var/tmp
#   /dev/shm
#
# These are common places for attackers to stage temporary payloads.
is_suspicious_path() {
  local exe="$1"
  local path

  if declare -p SUSPICIOUS_PATHS >/dev/null 2>&1; then
    for path in "${SUSPICIOUS_PATHS[@]}"; do
      [[ "$exe" == "$path"* ]] && return 0
    done
  fi

  return 1
}

# ---------------------------------------------------------
# is_suspicious_cmdline
# ---------------------------------------------------------
# Checks whether the process command line contains a suspicious
# pattern defined in SUSPICIOUS_CMD_PATTERNS.
#
# Example patterns might be:
#   nc -e
#   bash -i
#   curl|sh
#   python -c
#
# These patterns are heuristic only, not proof of compromise.
is_suspicious_cmdline() {
  local cmd="$1"
  local pattern

  if declare -p SUSPICIOUS_CMD_PATTERNS >/dev/null 2>&1; then
    for pattern in "${SUSPICIOUS_CMD_PATTERNS[@]}"; do
      [[ "$cmd" == *"$pattern"* ]] && return 0
    done
  fi

  return 1
}

# ---------------------------------------------------------
# get_exe_path
# ---------------------------------------------------------
# Resolves the real executable path behind /proc/<pid>/exe.
#
# readlink -f follows symlinks and returns the canonical path.
# If resolution fails, return an empty string instead of failing.
get_exe_path() {
  readlink -e "$1/exe" 2>/dev/null || true
}

# ---------------------------------------------------------
# get_exe_link
# ---------------------------------------------------------
# Reads the raw symbolic link target of /proc/<pid>/exe.
#
# This is useful for detecting deleted binaries, because Linux
# may show something like:
#   /tmp/malware (deleted)
get_exe_link() {
  readlink "$1/exe" 2>/dev/null || true
}

# ---------------------------------------------------------
# get_cmdline
# ---------------------------------------------------------
# Reads /proc/<pid>/cmdline, which stores the command line
# separated by null bytes instead of spaces.
#
# tr '\0' ' ' converts null bytes to normal spaces.
# sed removes trailing whitespace.
get_cmdline() {
  tr '\0' ' ' < "$1/cmdline" 2>/dev/null | sed 's/[[:space:]]*$//'
}

# ---------------------------------------------------------
# get_comm
# ---------------------------------------------------------
# Reads the short process name from /proc/<pid>/comm.
#
# This is useful when cmdline is empty.
# Some system processes and daemons do not expose a full command line.
get_comm() {
  cat "$1/comm" 2>/dev/null || true
}

# ---------------------------------------------------------
# is_kernel_thread
# ---------------------------------------------------------
# Detects kernel threads so they can be skipped.
#
# Why skip them?
# Kernel threads are not normal user-space programs:
#   - they usually do not have a real executable path
#   - they often have an empty cmdline
#   - they are not launched from the filesystem
#
# Without this check, the script may incorrectly treat them
# as suspicious "/proc/<pid>/exe" processes.
is_kernel_thread() {
  local proc_dir="$1"
  local exe cmd

  exe="$(get_exe_path "$proc_dir")"
  cmd="$(get_cmdline "$proc_dir")"

  [[ -z "$exe" && -z "$cmd" ]]
}

# ---------------------------------------------------------
# NETWORK ANALYSIS
# ---------------------------------------------------------
# Two associative arrays store per-process network statistics:
#   PID_ESTAB_COUNT  = number of established TCP connections
#   PID_LISTEN_COUNT = number of listening sockets
declare -A PID_ESTAB_COUNT
declare -A PID_LISTEN_COUNT

# ---------------------------------------------------------
# collect_network
# ---------------------------------------------------------
# Uses the 'ss' command to inspect live TCP sockets and map
# network activity to process IDs.
#
# - LISTEN means the process is waiting for inbound connections
# - ESTAB  means the process currently has an established TCP session
#
# Example use cases:
#   - unexpected listeners
#   - suspicious binaries with outbound traffic
#   - very large numbers of connections
collect_network() {
  local line pid

  command -v ss >/dev/null 2>&1 || return 0

  while IFS= read -r line; do
    [[ "$line" =~ pid=([0-9]+) ]] || continue
    pid="${BASH_REMATCH[1]}"

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
# MAIN EXECUTION
# ---------------------------------------------------------

echo "=========================================="
echo "Module 3 — Process and Network Check"
echo "$(date +"%Y-%m-%dT%H:%M:%S")"
echo "=========================================="

collect_network

counter=0

echo "[*] Analyzing processes and network activity..."

# ---------------------------------------------------------
# Walk through every numeric /proc directory.
# ---------------------------------------------------------
# Each /proc/<pid> folder represents one running process.
for proc_dir in /proc/[0-9]*; do
  pid="${proc_dir##*/}"
  [[ -d "$proc_dir" ]] || continue

  # Skip kernel threads to avoid false positives.
  if is_kernel_thread "$proc_dir"; then
    continue
  fi

  # Resolve executable metadata.
  exe="$(get_exe_path "$proc_dir")"
  exe_link="$(get_exe_link "$proc_dir")"

  # If there is no real executable path and it is not a deleted binary,
  # skip the process because there is not enough meaningful evidence.
  if [[ -z "$exe" && "$exe_link" != *"(deleted)"* ]]; then
    continue
  fi

  # Skip explicitly whitelisted executables.
  if [[ -n "$exe" ]] && is_whitelisted "$exe"; then
    continue
  fi

  # Collect process metadata.
  cmd="$(get_cmdline "$proc_dir")"
  comm="$(get_comm "$proc_dir")"
  user="$(ps -p "$pid" -o user= 2>/dev/null | xargs)"
  ppid="$(awk '/^PPid:/ {print $2}' "$proc_dir/status" 2>/dev/null || true)"

  # If cmdline is empty, fall back to executable path or short process name.
  [[ -z "$cmd" ]] && cmd="${exe:-$comm}"

  # Initialize a risk score and reason list.
  # The score grows when suspicious indicators are found.
  score=0
  reasons=()

  # -------------------------------------------------------
  # PATH-BASED DETECTION
  # -------------------------------------------------------

  # Strong signal:
  # The executable is running from a suspicious path such as /tmp.
  if [[ -n "$exe" ]] && is_suspicious_path "$exe"; then
    score=$((score + 4))
    reasons+=("suspicious_path")
  fi

  # Weak signal:
  # The executable is not in a trusted path, but also not in a known
  # suspicious path. This may be legitimate custom software, so it is
  # given only a small score.
  if [[ -n "$exe" ]] && ! is_trusted_path "$exe" && ! is_suspicious_path "$exe"; then
    score=$((score + 1))
    reasons+=("untrusted_path")
  fi

  # Strong signal:
  # The executable file was deleted after launch.
  # This can be a normal admin action in rare cases, but it is often
  # associated with stealthy or temporary malware.
  if [[ "$exe_link" == *"(deleted)"* ]]; then
    score=$((score + 5))
    reasons+=("deleted_binary")
  fi

  # Medium signal:
  # A root-owned process from a non-trusted path deserves extra attention.
  # Many legitimate daemons run as root, so this only adds weight when
  # combined with an unusual path.
  if [[ "$user" == "root" ]] && [[ -n "$exe" ]] && is_suspicious_path "$exe"; then
    score=$((score + 2))
    reasons+=("root_suspicious_path")
  fi

  # -------------------------------------------------------
  # COMMAND-LINE DETECTION
  # -------------------------------------------------------

  # Medium signal:
  # Some command-line patterns are commonly seen in malicious activity
  # or post-exploitation tradecraft.
  if is_suspicious_cmdline "$cmd"; then
    score=$((score + 2))
    reasons+=("suspicious_cmdline")
  fi

  # -------------------------------------------------------
  # NETWORK DETECTION
  # -------------------------------------------------------

  estab="${PID_ESTAB_COUNT[$pid]:-0}"
  listen="${PID_LISTEN_COUNT[$pid]:-0}"

  # Medium/strong signal:
  # A non-trusted process that is actively communicating on the network
  # deserves closer review.
  if [[ "$estab" -gt 0 ]] && [[ -n "$exe" ]] && ! is_trusted_path "$exe"; then
    score=$((score + 3))
    reasons+=("network_activity_untrusted_binary")
  fi

  # Medium signal:
  # A very large number of established outbound connections may suggest
  # scanning, beaconing, proxy behavior, or mass communication.
  threshold="${ESTABLISHED_CONN_THRESHOLD:-10}"
  if [[ "$estab" -ge "$threshold" ]]; then
    score=$((score + 2))
    reasons+=("many_connections")
  fi

  # Medium signal:
  # A process outside trusted paths that is listening for inbound
  # connections may represent a backdoor, rogue service, or test server.
  if [[ "$listen" -gt 0 ]] && [[ -n "$exe" ]] && ! is_trusted_path "$exe"; then
    score=$((score + 2))
    reasons+=("untrusted_listener")
  fi

  # If the score is still zero, there is no reason to alert.
  [[ $score -gt 3 ]] || continue

  counter=$((counter + 1))
  reason_text="$(IFS=,; echo "${reasons[*]}")"

  # -------------------------------------------------------
  # OUTPUT DECISION
  # -------------------------------------------------------
  # Use the final score to choose severity:
  #
  #   0      = ignore
  #   1-3    = informational
  #   4-6    = warning
  #   7 or + = critical
  #
  # Output includes structured KEY=value pairs so that Splunk
  # or another log collector can extract and sort the fields.
  if [[ $score -ge 6 ]]; then
    print_critical "PID=$pid USER=$user PPID=$ppid SCORE=$score ESTAB=$estab LISTEN=$listen REASONS=$reason_text EXE=$exe CMD=\"$cmd\""
  elif [[ $score -ge 4 ]]; then
    print_warning "PID=$pid USER=$user PPID=$ppid SCORE=$score ESTAB=$estab LISTEN=$listen REASONS=$reason_text EXE=$exe CMD=\"$cmd\""
  else
    print_info "PID=$pid USER=$user PPID=$ppid SCORE=$score ESTAB=$estab LISTEN=$listen REASONS=$reason_text EXE=$exe CMD=\"$cmd\""
  fi
done

echo "=========================================="
echo "Process and Network Check complete"
echo "Status: $counter alert(s) triggered"
echo "=========================================="
