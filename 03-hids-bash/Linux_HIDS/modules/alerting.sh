#!/usr/bin/env bash

# Get the folder where this script itself is located.
# dirname -- "${BASH_SOURCE[0]}" gets the script's directory.
# cd into that directory, then pwd prints the full absolute path.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# PROJECT_ROOT is set to the parent directory of SCRIPT_DIR.
# If the script is in modules/, then PROJECT_ROOT becomes the main project folder.
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

# Load configuration values from hids.conf.
# source runs the file in the current shell so variables become available here.
source "${PROJECT_ROOT}/config/hids.conf"

# Remove any carriage return characters from LOG_FILE.
# This is useful if hids.conf was edited on Windows, where lines may end with \r\n.
LOG_FILE="${LOG_FILE//$'\r'/}"

# If LOG_FILE is empty or unset, use config/events.jsonl as a default.
# The :- syntax means "use this default if variable is unset or empty".
LOG_FILE="${LOG_FILE:-config/events.jsonl}"

# If LOG_FILE is not an absolute path, make it relative to the project root.
case "$LOG_FILE" in
  /*) ;;  # If it starts with /, it is already an absolute path, so do nothing.
  *) LOG_FILE="${PROJECT_ROOT}/${LOG_FILE}" ;;  # Otherwise prepend project root.
esac

# Extract only the directory part from the log file path.
LOG_DIR="$(dirname "$LOG_FILE")"

# Create the log directory if it does not exist.
# mkdir -p creates parent directories as needed.
# If it fails, print an error to stderr and exit.
mkdir -p "$LOG_DIR" || {
  echo "[ERROR] Could not create log directory: $LOG_DIR" >&2
  exit 1
}

# Create the log file if it does not exist.
# touch creates an empty file or updates its timestamp.
touch "$LOG_FILE" || {
  echo "[ERROR] Could not create log file: $LOG_FILE" >&2
  exit 1
}

# Escapes special characters so a string can safely be written inside JSON.
json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; :a;N;$!ba; s/\n/\\n/g'
}

# Converts a field name into a safe JSON key:
# - lowercase only
# - replace non-alphanumeric characters with underscores
sanitize_json_key() {
  printf '%s' "$1" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9_]/_/g'
}

# Finds the name of the script/module that called this logging script.
# Example: if process_network.sh called print_warning, module becomes "process_network".
get_source_module() {
  local caller_frame caller_file module_name

  # caller shows the calling line and file from the call stack.
  # Try level 2 first, then level 1 if needed.
  caller_frame="$(caller 2 2>/dev/null || caller 1 2>/dev/null)"

  # Extract the 3rd field from caller output, which is the file path.
  caller_file="$(printf '%s' "$caller_frame" | awk '{print $3}')"

  # basename removes directory path, and .sh removes the extension.
  module_name="$(basename "${caller_file:-unknown}" .sh)"

  printf '%s' "$module_name"
}

# Extracts KEY=value pairs from a message and converts them into JSON fields.
# Example:
#   message='PID=123 USER=root CMD="bash -i"'
# becomes:
#   "pid":"123","user":"root","cmd":"bash -i"
extract_message_fields_json() {
  local remaining="$1"
  local pair key raw_value value safe_key escaped_value json_fields=""
  local kv_regex='([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|[^[:space:]]+)'

  # Repeatedly search for KEY=value patterns in the remaining string.
  # Supports:
  #   PID=123
  #   USER=root
  #   CMD="bash -i"
  while [[ $remaining =~ $kv_regex ]]; do
    pair="${BASH_REMATCH[0]}"      # Entire match, e.g. PID=123
    key="${BASH_REMATCH[1]}"       # Key only, e.g. PID
    raw_value="${BASH_REMATCH[2]}" # Value only, e.g. 123 or "bash -i"

    # If the value is surrounded by double quotes, remove them.
    if [[ ${raw_value:0:1} == "\"" && ${raw_value: -1} == "\"" ]]; then
      value="${raw_value:1:${#raw_value}-2}"
    else
      value="$raw_value"
    fi

    # Make the key safe for JSON and Splunk-style field naming.
    safe_key="$(sanitize_json_key "$key")"

    # Escape special JSON characters in the value.
    escaped_value="$(json_escape "$value")"

    # Append the field to the JSON fragment.
    json_fields+="\"${safe_key}\":\"${escaped_value}\","

    # Remove the matched part so the next loop finds the next pair.
    remaining="${remaining#*"$pair"}"
  done

  # Remove trailing comma if there is one.
  json_fields="${json_fields%,}"

  # Remove one trailing space if present.
  json_fields="${json_fields% }"

  printf '%s' "$json_fields"
}

# Writes one log entry in JSON format into the log file.
write_json_log() {
  local level="$1"
  local message="$2"
  local timestamp escaped_message source_module parsed_fields_json

  # Generate UTC timestamp in ISO 8601 style.
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  # Escape message so it is valid JSON.
  escaped_message="$(json_escape "$message")"

  # Get the name of the caller module and escape it too.
  source_module="$(json_escape "$(get_source_module)")"

  # Extract KEY=value subfields from the message.
  parsed_fields_json="$(extract_message_fields_json "$message")"

  # If fields were found, write full JSON with extra subfields.
  if [[ -n "$parsed_fields_json" ]]; then
    if ! printf '{"timestamp":"%s","level":"%s","module":"%s","message":"%s",%s}\n' \
      "$timestamp" "$level" "$source_module" "$escaped_message" "$parsed_fields_json" >> "$LOG_FILE"; then
      echo "[ERROR] Failed to write to log file: $LOG_FILE" >&2
      return 1
    fi
  else
    # Otherwise write basic JSON only.
    if ! printf '{"timestamp":"%s","level":"%s","module":"%s","message":"%s"}\n' \
      "$timestamp" "$level" "$source_module" "$escaped_message" >> "$LOG_FILE"; then
      echo "[ERROR] Failed to write to log file: $LOG_FILE" >&2
      return 1
    fi
  fi
}

# Prints an INFO message in blue on the terminal and logs it as JSON.
print_info() {
  local message="$1"
  echo -e "\e[34m[INFO]\e[0m $message"
  write_json_log "INFO" "$message"
}

# Prints a WARNING message in orange on the terminal and logs it as JSON.
print_warning() {
  local message="$1"
  echo -e "\e[38;5;208m[WARNING]\e[0m $message"
  write_json_log "WARNING" "$message"
}

# Prints a CRITICAL message in red on the terminal and logs it as JSON.
print_critical() {
  local message="$1"
  echo -e "\e[31m[CRITICAL]\e[0m $message"
  write_json_log "CRITICAL" "$message"
}
