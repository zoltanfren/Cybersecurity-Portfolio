#!/usr/bin/env bash

# Print an informational message.
print_info() {
  echo -e "\e[34m[INFO]\e[0m $1"
}

# Print a warning message.
print_warning() {
  echo -e "\e[38;5;208m[WARNING]\e[0m $1"
}

# Print a critical warning message.
print_critical() {
  echo -e "\e[31m[CRITICAL]\e[0m $1"
}
