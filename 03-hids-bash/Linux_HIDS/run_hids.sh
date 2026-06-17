#!/bin/bash

# ==============================================================================
# run_hids.sh — HIDS Orchestrator (DUAL MODE)
# Interactive when run in terminal
# Automatic when run by systemd/cron
# ==============================================================================

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ------------------------------------------------------------------------------
# Load dependencies
# ------------------------------------------------------------------------------
source "$PROJECT_ROOT/modules/alerting.sh"
source "$PROJECT_ROOT/config/hids.conf"

BASELINE_FULL_PATH="$PROJECT_ROOT/$FILE_BASELINE_DB"

mkdir -p "$PROJECT_ROOT/data"
mkdir -p "$PROJECT_ROOT/logs"

# ------------------------------------------------------------------------------
# MODE DETECTION
# ------------------------------------------------------------------------------
INTERACTIVE=false
if [[ -t 0 && -t 1 ]]; then
    INTERACTIVE=true
fi

SKIP_FILE_INTEGRITY=false

# ------------------------------------------------------------------------------
# BASELINE HANDLING
# ------------------------------------------------------------------------------
if [[ "$INTERACTIVE" == true ]]; then

    echo ""
    echo "=========================================="
    echo "  File Integrity Baseline Setup"
    echo "=========================================="
    
    if [[ ! -f "$BASELINE_FULL_PATH" ]]; then
        echo "No baseline found."
        echo "[1] Create baseline"
        echo "[2] Skip file integrity module"
        read -rp "Choice: " choice
        
        case "$choice" in
            1) sudo bash "$PROJECT_ROOT/generate_baseline.sh" ;;
            2) SKIP_FILE_INTEGRITY=true ;;
            *) echo "Invalid choice"; exit 1 ;;
        esac
    else
        echo "Baseline exists: $BASELINE_FULL_PATH"
        echo "[1] Use existing"
        echo "[2] Regenerate"
        echo "[3] Skip file integrity"
        read -rp "Choice: " choice
        
        case "$choice" in
            1) ;;
            2) sudo bash "$PROJECT_ROOT/generate_baseline.sh" --force ;;
            3) SKIP_FILE_INTEGRITY=true ;;
            *) echo "Invalid choice"; exit 1 ;;
        esac
    fi

else
    # AUTOMATIC MODE (NO PROMPTS)
    if [[ ! -f "$BASELINE_FULL_PATH" ]]; then
        echo "No baseline found → generating automatically"
        sudo bash "$PROJECT_ROOT/generate_baseline.sh" --force
    fi
fi

# ------------------------------------------------------------------------------
# MODULE SELECTION
# ------------------------------------------------------------------------------
if [[ "$INTERACTIVE" == true ]]; then

    echo ""
    echo "=========================================="
    echo "  HIDS Module Selection"
    echo "=========================================="
    echo "[0] All modules"
    echo "[1] System Health"
    echo "[2] User Activity"
    echo "[3] Process & Network"
    echo "[4] File Integrity"
    read -rp "Choice: " module_choice

    RUN1=false; RUN2=false; RUN3=false; RUN4=false

    if [[ "$module_choice" == "0" ]]; then
        RUN1=true; RUN2=true; RUN3=true; RUN4=true
    else
        for m in $module_choice; do
            [[ "$m" == "1" ]] && RUN1=true
            [[ "$m" == "2" ]] && RUN2=true
            [[ "$m" == "3" ]] && RUN3=true
            [[ "$m" == "4" ]] && RUN4=true
        done
    fi

else
    # AUTOMATIC MODE - RUN ALL MODULES
    RUN1=true; RUN2=true; RUN3=true; RUN4=true
fi

[[ "$SKIP_FILE_INTEGRITY" == true ]] && RUN4=false

# ------------------------------------------------------------------------------
# EXECUTION
# ------------------------------------------------------------------------------
echo ""
echo "=========================================="
echo "  HIDS RUN START"
echo "=========================================="

[[ "$RUN1" == true ]] && bash "$PROJECT_ROOT/modules/system_health.sh"
[[ "$RUN2" == true ]] && bash "$PROJECT_ROOT/modules/user_activity.sh"
[[ "$RUN3" == true ]] && bash "$PROJECT_ROOT/modules/process_network.sh"
[[ "$RUN4" == true ]] && bash "$PROJECT_ROOT/modules/file_integrity.sh"

echo ""
echo "HIDS execution completed"