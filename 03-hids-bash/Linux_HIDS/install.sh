#!/bin/bash
# =============================================================================
# install.sh — HIDS system installer (NON-INTERACTIVE)
# =============================================================================

set -e

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"

SERVICE_FILE="/etc/systemd/system/hids.service"
TIMER_FILE="/etc/systemd/system/hids.timer"

# -----------------------------------------------------------------------------
# Root check
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run as root"
    exit 1
fi

echo "[+] Installing HIDS..."

# -----------------------------------------------------------------------------
# Prepare directories
# -----------------------------------------------------------------------------
mkdir -p "$PROJECT_ROOT/data"
mkdir -p "$PROJECT_ROOT/logs"

# -----------------------------------------------------------------------------
# Cleanup duplicates
# -----------------------------------------------------------------------------
[[ -d "$PROJECT_ROOT/modules/data" ]] && rm -rf "$PROJECT_ROOT/modules/data"

# -----------------------------------------------------------------------------
# AUTO baseline generation
# -----------------------------------------------------------------------------
echo "[+] Ensuring baseline..."
if [[ ! -f "$PROJECT_ROOT/data/file_baseline.db" ]]; then
    bash "$PROJECT_ROOT/generate_baseline.sh" --force
fi

# -----------------------------------------------------------------------------
# Create systemd service
# -----------------------------------------------------------------------------
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=HIDS Service
After=network.target

[Service]
Type=oneshot
WorkingDirectory=$PROJECT_ROOT
ExecStart=/bin/bash $PROJECT_ROOT/run_hids.sh
EOF

# -----------------------------------------------------------------------------
# Create timer
# -----------------------------------------------------------------------------
cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Run HIDS every 60 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=60min
Unit=hids.service

[Install]
WantedBy=timers.target
EOF

# -----------------------------------------------------------------------------
# Enable systemd timer
# -----------------------------------------------------------------------------
systemctl daemon-reload
systemctl enable hids.timer
systemctl restart hids.timer

echo "[✓] HIDS installed and running"
echo "Runs automatically every 60 minutes"
