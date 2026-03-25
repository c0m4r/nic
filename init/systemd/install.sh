#!/bin/bash
set -e

echo "Installing nic for systemd..."

# Disable and mask systemd-networkd and systemd-resolved
for svc in systemd-networkd systemd-resolved systemd-networkd-wait-online systemd-networkd.socket; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    systemctl mask "$svc" 2>/dev/null || true
done

# Install service file
install -Dm644 "$(dirname "$0")/nic.service" /etc/systemd/system/nic.service

# Reload and enable
systemctl daemon-reload
systemctl enable nic.service

echo "Done. Masked: systemd-networkd, systemd-resolved"
echo "Enable with: systemctl start nic"
