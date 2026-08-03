#!/bin/bash
set -e

echo "Installing nic for systemd..."

destdir=${DESTDIR:-}
prefix=${PREFIX:-/usr/local}
systemddir=${SYSTEMDDIR:-/etc/systemd/system}

# Optionally disable conflicting services. This is deliberately opt-in so an
# installation cannot tear down the network before nic has been configured.
if [ -z "$destdir" ] && [ "${NIC_DISABLE_SYSTEM_SERVICES:-0}" = 1 ]; then
    for svc in systemd-networkd systemd-resolved systemd-networkd-wait-online systemd-networkd.socket; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
        systemctl mask "$svc" 2>/dev/null || true
    done
fi

# Install service file
install -Dm644 "$(dirname "$0")/nic.service" "$destdir$systemddir/nic.service"
sed -i "s|@PREFIX@|$prefix|g" "$destdir$systemddir/nic.service"

# Reload and enable
if [ -z "$destdir" ]; then
    systemctl daemon-reload
    systemctl enable nic.service
fi

if [ -z "$destdir" ]; then
    echo "Done. Enable with: systemctl start nic"
    echo "Set NIC_DISABLE_SYSTEM_SERVICES=1 during installation to mask systemd-networkd and systemd-resolved."
else
    echo "Installed nic.service into $destdir$systemddir"
fi
