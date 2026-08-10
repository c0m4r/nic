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

    # systemd-resolved commonly owns /etc/resolv.conf through a symlink into
    # /run. Once resolved is masked that target disappears, leaving DNS broken.
    # Replace only those known runtime links; preserve administrator-managed
    # files and symlinks (including the distribution-provided static fallback).
    if [ -L /etc/resolv.conf ]; then
        resolv_target=$(readlink /etc/resolv.conf 2>/dev/null || true)
        case "$resolv_target" in
            /run/systemd/resolve/*|../run/systemd/resolve/*)
                tmp_resolv=$(mktemp /etc/.nic-resolv.XXXXXX)
                printf '%s\n' '# Managed by nic; configure nameserver entries in /etc/nic.conf.' > "$tmp_resolv"
                chmod 0644 "$tmp_resolv"
                mv -f "$tmp_resolv" /etc/resolv.conf
                ;;
        esac
    fi
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
