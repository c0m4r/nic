# nic

A minimal, standalone network configuration tool for Linux. Single binary, zero dependencies, plain-text config.

Replaces systemd-networkd, netplan, and `/etc/network/interfaces` with one config file and one command.

## Features

- Declarative config at `/etc/nic.conf`
- Full iproute2 pass-through (including abbreviated syntax like `ip l s eth0 up`)
- Shortcut syntax for common operations
- Interface aliasing and MAC pinning
- Built-in DHCP client with fallback (dhclient, dhcpcd, udhcpc)
- WiFi support (wpa_supplicant, iwd)
- DNS management with `/etc/resolv.conf` guarding
- Config includes with natural sort order
- Dry-run mode
- Automatic rollback with confirmation timeout
- Init system support: systemd, OpenRC, SysV, runit
- IPv6 with DAD awareness
- No external Go dependencies

## Install

```sh
make build
sudo make install            # copies binary + default config
sudo make install-systemd    # also installs systemd service
sudo make install-openrc     # OpenRC
sudo make install-sysv       # SysV init
sudo make install-runit      # runit
```

Or install the init system from within nic:

```sh
sudo nic install systemd
sudo nic install openrc
sudo nic install sysv
sudo nic install runit
```

## Usage

```
nic <command> [options]

Commands:
  start                 Apply network configuration
  stop                  Tear down network configuration
  restart [options]     Stop and re-apply (with revert safety)
  reload [options]      Re-apply showing diff of changes
  status                Show current network state
  show                  Display parsed configuration
  dry-run               Show what would be done without applying
  confirm               Confirm changes after restart/reload
  install <init>        Install init scripts (systemd|openrc|sysv|runit)
  version               Show version

Options:
  --config=PATH         Config file (default: /etc/nic.conf)
  --verbose, -v         Show commands being executed
  --confirm-timeout=N   Seconds before automatic revert (default: 10)
  --force               Skip confirmation prompts
```

## Configuration

### Interface control

```sh
# Full iproute2
ip link set eth0 up

# Abbreviated (handled by ip binary)
ip l s eth0 up

# Shortcuts
if eth0 up
if eth0 down
up eth0
down eth0
```

### IP addresses

```sh
# Full iproute2
ip address add 192.168.1.100/24 dev eth0

# Abbreviated
ip a a 192.168.1.100/24 dev eth0

# Shortcut (auto-adds /32 or /128 if no prefix)
ip 192.168.1.100/24 eth0
ip fd76:1e4b:375a::/48 eth0
```

### Routes

```sh
# Full iproute2
ip route add default via 192.168.1.1 dev eth0

# Abbreviated
ip r a default via 192.168.1.1 dev eth0

# Shortcut
route default via 192.168.1.1 eth0
route 10.0.0.0/8 via 192.168.1.1 eth0
route 172.16.0.0/12 eth0
```

### DNS

```sh
nameserver 1.1.1.1
ns 8.8.8.8
```

Writes `/etc/resolv.conf` and protects it with `chattr +i`.

### DHCP

```sh
dhcp eth0              # auto-detects client
dhcp eth0 dhclient     # force specific client
```

Supports dhclient, dhcpcd, and udhcpc.

### WiFi

```sh
wifi MyNetwork MyPassword         # auto-detect interface
wifi MyNetwork MyPassword wlan0   # specify interface
```

Uses wpa_supplicant or iwd, with WPA3 (SAE) support.

### Aliases and MAC pinning

```sh
# Static alias
alias my_eth enp14s0

# Pin by MAC address (resolved at runtime)
pin my_eth aa:bb:cc:dd:ee:ff

# Use alias in subsequent commands
if my_eth up
ip 192.168.1.100/24 my_eth
```

### Includes

```sh
include nic.d/*.conf
```

Paths are relative to the config file directory. Files are loaded in natural sort order (`2.conf` before `10.conf`).

### Comments

```sh
# Full line comment
ip 10.0.0.1/24 eth0 # inline comment
```

## Example: LACP bond with VLAN

```sh
# /etc/nic.conf

# Create bond
ip link add bond0 type bond mode 802.3ad xmit_hash_policy layer2+3 lacp_rate fast
ip link set eth0 down
ip link set eth1 down
ip link set eth0 master bond0
ip link set eth1 master bond0
if bond0 up

# VLAN on top of bond
ip link add link bond0 name bond0.100 type vlan id 100
ip 192.168.100.10/24 bond0.100
if bond0.100 up

# Default route and DNS
route default via 192.168.100.1 bond0.100
ns 1.1.1.1
```

## Restart safety

`nic restart` and `nic reload` save the current network state before applying changes. If you don't run `nic confirm` within the timeout (default 10 seconds), the previous state is automatically restored. This prevents locking yourself out over SSH.

```sh
sudo nic restart --confirm-timeout=30
# test connectivity...
sudo nic confirm
```

## Build

Requires Go 1.22+.

```sh
make build    # produces ./nic
make test     # run tests
make lint     # run golangci-lint
```

## License

```
nic - network interfaces configurator
Copyright (C) 2026  c0m4r <https://github.com/c0m4r>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
