package dhcp

import (
	"fmt"

	"github.com/c0m4r/nic/internal/executor"
)

const pidDir = "/run/nic/dhcp"

// Start launches a DHCP client for the given interface.
// If preferredClient is empty, uses the native client.
// If preferredClient is "dhclient", "dhcpcd", or "udhcpc", uses that external client.
func Start(iface, preferredClient string) error {
	_ = Stop(iface)

	if executor.DryRun {
		mode := "native"
		if preferredClient != "" {
			mode = preferredClient
		}
		fmt.Printf("[dry-run] start dhcp (%s) on %s\n", mode, iface)
		return nil
	}

	if isExternalClient(preferredClient) {
		return startExternal(iface, preferredClient)
	}

	return startNative(iface)
}

// Stop kills the DHCP client running on the given interface.
func Stop(iface string) error {
	if executor.DryRun {
		fmt.Printf("[dry-run] stop dhcp on %s\n", iface)
		return nil
	}

	// Try native first, then external
	stopNative(iface)
	_ = stopExternal(iface)
	return nil
}

// StopAll kills all DHCP clients managed by nic.
func StopAll() {
	stopAllNative()
	stopAllExternal()
}

// Status returns the DHCP status for an interface.
func Status(iface string) string {
	if s := statusNative(iface); s != "" {
		return s
	}
	return statusExternal(iface)
}
