package dhcp

import (
	"errors"
	"fmt"

	"github.com/c0m4r/nic/internal/executor"
)

var (
	pidDir           = "/run/nic/dhcp"
	nativeStarter    = startNative
	externalStarter  = startExternal
	externalDetector = detectExternalClient
)

// Start launches a DHCPv4 client for the given interface.
// If preferredClient is empty, uses the native client.
// If preferredClient is "dhclient", "dhcpcd", or "udhcpc", uses that external client.
// In daemon mode, native client stays running to renew leases; otherwise it's oneshot.
func Start(iface, preferredClient string, daemonMode bool) error {
	if err := Stop(iface); err != nil {
		return err
	}

	if executor.DryRun {
		mode := "native"
		if preferredClient != "" {
			mode = preferredClient
		}
		fmt.Printf("[dry-run] start dhcp v4 (%s) on %s\n", mode, iface)
		return nil
	}

	if preferredClient == "native" {
		return nativeStarter(iface, daemonMode)
	}
	if isExternalClient(preferredClient) {
		return externalStarter(iface, preferredClient)
	}
	if preferredClient != "" {
		return fmt.Errorf("unsupported DHCP client %q (use native, dhclient, dhcpcd, or udhcpc)", preferredClient)
	}

	nativeErr := nativeStarter(iface, daemonMode)
	if nativeErr == nil {
		return nil
	}
	external := externalDetector()
	if external == "" {
		return nativeErr
	}
	if externalErr := externalStarter(iface, external); externalErr != nil {
		return errors.Join(nativeErr, fmt.Errorf("fallback %s: %w", external, externalErr))
	}
	return nil
}

// StartV6 launches a DHCPv6 client for the given interface.
func StartV6(iface string, daemonMode bool) error {
	if executor.DryRun {
		fmt.Printf("[dry-run] start dhcp v6 (native) on %s\n", iface)
		return nil
	}

	return startNativeV6(iface, daemonMode)
}

// Stop kills the DHCP client running on the given interface.
func Stop(iface string) error {
	if executor.DryRun {
		fmt.Printf("[dry-run] stop dhcp on %s\n", iface)
		return nil
	}

	// Try native first, then external
	stopNative(iface)
	return stopExternal(iface)
}

// StopAll kills all DHCP clients managed by nic.
func StopAll() error {
	stopAllNative()
	return stopAllExternal()
}

// Status returns the DHCP status for an interface.
func Status(iface string) string {
	if s := statusNative(iface); s != "" {
		return s
	}
	return statusExternal(iface)
}
