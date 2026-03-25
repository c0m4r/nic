package dhcp

import (
	"fmt"

	"github.com/c0m4r/nic/internal/dns"
	"github.com/c0m4r/nic/internal/executor"
)

// applyLease configures the interface with the acquired lease.
func applyLease(iface string, lease *Lease) error {
	cidr := lease.CIDR()

	// Add IP address
	if _, err := executor.RunIP("addr", "add", cidr, "dev", iface); err != nil {
		return fmt.Errorf("set address %s: %w", cidr, err)
	}

	// Bring interface up
	_, _ = executor.RunIP("link", "set", iface, "up")

	// Add default route
	if lease.Router != "" {
		_, _ = executor.RunIP("route", "add", "default", "via", lease.Router, "dev", iface)
	}

	// Write DNS
	if len(lease.DNS) > 0 {
		if err := dns.WriteResolvConf(lease.DNS); err != nil {
			return fmt.Errorf("write dns: %w", err)
		}
		_ = dns.Guard()
	}

	return nil
}

// unapplyLease removes the configuration from the interface.
func unapplyLease(iface string, lease *Lease) {
	if lease == nil {
		return
	}
	cidr := lease.CIDR()
	_, _ = executor.RunIP("addr", "del", cidr, "dev", iface)
	if lease.Router != "" {
		_, _ = executor.RunIP("route", "del", "default", "via", lease.Router, "dev", iface)
	}
}

// applyLeaseV6 configures the interface with DHCPv6 addresses.
func applyLeaseV6(iface string, lease *LeaseV6) error {
	for _, addr := range lease.Addresses {
		cidr := fmt.Sprintf("%s/%d", addr.IP, addr.PrefixLen)
		if _, err := executor.RunIP("addr", "add", cidr, "dev", iface); err != nil {
			return fmt.Errorf("set v6 address %s: %w", cidr, err)
		}
	}

	if len(lease.DNS) > 0 {
		// Merge with existing DNS rather than overwrite
		existing := dns.CurrentNameservers()
		merged := existing
		for _, ns := range lease.DNS {
			found := false
			for _, e := range existing {
				if e == ns {
					found = true
					break
				}
			}
			if !found {
				merged = append(merged, ns)
			}
		}
		if err := dns.WriteResolvConf(merged); err != nil {
			return fmt.Errorf("write v6 dns: %w", err)
		}
		_ = dns.Guard()
	}

	return nil
}

// unapplyLeaseV6 removes DHCPv6 addresses from the interface.
func unapplyLeaseV6(iface string, lease *LeaseV6) {
	if lease == nil {
		return
	}
	for _, addr := range lease.Addresses {
		cidr := fmt.Sprintf("%s/%d", addr.IP, addr.PrefixLen)
		_, _ = executor.RunIP("addr", "del", cidr, "dev", iface)
	}
}
