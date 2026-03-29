package dhcp

import (
	"fmt"
	"net"

	"github.com/c0m4r/nic/internal/dns"
	"github.com/c0m4r/nic/internal/executor"
)

const dhcpMetric = "1002"

// applyLease configures the interface with the acquired lease.
func applyLease(iface string, lease *Lease) error {
	cidr := lease.CIDR()

	// Set IP address with lifetime (replace is idempotent — add or update)
	addrArgs := []string{"addr", "replace", cidr, "dev", iface}
	if lease.LeaseTime > 0 {
		lt := fmt.Sprintf("%d", lease.LeaseTime)
		preferred := lt
		if lease.RenewTime > 0 {
			preferred = fmt.Sprintf("%d", lease.RenewTime)
		}
		addrArgs = append(addrArgs, "valid_lft", lt, "preferred_lft", preferred)
	}
	if _, err := executor.RunIP(addrArgs...); err != nil {
		return fmt.Errorf("set address %s: %w", cidr, err)
	}

	// Bring interface up
	_, _ = executor.RunIP("link", "set", iface, "up")

	// Add routes
	if lease.Router != "" {
		mask := net.IPMask(net.ParseIP(lease.SubnetMask).To4())
		ones, _ := mask.Size()

		// On /32 networks (common in cloud), the gateway is not directly
		// reachable. Add a host route to the gateway with scope link first.
		if ones == 32 {
			fmt.Printf("%s: adding host route to %s\n", iface, lease.Router)
			_, _ = executor.RunIP("route", "replace", lease.Router,
				"dev", iface,
				"proto", "dhcp",
				"scope", "link",
				"src", lease.IP,
				"metric", dhcpMetric)
		}

		fmt.Printf("%s: adding default route via %s\n", iface, lease.Router)
		_, _ = executor.RunIP("route", "replace", "default",
			"via", lease.Router,
			"dev", iface,
			"proto", "dhcp",
			"src", lease.IP,
			"metric", dhcpMetric)
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
	if lease.Router != "" {
		_, _ = executor.RunIP("route", "del", "default",
			"via", lease.Router, "dev", iface,
			"proto", "dhcp", "metric", dhcpMetric)
		mask := net.IPMask(net.ParseIP(lease.SubnetMask).To4())
		ones, _ := mask.Size()
		if ones == 32 {
			_, _ = executor.RunIP("route", "del", lease.Router,
				"dev", iface,
				"proto", "dhcp", "metric", dhcpMetric)
		}
	}
	cidr := lease.CIDR()
	_, _ = executor.RunIP("addr", "del", cidr, "dev", iface)
}

// applyLeaseV6 configures the interface with DHCPv6 addresses.
func applyLeaseV6(iface string, lease *LeaseV6) error {
	for _, addr := range lease.Addresses {
		cidr := fmt.Sprintf("%s/%d", addr.IP, addr.PrefixLen)
		addrArgs := []string{"addr", "replace", cidr, "dev", iface}
		if addr.ValidLife > 0 {
			addrArgs = append(addrArgs,
				"valid_lft", fmt.Sprintf("%d", addr.ValidLife),
				"preferred_lft", fmt.Sprintf("%d", addr.PreferredLife))
		}
		if _, err := executor.RunIP(addrArgs...); err != nil {
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
