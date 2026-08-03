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
	return applyLeaseReplacing(iface, lease, nil)
}

func applyLeaseReplacing(iface string, lease, previous *Lease) error {
	cidr := lease.CIDR()
	applied := false
	var dnsSnapshot dns.Snapshot
	if len(lease.DNS) > 0 {
		var err error
		dnsSnapshot, err = dns.Capture()
		if err != nil {
			return fmt.Errorf("capture dns: %w", err)
		}
	}
	defer func() {
		if !applied {
			rollbackLeaseTransition(iface, lease, previous)
			if dnsSnapshot.Captured {
				_ = dns.Restore(dnsSnapshot)
			}
		}
	}()

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
	if _, err := executor.RunIP("link", "set", iface, "up"); err != nil {
		return fmt.Errorf("bring up %s: %w", iface, err)
	}

	if err := applyLeaseRoutes(iface, lease); err != nil {
		return err
	}

	// Write DNS
	if len(lease.DNS) > 0 {
		if err := dns.WriteResolvConf(lease.DNS); err != nil {
			return fmt.Errorf("write dns: %w", err)
		}
		_ = dns.Guard()
	}

	applied = true
	return nil
}

func applyLeaseRoutes(iface string, lease *Lease) error {
	if lease.Router == "" {
		return nil
	}
	mask := net.IPMask(net.ParseIP(lease.SubnetMask).To4())
	ones, _ := mask.Size()
	if ones == 32 {
		fmt.Printf("%s: adding host route to %s\n", iface, lease.Router)
		if _, err := executor.RunIP("route", "replace", lease.Router,
			"dev", iface, "proto", "dhcp", "scope", "link",
			"src", lease.IP, "metric", dhcpMetric); err != nil {
			return fmt.Errorf("set host route to %s: %w", lease.Router, err)
		}
	}
	fmt.Printf("%s: adding default route via %s\n", iface, lease.Router)
	if _, err := executor.RunIP("route", "replace", "default",
		"via", lease.Router, "dev", iface, "proto", "dhcp",
		"src", lease.IP, "metric", dhcpMetric); err != nil {
		return fmt.Errorf("set default route via %s: %w", lease.Router, err)
	}
	return nil
}

func rollbackLeaseTransition(iface string, attempted, previous *Lease) {
	if previous == nil {
		unapplyLease(iface, attempted)
		return
	}
	if attempted.CIDR() != previous.CIDR() {
		_, _ = executor.RunIP("addr", "del", attempted.CIDR(), "dev", iface)
	}
	if attempted.Router != previous.Router || attempted.IP != previous.IP ||
		attempted.SubnetMask != previous.SubnetMask {
		removeLeaseRoutes(iface, attempted)
		_ = applyLeaseRoutes(iface, previous)
	}
}

func cleanupSupersededLease(iface string, oldLease, newLease *Lease) {
	if oldLease == nil || newLease == nil {
		return
	}
	if oldLease.CIDR() != newLease.CIDR() {
		_, _ = executor.RunIP("addr", "del", oldLease.CIDR(), "dev", iface)
	}
	if oldLease.Router != "" && oldLease.Router != newLease.Router {
		mask := net.IPMask(net.ParseIP(oldLease.SubnetMask).To4())
		ones, _ := mask.Size()
		if ones == 32 {
			_, _ = executor.RunIP("route", "del", oldLease.Router,
				"dev", iface, "proto", "dhcp", "metric", dhcpMetric)
		}
	}
}

// unapplyLease removes the configuration from the interface.
func unapplyLease(iface string, lease *Lease) {
	if lease == nil {
		return
	}
	removeLeaseRoutes(iface, lease)
	cidr := lease.CIDR()
	_, _ = executor.RunIP("addr", "del", cidr, "dev", iface)
}

func removeLeaseRoutes(iface string, lease *Lease) {
	if lease != nil && lease.Router != "" {
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
}

// applyLeaseV6 configures the interface with DHCPv6 addresses.
func applyLeaseV6(iface string, lease *LeaseV6) error {
	return applyLeaseV6Replacing(iface, lease, nil)
}

func applyLeaseV6Replacing(iface string, lease, previous *LeaseV6) error {
	applied := false
	var dnsSnapshot dns.Snapshot
	if len(lease.DNS) > 0 {
		var err error
		dnsSnapshot, err = dns.Capture()
		if err != nil {
			return fmt.Errorf("capture dns: %w", err)
		}
	}
	defer func() {
		if !applied {
			rollbackLeaseTransitionV6(iface, lease, previous)
			if dnsSnapshot.Captured {
				_ = dns.Restore(dnsSnapshot)
			}
		}
	}()
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

	applied = true
	return nil
}

func rollbackLeaseTransitionV6(iface string, attempted, previous *LeaseV6) {
	if previous == nil {
		unapplyLeaseV6(iface, attempted)
		return
	}
	oldAddresses := make(map[string]bool)
	for _, addr := range previous.Addresses {
		oldAddresses[fmt.Sprintf("%s/%d", addr.IP, addr.PrefixLen)] = true
	}
	for _, addr := range attempted.Addresses {
		cidr := fmt.Sprintf("%s/%d", addr.IP, addr.PrefixLen)
		if !oldAddresses[cidr] {
			_, _ = executor.RunIP("addr", "del", cidr, "dev", iface)
		}
	}
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

func cleanupSupersededLeaseV6(iface string, oldLease, newLease *LeaseV6) {
	current := make(map[string]bool)
	for _, addr := range newLease.Addresses {
		current[fmt.Sprintf("%s/%d", addr.IP, addr.PrefixLen)] = true
	}
	for _, addr := range oldLease.Addresses {
		cidr := fmt.Sprintf("%s/%d", addr.IP, addr.PrefixLen)
		if !current[cidr] {
			_, _ = executor.RunIP("addr", "del", cidr, "dev", iface)
		}
	}
}
