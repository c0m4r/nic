package dhcp

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Lease holds DHCPv4 lease information.
type Lease struct {
	Interface  string    `json:"interface"`
	IP         string    `json:"ip"`
	SubnetMask string    `json:"subnet_mask"`
	Router     string    `json:"router"`
	DNS        []string  `json:"dns"`
	Domain     string    `json:"domain,omitempty"`
	ServerIP   string    `json:"server_ip"`
	LeaseTime  uint32    `json:"lease_time"`
	RenewTime  uint32    `json:"renew_time"`
	RebindTime uint32    `json:"rebind_time"`
	AcquiredAt time.Time `json:"acquired_at"`
}

// LeaseV6 holds DHCPv6 lease information.
type LeaseV6 struct {
	Interface  string    `json:"interface"`
	Addresses  []V6Addr  `json:"addresses"`
	DNS        []string  `json:"dns"`
	ServerDUID []byte    `json:"server_duid"`
	IAID       uint32    `json:"iaid"`
	AcquiredAt time.Time `json:"acquired_at"`
}

// V6Addr holds a single DHCPv6 address with lifetimes.
type V6Addr struct {
	IP            string `json:"ip"`
	PrefixLen     int    `json:"prefix_len"`
	PreferredLife uint32 `json:"preferred_life"`
	ValidLife     uint32 `json:"valid_life"`
}

// CIDR returns the IP/prefix string for ip addr add.
func (l *Lease) CIDR() string {
	mask := net.IPMask(net.ParseIP(l.SubnetMask).To4())
	ones, _ := mask.Size()
	if ones == 0 {
		ones = 32
	}
	return fmt.Sprintf("%s/%d", l.IP, ones)
}

// RenewalDeadline returns when the lease should be renewed.
func (l *Lease) RenewalDeadline() time.Time {
	t := l.RenewTime
	if t == 0 {
		t = l.LeaseTime / 2
	}
	return l.AcquiredAt.Add(time.Duration(t) * time.Second)
}

// RebindDeadline returns when the lease enters rebinding state.
func (l *Lease) RebindDeadline() time.Time {
	t := l.RebindTime
	if t == 0 {
		t = l.LeaseTime * 7 / 8
	}
	return l.AcquiredAt.Add(time.Duration(t) * time.Second)
}

// ExpiryDeadline returns when the lease expires.
func (l *Lease) ExpiryDeadline() time.Time {
	return l.AcquiredAt.Add(time.Duration(l.LeaseTime) * time.Second)
}

func (l *Lease) save() error {
	_ = os.MkdirAll(pidDir, 0755)
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(pidDir, l.Interface+".lease.json"), data, 0600)
}

func (l *LeaseV6) save() error {
	_ = os.MkdirAll(pidDir, 0755)
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(pidDir, l.Interface+".v6.lease.json"), data, 0600)
}

func removeLease(iface string) {
	_ = os.Remove(filepath.Join(pidDir, iface+".lease.json"))
}

func removeLeaseV6(iface string) {
	_ = os.Remove(filepath.Join(pidDir, iface+".v6.lease.json"))
}
