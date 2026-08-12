package dhcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"github.com/c0m4r/nic/internal/executor"
)

var (
	errDHCPv6NoAddresses = errors.New("no addresses in DHCPv6 reply")
	errDADFailed         = errors.New("duplicate address detection failed for the link-local address")
)

// linkLocalTimeout bounds the wait for duplicate address detection to finish.
// DAD normally settles in about a second, but a link that has just gained
// carrier can take noticeably longer.
const linkLocalTimeout = 10 * time.Second

// DHCPv6 multicast address for all relay agents and servers.
var dhcpv6ServerAddr = &net.UDPAddr{
	IP:   net.ParseIP("ff02::1:2"),
	Port: 547,
}

// runDHCPv6 performs the DHCPv6 SARR exchange and returns a lease.
func runDHCPv6(ctx context.Context, iface string) (*LeaseV6, error) {
	mac, _, err := getIfaceInfo(iface)
	if err != nil {
		return nil, err
	}

	// Wait for link-local address to be ready (non-tentative)
	if err := waitForLinkLocal(ctx, iface); err != nil {
		return nil, err
	}

	duid, err := loadOrCreateDUID(mac)
	if err != nil {
		return nil, fmt.Errorf("load DHCPv6 client identity: %w", err)
	}
	iaid := computeIAID(iface)

	txID := randomTxID()

	conn, err := net.ListenPacket("udp6", "[::]:546")
	if err != nil {
		return nil, fmt.Errorf("listen udp6:546: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// SOLICIT
	serverDUID, addrs, err := doSolicit(ctx, conn, duid, iaid, txID, iface)
	if err != nil {
		return nil, err
	}

	// REQUEST
	lease, err := doRequestV6(ctx, conn, duid, serverDUID, iaid, randomTxID(), addrs, iface)
	if err != nil {
		return nil, err
	}

	return lease, nil
}

func doSolicit(ctx context.Context, conn net.PacketConn, duid v6DUID, iaid uint32, txID [3]byte, iface string) ([]byte, []iaAddrInfo, error) {
	solicit := buildSolicit(duid, iaid, txID)
	dst := &net.UDPAddr{
		IP:   dhcpv6ServerAddr.IP,
		Port: dhcpv6ServerAddr.Port,
		Zone: iface,
	}

	timeout := time.Second
	var sendErr error
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		if _, err := conn.WriteTo(solicit, dst); err != nil {
			// The source address can still be unusable here when DAD restarts
			// after a carrier bounce, which surfaces as EADDRNOTAVAIL. Retry
			// instead of abandoning the lease on a transient condition.
			sendErr = fmt.Errorf("send solicit: %w", err)
			waitBeforeRetry(ctx, timeout)
			timeout = min(timeout*2, 120*time.Second)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			timeout = min(timeout*2, 120*time.Second)
			continue
		}

		msg, err := parseV6Message(buf[:n])
		if err != nil || msg.Type != msgV6Advertise {
			continue
		}
		if msg.TransactionID != txID {
			continue
		}

		serverDUID := msg.getOption(optV6ServerID)
		if serverDUID == nil {
			continue
		}
		if clientID := msg.getOption(optV6ClientID); clientID == nil || !bytes.Equal(clientID, duid.raw) {
			continue
		}

		ianaData := msg.getOption(optV6IANA)
		if ianaData == nil {
			continue
		}

		_, _, _, addrs := parseIANA(ianaData)
		if len(addrs) == 0 {
			continue
		}

		return serverDUID, addrs, nil
	}

	if sendErr != nil {
		return nil, nil, sendErr
	}
	return nil, nil, fmt.Errorf("no DHCPv6 advertise received")
}

// waitBeforeRetry sleeps for d unless the context is cancelled first.
func waitBeforeRetry(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func doRequestV6(ctx context.Context, conn net.PacketConn, clientDUID v6DUID, serverDUID []byte, iaid uint32, txID [3]byte, addrs []iaAddrInfo, iface string) (*LeaseV6, error) {
	request := buildRequestV6(clientDUID, serverDUID, iaid, txID, addrs)
	dst := &net.UDPAddr{
		IP:   dhcpv6ServerAddr.IP,
		Port: dhcpv6ServerAddr.Port,
		Zone: iface,
	}

	timeout := time.Second
	var sendErr error
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if _, err := conn.WriteTo(request, dst); err != nil {
			sendErr = fmt.Errorf("send request: %w", err)
			waitBeforeRetry(ctx, timeout)
			timeout = min(timeout*2, 120*time.Second)
			continue
		}

		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			timeout = min(timeout*2, 120*time.Second)
			continue
		}

		msg, err := parseV6Message(buf[:n])
		if err != nil || msg.Type != msgV6Reply {
			continue
		}
		if msg.TransactionID != txID {
			continue
		}
		if !bytes.Equal(msg.getOption(optV6ClientID), clientDUID.raw) ||
			!bytes.Equal(msg.getOption(optV6ServerID), serverDUID) {
			continue
		}

		return parseLeaseV6(iface, msg, serverDUID, iaid, clientDUID)
	}

	if sendErr != nil {
		return nil, sendErr
	}
	return nil, fmt.Errorf("no DHCPv6 reply received")
}

func parseLeaseV6(iface string, msg *v6Message, serverDUID []byte, iaid uint32, clientDUID v6DUID) (*LeaseV6, error) {
	lease, _, err := parseLeaseV6Reply(iface, msg, serverDUID, iaid, clientDUID)
	if err != nil {
		return nil, err
	}
	if len(lease.Addresses) == 0 {
		return nil, errDHCPv6NoAddresses
	}
	return lease, nil
}

func parseLeaseV6Reply(iface string, msg *v6Message, serverDUID []byte, iaid uint32, clientDUID v6DUID) (*LeaseV6, map[string]bool, error) {
	lease := &LeaseV6{
		Interface:  iface,
		ServerDUID: serverDUID,
		ClientDUID: append([]byte(nil), clientDUID.raw...),
		IAID:       iaid,
		AcquiredAt: time.Now(),
	}
	seenAddresses := make(map[string]bool)

	ianaData := msg.getOption(optV6IANA)
	if ianaData != nil {
		if len(ianaData) < 12 {
			return nil, nil, fmt.Errorf("malformed DHCPv6 IA_NA option")
		}
		parsedIAID, t1, t2, addrs := parseIANA(ianaData)
		if parsedIAID != iaid {
			return nil, nil, fmt.Errorf("DHCPv6 reply has IAID %d, want %d", parsedIAID, iaid)
		}
		lease.RenewTime = t1
		lease.RebindTime = t2
		for _, a := range addrs {
			address := a.IP.String()
			seenAddresses[address] = true
			// A zero valid lifetime withdraws this IA address. Omitting lifetime
			// arguments later would otherwise turn that withdrawal into a
			// permanent address on the interface.
			if a.ValidLife == 0 {
				continue
			}
			if a.PreferredLife > a.ValidLife {
				return nil, nil, fmt.Errorf("DHCPv6 address %s has preferred lifetime greater than valid lifetime", a.IP)
			}
			lease.Addresses = append(lease.Addresses, V6Addr{
				IP:            address,
				PrefixLen:     128, // IA_NA addresses are /128
				PreferredLife: a.PreferredLife,
				ValidLife:     a.ValidLife,
			})
		}
	}

	if dnsData := msg.getOption(optV6DNSServers); dnsData != nil {
		lease.DNS = parseDNSServers(dnsData)
	}

	return lease, seenAddresses, nil
}

// parseRenewedLeaseV6 implements RFC 8415 section 18.2.10.1: an IA Address
// omitted from a Reply remains unchanged, while an explicitly returned zero
// valid lifetime withdraws it. Preserved lifetimes are reduced by the time
// already spent on the previous lease.
func parseRenewedLeaseV6(iface string, msg *v6Message, serverDUID []byte, iaid uint32, clientDUID v6DUID, previous *LeaseV6) (*LeaseV6, error) {
	lease, seen, err := parseLeaseV6Reply(iface, msg, serverDUID, iaid, clientDUID)
	if err != nil {
		return nil, err
	}
	if previous != nil {
		elapsed := elapsedV6LifetimeSeconds(previous.AcquiredAt, lease.AcquiredAt)
		for _, address := range previous.Addresses {
			canonical := net.ParseIP(address.IP)
			key := address.IP
			if canonical != nil {
				key = canonical.String()
			}
			if seen[key] {
				continue
			}
			remaining, valid := remainingV6Address(address, elapsed)
			if valid {
				lease.Addresses = append(lease.Addresses, remaining)
			}
		}
	}
	if len(lease.Addresses) == 0 {
		return nil, errDHCPv6NoAddresses
	}
	return lease, nil
}

func remainingV6Address(address V6Addr, elapsed uint64) (V6Addr, bool) {
	if address.ValidLife == 0 || elapsed >= uint64(address.ValidLife) {
		return V6Addr{}, false
	}
	address.ValidLife -= uint32(elapsed)
	if elapsed >= uint64(address.PreferredLife) {
		address.PreferredLife = 0
	} else {
		address.PreferredLife -= uint32(elapsed)
	}
	return address, true
}

func elapsedV6LifetimeSeconds(acquiredAt, now time.Time) uint64 {
	if acquiredAt.IsZero() || !now.After(acquiredAt) {
		return 0
	}
	elapsed := now.Sub(acquiredAt)
	seconds := elapsed / time.Second
	if elapsed%time.Second != 0 {
		seconds++
	}
	return uint64(seconds)
}

// renewLeaseV6 sends a DHCPv6 RENEW to extend the lease.
func renewLeaseV6(iface string, lease *LeaseV6, clientDUID v6DUID) (*LeaseV6, error) {
	conn, err := net.ListenPacket("udp6", "[::]:546")
	if err != nil {
		return nil, fmt.Errorf("listen udp6:546: %w", err)
	}
	defer func() { _ = conn.Close() }()

	txID := randomTxID()

	renew := buildRenewV6(clientDUID, lease.ServerDUID, lease.IAID, txID, leaseV6AddrInfos(lease))
	dst := &net.UDPAddr{
		IP:   dhcpv6ServerAddr.IP,
		Port: dhcpv6ServerAddr.Port,
		Zone: iface,
	}

	if _, err := conn.WriteTo(renew, dst); err != nil {
		return nil, fmt.Errorf("send renew: %w", err)
	}

	msg, serverDUID, err := readLeaseV6Reply(conn, txID, clientDUID, lease.ServerDUID, false)
	if err != nil {
		return nil, fmt.Errorf("read renew response: %w", err)
	}
	return parseRenewedLeaseV6(iface, msg, serverDUID, lease.IAID, clientDUID, lease)
}

// rebindLeaseV6 sends a multicast DHCPv6 REBIND after T2. It accepts a reply
// from a different server because the original server may be unavailable.
func rebindLeaseV6(iface string, lease *LeaseV6, clientDUID v6DUID) (*LeaseV6, error) {
	conn, err := net.ListenPacket("udp6", "[::]:546")
	if err != nil {
		return nil, fmt.Errorf("listen udp6:546: %w", err)
	}
	defer func() { _ = conn.Close() }()

	txID := randomTxID()
	rebind := buildRebindV6(clientDUID, lease.IAID, txID, leaseV6AddrInfos(lease))
	dst := &net.UDPAddr{
		IP:   dhcpv6ServerAddr.IP,
		Port: dhcpv6ServerAddr.Port,
		Zone: iface,
	}
	if _, err := conn.WriteTo(rebind, dst); err != nil {
		return nil, fmt.Errorf("send rebind: %w", err)
	}

	msg, serverDUID, err := readLeaseV6Reply(conn, txID, clientDUID, nil, true)
	if err != nil {
		return nil, fmt.Errorf("read rebind response: %w", err)
	}
	return parseRenewedLeaseV6(iface, msg, serverDUID, lease.IAID, clientDUID, lease)
}

func leaseV6AddrInfos(lease *LeaseV6) []iaAddrInfo {
	addrs := make([]iaAddrInfo, 0, len(lease.Addresses))
	for _, a := range lease.Addresses {
		addrs = append(addrs, iaAddrInfo{
			IP:            net.ParseIP(a.IP),
			PreferredLife: a.PreferredLife,
			ValidLife:     a.ValidLife,
		})
	}
	return addrs
}

func readLeaseV6Reply(conn net.PacketConn, txID [3]byte, clientDUID v6DUID, expectedServerDUID []byte, allowAnyServer bool) (*v6Message, []byte, error) {
	deadline := time.Now().Add(10 * time.Second)
	buf := make([]byte, 1500)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, nil, err
		}
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return nil, nil, err
		}
		msg, err := parseV6Message(buf[:n])
		if err != nil || msg.Type != msgV6Reply || msg.TransactionID != txID {
			continue
		}
		if !bytes.Equal(msg.getOption(optV6ClientID), clientDUID.raw) {
			continue
		}
		serverDUID := msg.getOption(optV6ServerID)
		if len(serverDUID) == 0 {
			continue
		}
		if !allowAnyServer && !bytes.Equal(serverDUID, expectedServerDUID) {
			continue
		}
		return msg, append([]byte(nil), serverDUID...), nil
	}
}

// waitForLinkLocal waits for a non-tentative link-local address on the
// interface. A solicit sourced from an address still undergoing duplicate
// address detection is rejected by the kernel with EADDRNOTAVAIL, so DAD has
// to finish before the exchange starts.
func waitForLinkLocal(ctx context.Context, iface string) error {
	deadline := time.After(linkLocalTimeout)
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			if lastErr != nil {
				return fmt.Errorf("waiting for link-local address on %s: %w", iface, lastErr)
			}
			return fmt.Errorf("timeout waiting for link-local address on %s", iface)
		default:
		}

		ready, err := hasUsableLinkLocal(iface)
		switch {
		case errors.Is(err, errDADFailed):
			return fmt.Errorf("%w on %s", errDADFailed, iface)
		case err != nil:
			lastErr = err
		case ready:
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// linkLocalAddrs mirrors the subset of `ip -j addr show` that DAD state is read
// from. The net package does not expose per-address kernel flags, so tentative
// and dadfailed can only be observed through ip.
type linkLocalAddrs struct {
	AddrInfo []struct {
		Local     string `json:"local"`
		Tentative bool   `json:"tentative"`
		DadFailed bool   `json:"dadfailed"`
	} `json:"addr_info"`
}

func hasUsableLinkLocal(iface string) (bool, error) {
	output, err := executor.RunQuiet("ip", "-j", "-6", "addr", "show", "dev", iface, "scope", "link")
	if err != nil {
		return false, err
	}
	if output == "" {
		return false, nil
	}
	var entries []linkLocalAddrs
	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return false, fmt.Errorf("parse addresses on %s: %w", iface, err)
	}

	dadFailed := false
	for _, entry := range entries {
		for _, addr := range entry.AddrInfo {
			ip := net.ParseIP(addr.Local)
			if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
				continue
			}
			switch {
			case addr.DadFailed:
				dadFailed = true
			case !addr.Tentative:
				return true, nil
			}
		}
	}
	if dadFailed {
		return false, errDADFailed
	}
	return false, nil
}

// computeIAID generates a stable IAID from the interface name.
func computeIAID(iface string) uint32 {
	// Simple hash of interface name
	var h uint32
	for _, c := range iface {
		h = h*31 + uint32(c)
	}
	return h
}

func randomTxID() [3]byte {
	var txID [3]byte
	value := rand.Uint32()
	txID[0] = byte(value >> 16)
	txID[1] = byte(value >> 8)
	txID[2] = byte(value)
	return txID
}

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
