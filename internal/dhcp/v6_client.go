package dhcp

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"time"
)

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

	duid := newDUID(mac)
	iaid := computeIAID(iface)

	var txID [3]byte
	r := rand.Uint32()
	txID[0] = byte(r >> 16)
	txID[1] = byte(r >> 8)
	txID[2] = byte(r)

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
	lease, err := doRequestV6(ctx, conn, duid, serverDUID, iaid, txID, addrs, iface)
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
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}

		if _, err := conn.WriteTo(solicit, dst); err != nil {
			return nil, nil, fmt.Errorf("send solicit: %w", err)
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

	return nil, nil, fmt.Errorf("no DHCPv6 advertise received")
}

func doRequestV6(ctx context.Context, conn net.PacketConn, clientDUID v6DUID, serverDUID []byte, iaid uint32, txID [3]byte, addrs []iaAddrInfo, iface string) (*LeaseV6, error) {
	request := buildRequestV6(clientDUID, serverDUID, iaid, txID, addrs)
	dst := &net.UDPAddr{
		IP:   dhcpv6ServerAddr.IP,
		Port: dhcpv6ServerAddr.Port,
		Zone: iface,
	}

	timeout := time.Second
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if _, err := conn.WriteTo(request, dst); err != nil {
			return nil, fmt.Errorf("send request: %w", err)
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

		return parseLeaseV6(iface, msg, serverDUID, iaid)
	}

	return nil, fmt.Errorf("no DHCPv6 reply received")
}

func parseLeaseV6(iface string, msg *v6Message, serverDUID []byte, iaid uint32) (*LeaseV6, error) {
	lease := &LeaseV6{
		Interface:  iface,
		ServerDUID: serverDUID,
		IAID:       iaid,
		AcquiredAt: time.Now(),
	}

	ianaData := msg.getOption(optV6IANA)
	if ianaData != nil {
		_, _, _, addrs := parseIANA(ianaData)
		for _, a := range addrs {
			lease.Addresses = append(lease.Addresses, V6Addr{
				IP:            a.IP.String(),
				PrefixLen:     128, // IA_NA addresses are /128
				PreferredLife: a.PreferredLife,
				ValidLife:     a.ValidLife,
			})
		}
	}

	if dnsData := msg.getOption(optV6DNSServers); dnsData != nil {
		lease.DNS = parseDNSServers(dnsData)
	}

	if len(lease.Addresses) == 0 {
		return nil, fmt.Errorf("no addresses in DHCPv6 reply")
	}

	return lease, nil
}

// renewLeaseV6 sends a DHCPv6 RENEW to extend the lease.
func renewLeaseV6(iface string, lease *LeaseV6, clientDUID v6DUID) (*LeaseV6, error) {
	conn, err := net.ListenPacket("udp6", "[::]:546")
	if err != nil {
		return nil, fmt.Errorf("listen udp6:546: %w", err)
	}
	defer func() { _ = conn.Close() }()

	var txID [3]byte
	r := rand.Uint32()
	txID[0] = byte(r >> 16)
	txID[1] = byte(r >> 8)
	txID[2] = byte(r)

	var addrs []iaAddrInfo
	for _, a := range lease.Addresses {
		addrs = append(addrs, iaAddrInfo{
			IP:            net.ParseIP(a.IP),
			PreferredLife: a.PreferredLife,
			ValidLife:     a.ValidLife,
		})
	}

	renew := buildRenewV6(clientDUID, lease.ServerDUID, lease.IAID, txID, addrs)
	dst := &net.UDPAddr{
		IP:   dhcpv6ServerAddr.IP,
		Port: dhcpv6ServerAddr.Port,
		Zone: iface,
	}

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.WriteTo(renew, dst); err != nil {
		return nil, fmt.Errorf("send renew: %w", err)
	}

	buf := make([]byte, 1500)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, fmt.Errorf("read renew response: %w", err)
	}

	msg, err := parseV6Message(buf[:n])
	if err != nil {
		return nil, err
	}
	if msg.Type != msgV6Reply {
		return nil, fmt.Errorf("unexpected v6 message type %d", msg.Type)
	}

	return parseLeaseV6(iface, msg, lease.ServerDUID, lease.IAID)
}

// waitForLinkLocal waits for a non-tentative link-local address on the interface.
func waitForLinkLocal(ctx context.Context, iface string) error {
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for link-local address on %s", iface)
		default:
		}

		ifaces, err := net.InterfaceByName(iface)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		addrs, err := ifaces.Addrs()
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.IP.IsLinkLocalUnicast() && ipNet.IP.To4() == nil {
				return nil
			}
		}

		time.Sleep(100 * time.Millisecond)
	}
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

func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

