package dhcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var errDHCPv4NAK = errors.New("DHCP server NAK")

// runDHCPv4 performs the full DORA exchange and returns a lease.
func runDHCPv4(ctx context.Context, iface string) (*Lease, error) {
	mac, ifIndex, err := getIfaceInfo(iface)
	if err != nil {
		return nil, err
	}

	fd, err := openRawSocket(ifIndex)
	if err != nil {
		return nil, fmt.Errorf("open raw socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	xid := rand.Uint32()

	fmt.Printf("%s: soliciting a DHCP lease\n", iface)

	// DISCOVER
	offer, err := doDiscover(ctx, fd, mac, xid, ifIndex)
	if err != nil {
		return nil, err
	}

	offeredIP := offer.YIAddr
	serverID := offer.getOption(optServerID)
	if serverID == nil {
		return nil, fmt.Errorf("offer missing server ID")
	}

	fmt.Printf("%s: offered %s from %s\n", iface, offeredIP, net.IP(serverID))

	// REQUEST
	ack, err := doRequest(ctx, fd, mac, xid, ifIndex, net.IP(serverID), offeredIP)
	if err != nil {
		return nil, err
	}

	lease, err := parseLease(iface, ack)
	if err != nil {
		return nil, err
	}

	fmt.Printf("%s: leased %s for %d seconds\n", iface, lease.IP, lease.LeaseTime)

	return lease, nil
}

// doDiscover sends DHCPDISCOVER and waits for DHCPOFFER.
func doDiscover(ctx context.Context, fd int, mac net.HardwareAddr, xid uint32, ifIndex int) (*v4Packet, error) {
	discover := buildDiscover(mac, xid)
	packet := wrapUDPIP(discover)

	timeout := 4 * time.Second
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := sendBroadcast(fd, packet, ifIndex); err != nil {
			return nil, fmt.Errorf("send discover: %w", err)
		}

		offer, err := recvResponse(ctx, fd, xid, mac, msgOffer, timeout)
		if err == nil {
			return offer, nil
		}
		if errors.Is(err, errDHCPv4NAK) {
			return nil, err
		}

		timeout *= 2 // exponential backoff
	}

	return nil, fmt.Errorf("no DHCP offer received")
}

// doRequest sends DHCPREQUEST and waits for DHCPACK.
func doRequest(ctx context.Context, fd int, mac net.HardwareAddr, xid uint32, ifIndex int, serverIP, requestedIP net.IP) (*v4Packet, error) {
	request := buildRequest(mac, xid, serverIP, requestedIP)
	packet := wrapUDPIP(request)

	timeout := 4 * time.Second
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		if err := sendBroadcast(fd, packet, ifIndex); err != nil {
			return nil, fmt.Errorf("send request: %w", err)
		}

		ack, err := recvResponse(ctx, fd, xid, mac, msgAck, timeout)
		if err == nil {
			return ack, nil
		}
		if errors.Is(err, errDHCPv4NAK) {
			return nil, err
		}
	}

	return nil, fmt.Errorf("no DHCP ack received")
}

// renewLease sends a unicast DHCPREQUEST to renew the lease.
func renewLease(iface string, lease *Lease) (*Lease, error) {
	mac, _, err := getIfaceInfo(iface)
	if err != nil {
		return nil, err
	}

	localAddr, serverAddr, err := v4LeaseUDPAddrs(lease)
	if err != nil {
		return nil, err
	}

	// DHCP servers send renewal replies to UDP port 68. Binding the socket to
	// the leased address and that port also ensures the request uses the correct
	// source address on a multi-homed host.
	conn, err := net.DialUDP("udp4", localAddr, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}
	defer func() { _ = conn.Close() }()

	xid := rand.Uint32()
	request := buildRenew(mac, xid, localAddr.IP)

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, fmt.Errorf("send renew: %w", err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read renew response: %w", err)
	}

	pkt, err := parseV4Packet(buf[:n])
	if err != nil {
		return nil, err
	}
	if pkt.Op != bootReply || pkt.XID != xid || !bytes.Equal(pkt.CHAddr, mac) {
		return nil, fmt.Errorf("DHCP renewal reply identity mismatch")
	}

	if pkt.messageType() == msgNak {
		return nil, fmt.Errorf("renewal: %w", errDHCPv4NAK)
	}
	if pkt.messageType() != msgAck {
		return nil, fmt.Errorf("unexpected message type %d", pkt.messageType())
	}

	return parseRenewedLease(iface, pkt, lease)
}

func v4LeaseUDPAddrs(lease *Lease) (*net.UDPAddr, *net.UDPAddr, error) {
	serverIP := net.ParseIP(lease.ServerIP).To4()
	if serverIP == nil {
		return nil, nil, fmt.Errorf("invalid DHCP server address %q", lease.ServerIP)
	}
	clientIP := net.ParseIP(lease.IP).To4()
	if clientIP == nil || clientIP.Equal(net.IPv4zero) {
		return nil, nil, fmt.Errorf("invalid DHCP client address %q", lease.IP)
	}
	return &net.UDPAddr{IP: clientIP, Port: 68}, &net.UDPAddr{IP: serverIP, Port: 67}, nil
}

// rebindLease broadcasts a DHCPREQUEST after T2. Unlike renewal, rebinding
// intentionally has no server identifier so another DHCP server can take over
// the lease.
func rebindLease(ctx context.Context, iface string, lease *Lease) (*Lease, error) {
	mac, ifIndex, err := getIfaceInfo(iface)
	if err != nil {
		return nil, err
	}
	clientIP := net.ParseIP(lease.IP).To4()
	if clientIP == nil || clientIP.Equal(net.IPv4zero) {
		return nil, fmt.Errorf("invalid DHCP client address %q", lease.IP)
	}

	fd, err := openRawSocket(ifIndex)
	if err != nil {
		return nil, fmt.Errorf("open raw socket: %w", err)
	}
	defer func() { _ = syscall.Close(fd) }()

	xid := rand.Uint32()
	packet := wrapUDPIPFromTo(buildRebind(mac, xid, clientIP), clientIP, net.IPv4bcast)
	timeout := 4 * time.Second
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := sendBroadcast(fd, packet, ifIndex); err != nil {
			return nil, fmt.Errorf("send rebind: %w", err)
		}
		ack, err := recvResponse(ctx, fd, xid, mac, msgAck, timeout)
		if err == nil {
			return parseRenewedLease(iface, ack, lease)
		}
		if errors.Is(err, errDHCPv4NAK) {
			return nil, err
		}
		timeout *= 2
	}
	return nil, fmt.Errorf("no DHCP rebind ack received")
}

// parseRenewedLease preserves values that a DHCPACK is allowed to omit during
// a renewal or rebind exchange. In particular, yiaddr is commonly zero when
// the client identifies the lease through ciaddr.
func parseRenewedLease(iface string, ack *v4Packet, previous *Lease) (*Lease, error) {
	lease, err := parseLease(iface, ack)
	if err != nil {
		return nil, err
	}
	if previous == nil {
		return lease, nil
	}

	if ack.YIAddr.To4() == nil || ack.YIAddr.To4().Equal(net.IPv4zero) {
		lease.IP = previous.IP
	}
	if len(ack.getOption(optSubnetMask)) != 4 {
		lease.SubnetMask = previous.SubnetMask
	}
	if len(ack.getOption(optRouter)) < 4 {
		lease.Router = previous.Router
	}
	if len(ack.getOption(optDNS)) < 4 {
		lease.DNS = append([]string(nil), previous.DNS...)
	}
	if len(ack.getOption(optDomainName)) == 0 {
		lease.Domain = previous.Domain
	}
	if len(ack.getOption(optServerID)) != 4 {
		lease.ServerIP = previous.ServerIP
	}
	if len(ack.getOption(optLeaseTime)) != 4 {
		lease.LeaseTime = previous.LeaseTime
	}
	if len(ack.getOption(optRenewalTime)) != 4 {
		lease.RenewTime = previous.RenewTime
	}
	if len(ack.getOption(optRebindingTime)) != 4 {
		lease.RebindTime = previous.RebindTime
	}
	return lease, nil
}

// parseLease extracts lease information from a DHCPACK packet.
func parseLease(iface string, ack *v4Packet) (*Lease, error) {
	lease := &Lease{
		Interface:  iface,
		IP:         ack.YIAddr.String(),
		AcquiredAt: time.Now(),
	}

	if data := ack.getOption(optSubnetMask); len(data) == 4 {
		lease.SubnetMask = net.IP(data).String()
	} else {
		lease.SubnetMask = "255.255.255.0" // default /24
	}

	if data := ack.getOption(optRouter); len(data) >= 4 {
		lease.Router = net.IP(data[:4]).String()
	}

	if data := ack.getOption(optDNS); len(data) >= 4 {
		for i := 0; i+4 <= len(data); i += 4 {
			lease.DNS = append(lease.DNS, net.IP(data[i:i+4]).String())
		}
	}

	if data := ack.getOption(optDomainName); len(data) > 0 {
		lease.Domain = string(data)
	}

	if data := ack.getOption(optServerID); len(data) == 4 {
		lease.ServerIP = net.IP(data).String()
	}

	if data := ack.getOption(optLeaseTime); len(data) == 4 {
		lease.LeaseTime = binary.BigEndian.Uint32(data)
	} else {
		lease.LeaseTime = 86400 // default 24h
	}

	if data := ack.getOption(optRenewalTime); len(data) == 4 {
		lease.RenewTime = binary.BigEndian.Uint32(data)
	}

	if data := ack.getOption(optRebindingTime); len(data) == 4 {
		lease.RebindTime = binary.BigEndian.Uint32(data)
	}

	return lease, nil
}

// Raw socket operations.

func openRawSocket(ifIndex int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return -1, err
	}

	// Bind to the interface
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  ifIndex,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		_ = syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

func sendBroadcast(fd int, data []byte, ifIndex int) error {
	addr := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  ifIndex,
		Halen:    6,
		Addr:     [8]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, // broadcast
	}
	return syscall.Sendto(fd, data, 0, addr)
}

func recvResponse(ctx context.Context, fd int, xid uint32, mac net.HardwareAddr, expectedType byte, timeout time.Duration) (*v4Packet, error) {
	buf := make([]byte, 1500)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pollTimeout := minDuration(500*time.Millisecond, time.Until(deadline))
		if pollTimeout <= 0 {
			return nil, fmt.Errorf("timeout")
		}
		tv := syscall.NsecToTimeval(pollTimeout.Nanoseconds())
		if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
			return nil, fmt.Errorf("set receive timeout: %w", err)
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return nil, err
		}

		// Extract DHCP payload from IP+UDP
		payload := extractDHCPPayload(buf[:n])
		if payload == nil {
			continue
		}

		pkt, err := parseV4Packet(payload)
		if err != nil {
			continue
		}

		if pkt.Op != bootReply || pkt.XID != xid || !bytes.Equal(pkt.CHAddr, mac) {
			continue
		}

		if pkt.messageType() == expectedType {
			return pkt, nil
		}

		if pkt.messageType() == msgNak {
			return nil, errDHCPv4NAK
		}
	}

	return nil, fmt.Errorf("timeout")
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Helper functions.

func getIfaceInfo(name string) (net.HardwareAddr, int, error) {
	// Read MAC from sysfs
	macData, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/address", name))
	if err != nil {
		return nil, 0, fmt.Errorf("read MAC for %s: %w", name, err)
	}
	mac, err := net.ParseMAC(strings.TrimSpace(string(macData)))
	if err != nil {
		return nil, 0, fmt.Errorf("parse MAC: %w", err)
	}

	// Read interface index from sysfs
	idxData, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/ifindex", name))
	if err != nil {
		return nil, 0, fmt.Errorf("read ifindex for %s: %w", name, err)
	}
	var ifIndex int
	_, _ = fmt.Sscanf(strings.TrimSpace(string(idxData)), "%d", &ifIndex)

	return mac, ifIndex, nil
}

func htons(v uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], v)
	return *(*uint16)(unsafe.Pointer(&buf[0]))
}
