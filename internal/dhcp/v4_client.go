package dhcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

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

		offer, err := recvResponse(fd, xid, msgOffer, timeout)
		if err == nil {
			return offer, nil
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

		ack, err := recvResponse(fd, xid, msgAck, timeout)
		if err == nil {
			return ack, nil
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

	serverAddr := lease.ServerIP + ":67"
	conn, err := net.DialTimeout("udp4", serverAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}
	defer func() { _ = conn.Close() }()

	xid := rand.Uint32()
	request := buildRenew(mac, xid, net.ParseIP(lease.IP))

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

	if pkt.messageType() == msgNak {
		return nil, fmt.Errorf("server NAK'd renewal")
	}
	if pkt.messageType() != msgAck {
		return nil, fmt.Errorf("unexpected message type %d", pkt.messageType())
	}

	return parseLease(iface, pkt)
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

func recvResponse(fd int, xid uint32, expectedType byte, timeout time.Duration) (*v4Packet, error) {
	tv := syscall.Timeval{
		Sec:  int64(timeout.Seconds()),
		Usec: int64((timeout % time.Second).Microseconds()),
	}
	// #nosec G103 -- unsafe.Sizeof on fixed-size struct is safe
	_ = setsockopt(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, unsafe.Pointer(&tv), uint32(unsafe.Sizeof(tv)))

	buf := make([]byte, 1500)
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				return nil, fmt.Errorf("timeout")
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

		if pkt.XID != xid {
			continue
		}

		if pkt.messageType() == expectedType {
			return pkt, nil
		}

		if pkt.messageType() == msgNak {
			return nil, fmt.Errorf("server NAK")
		}
	}

	return nil, fmt.Errorf("timeout")
}

func setsockopt(fd, level, name int, val unsafe.Pointer, vallen uint32) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(name),
		uintptr(val), uintptr(vallen), 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
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
