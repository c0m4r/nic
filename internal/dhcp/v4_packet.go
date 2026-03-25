package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// DHCPv4 opcodes.
const (
	bootRequest byte = 1
	bootReply   byte = 2
)

// DHCPv4 message types (option 53).
const (
	msgDiscover byte = 1
	msgOffer    byte = 2
	msgRequest  byte = 3
	msgDecline  byte = 4
	msgAck      byte = 5
	msgNak      byte = 6
	msgRelease  byte = 7
)

// DHCPv4 option codes (RFC 2132).
const (
	optSubnetMask       byte = 1
	optRouter           byte = 3
	optDNS              byte = 6
	optHostname         byte = 12
	optDomainName       byte = 15
	optRequestedIP      byte = 50
	optLeaseTime        byte = 51
	optMessageType      byte = 53
	optServerID         byte = 54
	optParamRequestList byte = 55
	optRenewalTime      byte = 58
	optRebindingTime    byte = 59
	optEnd              byte = 255
)

// Magic cookie that precedes DHCP options.
var magicCookie = []byte{99, 130, 83, 99}

// v4Packet represents a parsed DHCPv4 packet.
type v4Packet struct {
	Op      byte
	HType   byte
	HLen    byte
	Hops    byte
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  net.IP
	YIAddr  net.IP
	SIAddr  net.IP
	GIAddr  net.IP
	CHAddr  net.HardwareAddr
	Options []v4Option
}

type v4Option struct {
	Code byte
	Data []byte
}

const v4HeaderLen = 236

// marshalV4 serializes a DHCPv4 packet to wire format.
func (p *v4Packet) marshal() []byte {
	buf := make([]byte, v4HeaderLen)

	buf[0] = p.Op
	buf[1] = p.HType
	buf[2] = p.HLen
	buf[3] = p.Hops
	binary.BigEndian.PutUint32(buf[4:8], p.XID)
	binary.BigEndian.PutUint16(buf[8:10], p.Secs)
	binary.BigEndian.PutUint16(buf[10:12], p.Flags)

	copy(buf[12:16], p.CIAddr.To4())
	copy(buf[16:20], p.YIAddr.To4())
	copy(buf[20:24], p.SIAddr.To4())
	copy(buf[24:28], p.GIAddr.To4())
	copy(buf[28:44], p.CHAddr)

	// Append magic cookie + options
	buf = append(buf, magicCookie...)
	for _, opt := range p.Options {
		buf = append(buf, opt.Code)
		buf = append(buf, byte(len(opt.Data)))
		buf = append(buf, opt.Data...)
	}
	buf = append(buf, optEnd)

	// Pad to minimum 300 bytes (some servers expect this)
	for len(buf) < 300 {
		buf = append(buf, 0)
	}

	return buf
}

// parseV4Packet parses a DHCPv4 packet from wire format.
func parseV4Packet(data []byte) (*v4Packet, error) {
	if len(data) < v4HeaderLen+4 { // header + magic cookie
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	p := &v4Packet{
		Op:     data[0],
		HType:  data[1],
		HLen:   data[2],
		Hops:   data[3],
		XID:    binary.BigEndian.Uint32(data[4:8]),
		Secs:   binary.BigEndian.Uint16(data[8:10]),
		Flags:  binary.BigEndian.Uint16(data[10:12]),
		CIAddr: net.IP(data[12:16]),
		YIAddr: net.IP(data[16:20]),
		SIAddr: net.IP(data[20:24]),
		GIAddr: net.IP(data[24:28]),
		CHAddr: net.HardwareAddr(data[28 : 28+6]),
	}

	// Verify magic cookie
	offset := v4HeaderLen
	if data[offset] != 99 || data[offset+1] != 130 ||
		data[offset+2] != 83 || data[offset+3] != 99 {
		return nil, fmt.Errorf("invalid magic cookie")
	}
	offset += 4

	// Parse options
	for offset < len(data) {
		code := data[offset]
		if code == optEnd {
			break
		}
		if code == 0 { // pad
			offset++
			continue
		}
		offset++
		if offset >= len(data) {
			break
		}
		length := int(data[offset])
		offset++
		if offset+length > len(data) {
			break
		}
		p.Options = append(p.Options, v4Option{
			Code: code,
			Data: data[offset : offset+length],
		})
		offset += length
	}

	return p, nil
}

// getOption returns the data for a given option code, or nil.
func (p *v4Packet) getOption(code byte) []byte {
	for _, opt := range p.Options {
		if opt.Code == code {
			return opt.Data
		}
	}
	return nil
}

// messageType returns the DHCP message type (option 53).
func (p *v4Packet) messageType() byte {
	data := p.getOption(optMessageType)
	if len(data) == 1 {
		return data[0]
	}
	return 0
}

// newV4Base creates a base DHCPv4 packet for the given MAC and transaction ID.
func newV4Base(mac net.HardwareAddr, xid uint32) *v4Packet {
	p := &v4Packet{
		Op:     bootRequest,
		HType:  1, // Ethernet
		HLen:   6,
		XID:    xid,
		Flags:  0x8000, // broadcast
		CIAddr: net.IPv4zero,
		YIAddr: net.IPv4zero,
		SIAddr: net.IPv4zero,
		GIAddr: net.IPv4zero,
		CHAddr: make(net.HardwareAddr, 16),
	}
	copy(p.CHAddr, mac)
	return p
}

// buildDiscover creates a DHCPDISCOVER packet.
func buildDiscover(mac net.HardwareAddr, xid uint32) []byte {
	p := newV4Base(mac, xid)
	p.Options = []v4Option{
		{optMessageType, []byte{msgDiscover}},
		{optParamRequestList, []byte{
			optSubnetMask, optRouter, optDNS,
			optDomainName, optLeaseTime,
			optRenewalTime, optRebindingTime,
		}},
	}
	return p.marshal()
}

// buildRequest creates a DHCPREQUEST packet.
func buildRequest(mac net.HardwareAddr, xid uint32, serverIP, requestedIP net.IP) []byte {
	p := newV4Base(mac, xid)
	p.Options = []v4Option{
		{optMessageType, []byte{msgRequest}},
		{optServerID, serverIP.To4()},
		{optRequestedIP, requestedIP.To4()},
		{optParamRequestList, []byte{
			optSubnetMask, optRouter, optDNS,
			optDomainName, optLeaseTime,
			optRenewalTime, optRebindingTime,
		}},
	}
	return p.marshal()
}

// buildRenew creates a DHCPREQUEST for renewal (unicast, no server ID option).
func buildRenew(mac net.HardwareAddr, xid uint32, clientIP net.IP) []byte {
	p := newV4Base(mac, xid)
	p.Flags = 0 // unicast
	p.CIAddr = clientIP.To4()
	p.Options = []v4Option{
		{optMessageType, []byte{msgRequest}},
		{optParamRequestList, []byte{
			optSubnetMask, optRouter, optDNS,
			optDomainName, optLeaseTime,
			optRenewalTime, optRebindingTime,
		}},
	}
	return p.marshal()
}

// buildRelease creates a DHCPRELEASE packet.
func buildRelease(mac net.HardwareAddr, clientIP, serverIP net.IP) []byte {
	p := newV4Base(mac, xid0())
	p.Flags = 0
	p.CIAddr = clientIP.To4()
	p.Options = []v4Option{
		{optMessageType, []byte{msgRelease}},
		{optServerID, serverIP.To4()},
	}
	return p.marshal()
}

func xid0() uint32 { return 0 }

// IP/UDP header construction for raw socket sends.

const (
	ipHeaderLen  = 20
	udpHeaderLen = 8
)

// wrapUDPIP wraps a DHCP payload in IP + UDP headers for raw socket transmission.
func wrapUDPIP(payload []byte) []byte {
	totalLen := ipHeaderLen + udpHeaderLen + len(payload)
	buf := make([]byte, totalLen)

	// IP header
	buf[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	buf[8] = 64                                         // TTL
	buf[9] = 17                                         // UDP
	copy(buf[12:16], net.IPv4zero.To4())                // src: 0.0.0.0
	copy(buf[16:20], net.IPv4bcast.To4())               // dst: 255.255.255.255
	binary.BigEndian.PutUint16(buf[10:12], ipChecksum(buf[:ipHeaderLen]))

	// UDP header
	udpStart := ipHeaderLen
	binary.BigEndian.PutUint16(buf[udpStart:], 68)                           // src port
	binary.BigEndian.PutUint16(buf[udpStart+2:], 67)                         // dst port
	binary.BigEndian.PutUint16(buf[udpStart+4:], uint16(udpHeaderLen+len(payload))) // length

	// Copy payload
	copy(buf[ipHeaderLen+udpHeaderLen:], payload)

	// UDP checksum (with pseudo-header)
	binary.BigEndian.PutUint16(buf[udpStart+6:], udpChecksum(buf))

	return buf
}

// ipChecksum computes the IP header checksum.
func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum including the pseudo-header.
func udpChecksum(ipPacket []byte) uint16 {
	var sum uint32

	// Pseudo-header: src IP, dst IP, zero, protocol, UDP length
	sum += uint32(binary.BigEndian.Uint16(ipPacket[12:14])) // src IP
	sum += uint32(binary.BigEndian.Uint16(ipPacket[14:16]))
	sum += uint32(binary.BigEndian.Uint16(ipPacket[16:18])) // dst IP
	sum += uint32(binary.BigEndian.Uint16(ipPacket[18:20]))
	sum += uint32(ipPacket[9]) // protocol (UDP = 17)
	udpLen := binary.BigEndian.Uint16(ipPacket[ipHeaderLen+4 : ipHeaderLen+6])
	sum += uint32(udpLen)

	// UDP header + data (skip checksum field)
	udpData := ipPacket[ipHeaderLen:]
	for i := 0; i < len(udpData)-1; i += 2 {
		if i == 6 {
			continue // skip checksum field
		}
		sum += uint32(binary.BigEndian.Uint16(udpData[i:]))
	}
	if len(udpData)%2 == 1 {
		sum += uint32(udpData[len(udpData)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	result := ^uint16(sum)
	if result == 0 {
		result = 0xFFFF
	}
	return result
}

// extractDHCPPayload extracts the DHCP payload from a raw IP+UDP packet.
// Returns nil if the packet is not a UDP packet to port 68.
func extractDHCPPayload(data []byte) []byte {
	if len(data) < ipHeaderLen+udpHeaderLen {
		return nil
	}

	// Check IP version and protocol
	if data[0]>>4 != 4 {
		return nil
	}
	if data[9] != 17 { // UDP
		return nil
	}

	ihl := int(data[0]&0x0F) * 4
	if len(data) < ihl+udpHeaderLen {
		return nil
	}

	// Check destination port is 68 (DHCP client)
	dstPort := binary.BigEndian.Uint16(data[ihl+2 : ihl+4])
	if dstPort != 68 {
		return nil
	}

	return data[ihl+udpHeaderLen:]
}
