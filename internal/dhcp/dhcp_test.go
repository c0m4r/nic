package dhcp

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestV4PacketRoundTrip(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	xid := uint32(0x12345678)

	discover := buildDiscover(mac, xid)
	pkt, err := parseV4Packet(discover)
	if err != nil {
		t.Fatalf("parse discover: %v", err)
	}

	if pkt.Op != bootRequest {
		t.Errorf("Op = %d, want %d", pkt.Op, bootRequest)
	}
	if pkt.XID != xid {
		t.Errorf("XID = 0x%x, want 0x%x", pkt.XID, xid)
	}
	if pkt.HType != 1 {
		t.Errorf("HType = %d, want 1", pkt.HType)
	}
	if pkt.HLen != 6 {
		t.Errorf("HLen = %d, want 6", pkt.HLen)
	}
	if pkt.messageType() != msgDiscover {
		t.Errorf("messageType = %d, want %d", pkt.messageType(), msgDiscover)
	}
	if net.HardwareAddr(pkt.CHAddr[:6]).String() != mac.String() {
		t.Errorf("CHAddr = %s, want %s", pkt.CHAddr[:6], mac)
	}
}

func TestV4RequestRoundTrip(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	xid := uint32(0xDEADBEEF)
	serverIP := net.ParseIP("192.168.1.1")
	requestedIP := net.ParseIP("192.168.1.100")

	request := buildRequest(mac, xid, serverIP, requestedIP)
	pkt, err := parseV4Packet(request)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}

	if pkt.messageType() != msgRequest {
		t.Errorf("messageType = %d, want %d", pkt.messageType(), msgRequest)
	}
	if pkt.XID != xid {
		t.Errorf("XID = 0x%x, want 0x%x", pkt.XID, xid)
	}

	sid := pkt.getOption(optServerID)
	if !net.IP(sid).Equal(serverIP) {
		t.Errorf("server ID = %s, want %s", net.IP(sid), serverIP)
	}

	rip := pkt.getOption(optRequestedIP)
	if !net.IP(rip).Equal(requestedIP) {
		t.Errorf("requested IP = %s, want %s", net.IP(rip), requestedIP)
	}
}

func TestV4OptionParsing(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")

	// Build a fake ACK
	p := newV4Base(mac, 1)
	p.Op = bootReply
	p.YIAddr = net.ParseIP("10.0.0.50").To4()
	p.Options = []v4Option{
		{optMessageType, []byte{msgAck}},
		{optSubnetMask, net.ParseIP("255.255.255.0").To4()},
		{optRouter, net.ParseIP("10.0.0.1").To4()},
		{optDNS, append(net.ParseIP("1.1.1.1").To4(), net.ParseIP("8.8.8.8").To4()...)},
		{optLeaseTime, []byte{0, 0, 0x0E, 0x10}}, // 3600 seconds
		{optDomainName, []byte("example.com")},
	}

	data := p.marshal()
	parsed, err := parseV4Packet(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if parsed.messageType() != msgAck {
		t.Errorf("type = %d, want ACK", parsed.messageType())
	}

	lease, err := parseLease("eth0", parsed)
	if err != nil {
		t.Fatalf("parseLease: %v", err)
	}

	if lease.IP != "10.0.0.50" {
		t.Errorf("IP = %s, want 10.0.0.50", lease.IP)
	}
	if lease.SubnetMask != "255.255.255.0" {
		t.Errorf("SubnetMask = %s, want 255.255.255.0", lease.SubnetMask)
	}
	if lease.Router != "10.0.0.1" {
		t.Errorf("Router = %s, want 10.0.0.1", lease.Router)
	}
	if len(lease.DNS) != 2 || lease.DNS[0] != "1.1.1.1" || lease.DNS[1] != "8.8.8.8" {
		t.Errorf("DNS = %v, want [1.1.1.1 8.8.8.8]", lease.DNS)
	}
	if lease.LeaseTime != 3600 {
		t.Errorf("LeaseTime = %d, want 3600", lease.LeaseTime)
	}
	if lease.Domain != "example.com" {
		t.Errorf("Domain = %s, want example.com", lease.Domain)
	}
	if lease.CIDR() != "10.0.0.50/24" {
		t.Errorf("CIDR = %s, want 10.0.0.50/24", lease.CIDR())
	}
}

func TestIPChecksum(t *testing.T) {
	// Standard test vector from RFC 1071
	header := []byte{
		0x45, 0x00, 0x00, 0x73,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, // checksum zeroed
		0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	sum := ipChecksum(header)
	if sum == 0 {
		t.Error("checksum should not be zero for non-trivial header")
	}

	// Verify: computing checksum of header WITH the checksum should give 0
	binary.BigEndian.PutUint16(header[10:12], sum)
	verify := ipChecksum(header)
	if verify != 0 {
		t.Errorf("verification checksum = 0x%04x, want 0", verify)
	}
}

func TestWrapUDPIP(t *testing.T) {
	payload := []byte("test dhcp")
	packet := wrapUDPIP(payload)

	if len(packet) < ipHeaderLen+udpHeaderLen+len(payload) {
		t.Fatalf("packet too short: %d", len(packet))
	}

	// Check IP version
	if packet[0]>>4 != 4 {
		t.Errorf("IP version = %d, want 4", packet[0]>>4)
	}
	// Check protocol
	if packet[9] != 17 {
		t.Errorf("protocol = %d, want 17 (UDP)", packet[9])
	}
	// Check src/dst
	if !net.IP(packet[12:16]).Equal(net.IPv4zero) {
		t.Errorf("src IP = %s, want 0.0.0.0", net.IP(packet[12:16]))
	}
	if !net.IP(packet[16:20]).Equal(net.IPv4bcast) {
		t.Errorf("dst IP = %s, want 255.255.255.255", net.IP(packet[16:20]))
	}
	// Check ports
	srcPort := binary.BigEndian.Uint16(packet[ipHeaderLen:])
	dstPort := binary.BigEndian.Uint16(packet[ipHeaderLen+2:])
	if srcPort != 68 {
		t.Errorf("src port = %d, want 68", srcPort)
	}
	if dstPort != 67 {
		t.Errorf("dst port = %d, want 67", dstPort)
	}
}

func TestExtractDHCPPayload(t *testing.T) {
	// Simulate an incoming server→client packet (dst port 68)
	dhcpPayload := buildDiscover(net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, 1)
	totalLen := ipHeaderLen + udpHeaderLen + len(dhcpPayload)
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[8] = 64
	packet[9] = 17 // UDP
	// src port 67 (server), dst port 68 (client)
	binary.BigEndian.PutUint16(packet[ipHeaderLen:], 67)
	binary.BigEndian.PutUint16(packet[ipHeaderLen+2:], 68)
	binary.BigEndian.PutUint16(packet[ipHeaderLen+4:], uint16(udpHeaderLen+len(dhcpPayload)))
	copy(packet[ipHeaderLen+udpHeaderLen:], dhcpPayload)

	extracted := extractDHCPPayload(packet)
	if extracted == nil {
		t.Fatal("extractDHCPPayload returned nil")
	}

	pkt, err := parseV4Packet(extracted)
	if err != nil {
		t.Fatalf("parse extracted: %v", err)
	}
	if pkt.messageType() != msgDiscover {
		t.Errorf("type = %d, want DISCOVER", pkt.messageType())
	}
}

func TestExtractDHCPPayloadWrongPort(t *testing.T) {
	// Create a packet with wrong destination port
	payload := []byte("not dhcp")
	packet := wrapUDPIP(payload)
	// Change dst port to something else
	binary.BigEndian.PutUint16(packet[ipHeaderLen+2:], 80)

	extracted := extractDHCPPayload(packet)
	if extracted != nil {
		t.Error("should return nil for non-DHCP packet")
	}
}

func TestV6MessageRoundTrip(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	duid := newDUID(mac)
	iaid := uint32(42)
	txID := [3]byte{0x01, 0x02, 0x03}

	solicit := buildSolicit(duid, iaid, txID)
	msg, err := parseV6Message(solicit)
	if err != nil {
		t.Fatalf("parse solicit: %v", err)
	}

	if msg.Type != msgV6Solicit {
		t.Errorf("type = %d, want %d", msg.Type, msgV6Solicit)
	}
	if msg.TransactionID != txID {
		t.Errorf("txID = %v, want %v", msg.TransactionID, txID)
	}

	// Should have Client ID option
	clientID := msg.getOption(optV6ClientID)
	if clientID == nil {
		t.Error("missing client ID option")
	}

	// Should have IA_NA option
	iana := msg.getOption(optV6IANA)
	if iana == nil {
		t.Error("missing IA_NA option")
	}

	if iana != nil {
		parsedIAID, _, _, _ := parseIANA(iana)
		if parsedIAID != iaid {
			t.Errorf("IAID = %d, want %d", parsedIAID, iaid)
		}
	}
}

func TestV6RequestRoundTrip(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	clientDUID := newDUID(mac)
	serverDUID := []byte{0, 1, 0, 1, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	iaid := uint32(100)
	txID := [3]byte{0xAA, 0xBB, 0xCC}

	addrs := []iaAddrInfo{
		{
			IP:            net.ParseIP("2001:db8::1"),
			PreferredLife: 3600,
			ValidLife:     7200,
		},
	}

	request := buildRequestV6(clientDUID, serverDUID, iaid, txID, addrs)
	msg, err := parseV6Message(request)
	if err != nil {
		t.Fatalf("parse request: %v", err)
	}

	if msg.Type != msgV6Request {
		t.Errorf("type = %d, want %d", msg.Type, msgV6Request)
	}

	sid := msg.getOption(optV6ServerID)
	if sid == nil {
		t.Error("missing server ID")
	}

	iana := msg.getOption(optV6IANA)
	if iana == nil {
		t.Fatal("missing IA_NA")
	}

	parsedIAID, _, _, parsedAddrs := parseIANA(iana)
	if parsedIAID != iaid {
		t.Errorf("IAID = %d, want %d", parsedIAID, iaid)
	}
	if len(parsedAddrs) != 1 {
		t.Fatalf("got %d addrs, want 1", len(parsedAddrs))
	}
	if !parsedAddrs[0].IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("addr = %s, want 2001:db8::1", parsedAddrs[0].IP)
	}
	if parsedAddrs[0].PreferredLife != 3600 {
		t.Errorf("preferred = %d, want 3600", parsedAddrs[0].PreferredLife)
	}
	if parsedAddrs[0].ValidLife != 7200 {
		t.Errorf("valid = %d, want 7200", parsedAddrs[0].ValidLife)
	}
}

func TestParseDNSServers(t *testing.T) {
	// Two DNS servers
	data := make([]byte, 32)
	copy(data[0:16], net.ParseIP("2001:4860:4860::8888").To16())
	copy(data[16:32], net.ParseIP("2001:4860:4860::8844").To16())

	servers := parseDNSServers(data)
	if len(servers) != 2 {
		t.Fatalf("got %d servers, want 2", len(servers))
	}
	if servers[0] != "2001:4860:4860::8888" {
		t.Errorf("server[0] = %s, want 2001:4860:4860::8888", servers[0])
	}
	if servers[1] != "2001:4860:4860::8844" {
		t.Errorf("server[1] = %s, want 2001:4860:4860::8844", servers[1])
	}
}

func TestComputeIAID(t *testing.T) {
	// Should be deterministic
	a := computeIAID("eth0")
	b := computeIAID("eth0")
	if a != b {
		t.Error("IAID should be deterministic")
	}

	// Different interfaces should get different IAIDs
	c := computeIAID("eth1")
	if a == c {
		t.Error("different interfaces should get different IAIDs")
	}
}

func TestLeaseCIDR(t *testing.T) {
	tests := []struct {
		ip   string
		mask string
		want string
	}{
		{"192.168.1.100", "255.255.255.0", "192.168.1.100/24"},
		{"10.0.0.1", "255.0.0.0", "10.0.0.1/8"},
		{"172.16.0.1", "255.255.0.0", "172.16.0.1/16"},
	}

	for _, tt := range tests {
		l := &Lease{IP: tt.ip, SubnetMask: tt.mask}
		if got := l.CIDR(); got != tt.want {
			t.Errorf("CIDR(%s, %s) = %s, want %s", tt.ip, tt.mask, got, tt.want)
		}
	}
}
