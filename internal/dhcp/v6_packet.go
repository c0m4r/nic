package dhcp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// DHCPv6 message types.
const (
	msgV6Solicit   byte = 1
	msgV6Advertise byte = 2
	msgV6Request   byte = 3
	msgV6Renew     byte = 5
	msgV6Rebind    byte = 6
	msgV6Reply     byte = 7
	msgV6Release   byte = 8
)

// DHCPv6 option types.
const (
	optV6ClientID    uint16 = 1
	optV6ServerID    uint16 = 2
	optV6IANA        uint16 = 3
	optV6IAAddr      uint16 = 5
	optV6ORO         uint16 = 6
	optV6Preference  uint16 = 7
	optV6ElapsedTime uint16 = 8
	optV6StatusCode  uint16 = 13
	optV6DNSServers  uint16 = 23
	optV6DomainList  uint16 = 24
)

// DUID types.
const (
	duidTypeLLT uint16 = 1 // Link-layer Address Plus Time
)

// v6Message represents a parsed DHCPv6 message.
type v6Message struct {
	Type          byte
	TransactionID [3]byte
	Options       []v6Option
}

type v6Option struct {
	Code uint16
	Data []byte
}

// v6DUID represents a DUID-LLT.
type v6DUID struct {
	raw []byte
}

// newDUID creates a DUID-LLT from a MAC address.
func newDUID(mac net.HardwareAddr) v6DUID {
	// DUID-LLT: type(2) + hw-type(2) + time(4) + link-layer(6) = 14 bytes
	// Time is seconds since 2000-01-01 00:00:00 UTC
	epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	secs := uint32(time.Since(epoch).Seconds())

	buf := make([]byte, 14)
	binary.BigEndian.PutUint16(buf[0:2], duidTypeLLT)
	binary.BigEndian.PutUint16(buf[2:4], 1) // hardware type: Ethernet
	binary.BigEndian.PutUint32(buf[4:8], secs)
	copy(buf[8:14], mac)

	return v6DUID{raw: buf}
}

// marshal serializes a DHCPv6 message.
func (m *v6Message) marshal() []byte {
	// Header: type(1) + transaction-id(3) = 4 bytes
	buf := make([]byte, 4)
	buf[0] = m.Type
	copy(buf[1:4], m.TransactionID[:])

	for _, opt := range m.Options {
		buf = append(buf, marshalV6Option(opt)...)
	}

	return buf
}

// parseV6Message parses a DHCPv6 message from wire format.
func parseV6Message(data []byte) (*v6Message, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("v6 message too short: %d bytes", len(data))
	}

	m := &v6Message{
		Type: data[0],
	}
	copy(m.TransactionID[:], data[1:4])

	offset := 4
	for offset+4 <= len(data) {
		code := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(length) > len(data) {
			break
		}

		m.Options = append(m.Options, v6Option{
			Code: code,
			Data: data[offset : offset+int(length)],
		})
		offset += int(length)
	}

	return m, nil
}

func marshalV6Option(opt v6Option) []byte {
	buf := make([]byte, 4+len(opt.Data))
	binary.BigEndian.PutUint16(buf[0:2], opt.Code)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(opt.Data)))
	copy(buf[4:], opt.Data)
	return buf
}

// getOption returns the first option with the given code, or nil.
func (m *v6Message) getOption(code uint16) []byte {
	for _, opt := range m.Options {
		if opt.Code == code {
			return opt.Data
		}
	}
	return nil
}

// buildSolicit creates a DHCPv6 SOLICIT message.
func buildSolicit(duid v6DUID, iaid uint32, txID [3]byte) []byte {
	m := &v6Message{
		Type:          msgV6Solicit,
		TransactionID: txID,
	}

	// Client ID
	m.Options = append(m.Options, v6Option{
		Code: optV6ClientID,
		Data: duid.raw,
	})

	// IA_NA (Identity Association for Non-temporary Addresses)
	ianaData := make([]byte, 12) // IAID(4) + T1(4) + T2(4)
	binary.BigEndian.PutUint32(ianaData[0:4], iaid)
	// T1 and T2 = 0 means let server decide
	m.Options = append(m.Options, v6Option{
		Code: optV6IANA,
		Data: ianaData,
	})

	// Option Request: DNS servers + domain list
	oro := make([]byte, 4)
	binary.BigEndian.PutUint16(oro[0:2], optV6DNSServers)
	binary.BigEndian.PutUint16(oro[2:4], optV6DomainList)
	m.Options = append(m.Options, v6Option{
		Code: optV6ORO,
		Data: oro,
	})

	// Elapsed Time (0 at start)
	m.Options = append(m.Options, v6Option{
		Code: optV6ElapsedTime,
		Data: []byte{0, 0},
	})

	return m.marshal()
}

// buildRequestV6 creates a DHCPv6 REQUEST message.
func buildRequestV6(clientDUID v6DUID, serverDUID []byte, iaid uint32, txID [3]byte, addrs []iaAddrInfo) []byte {
	m := &v6Message{
		Type:          msgV6Request,
		TransactionID: txID,
	}

	// Client ID
	m.Options = append(m.Options, v6Option{
		Code: optV6ClientID,
		Data: clientDUID.raw,
	})

	// Server ID
	m.Options = append(m.Options, v6Option{
		Code: optV6ServerID,
		Data: serverDUID,
	})

	// IA_NA with addresses
	m.Options = append(m.Options, v6Option{
		Code: optV6IANA,
		Data: buildIANA(iaid, addrs),
	})

	// Option Request
	oro := make([]byte, 4)
	binary.BigEndian.PutUint16(oro[0:2], optV6DNSServers)
	binary.BigEndian.PutUint16(oro[2:4], optV6DomainList)
	m.Options = append(m.Options, v6Option{
		Code: optV6ORO,
		Data: oro,
	})

	// Elapsed Time
	m.Options = append(m.Options, v6Option{
		Code: optV6ElapsedTime,
		Data: []byte{0, 0},
	})

	return m.marshal()
}

// buildRenewV6 creates a DHCPv6 RENEW message.
func buildRenewV6(clientDUID v6DUID, serverDUID []byte, iaid uint32, txID [3]byte, addrs []iaAddrInfo) []byte {
	m := &v6Message{
		Type:          msgV6Renew,
		TransactionID: txID,
	}

	m.Options = append(m.Options, v6Option{Code: optV6ClientID, Data: clientDUID.raw})
	m.Options = append(m.Options, v6Option{Code: optV6ServerID, Data: serverDUID})
	m.Options = append(m.Options, v6Option{Code: optV6IANA, Data: buildIANA(iaid, addrs)})
	m.Options = append(m.Options, v6Option{Code: optV6ElapsedTime, Data: []byte{0, 0}})

	return m.marshal()
}

// buildReleaseV6 creates a DHCPv6 RELEASE message.
func buildReleaseV6(clientDUID v6DUID, serverDUID []byte, iaid uint32, txID [3]byte, addrs []iaAddrInfo) []byte {
	m := &v6Message{
		Type:          msgV6Release,
		TransactionID: txID,
	}

	m.Options = append(m.Options, v6Option{Code: optV6ClientID, Data: clientDUID.raw})
	m.Options = append(m.Options, v6Option{Code: optV6ServerID, Data: serverDUID})
	m.Options = append(m.Options, v6Option{Code: optV6IANA, Data: buildIANA(iaid, addrs)})

	return m.marshal()
}

type iaAddrInfo struct {
	IP            net.IP
	PreferredLife uint32
	ValidLife     uint32
}

func buildIANA(iaid uint32, addrs []iaAddrInfo) []byte {
	// IAID(4) + T1(4) + T2(4) + sub-options
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf[0:4], iaid)

	for _, addr := range addrs {
		// IA Address option: IP(16) + preferred-life(4) + valid-life(4) = 24
		addrBuf := make([]byte, 24)
		copy(addrBuf[0:16], addr.IP.To16())
		binary.BigEndian.PutUint32(addrBuf[16:20], addr.PreferredLife)
		binary.BigEndian.PutUint32(addrBuf[20:24], addr.ValidLife)
		buf = append(buf, marshalV6Option(v6Option{Code: optV6IAAddr, Data: addrBuf})...)
	}

	return buf
}

// parseIANA extracts addresses and timers from an IA_NA option.
func parseIANA(data []byte) (iaid uint32, t1, t2 uint32, addrs []iaAddrInfo) {
	if len(data) < 12 {
		return
	}

	iaid = binary.BigEndian.Uint32(data[0:4])
	t1 = binary.BigEndian.Uint32(data[4:8])
	t2 = binary.BigEndian.Uint32(data[8:12])

	// Parse sub-options
	offset := 12
	for offset+4 <= len(data) {
		code := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		if offset+int(length) > len(data) {
			break
		}

		if code == optV6IAAddr && length >= 24 {
			sub := data[offset : offset+int(length)]
			addrs = append(addrs, iaAddrInfo{
				IP:            net.IP(sub[0:16]),
				PreferredLife: binary.BigEndian.Uint32(sub[16:20]),
				ValidLife:     binary.BigEndian.Uint32(sub[20:24]),
			})
		}

		offset += int(length)
	}

	return
}

// parseDNSServers extracts DNS server IPs from option 23.
func parseDNSServers(data []byte) []string {
	var servers []string
	for i := 0; i+16 <= len(data); i += 16 {
		ip := net.IP(data[i : i+16])
		servers = append(servers, ip.String())
	}
	return servers
}
