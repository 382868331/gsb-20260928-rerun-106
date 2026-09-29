package pcapio

import (
	"net"
)

// TCPFlags is a bitmask of TCP flags for the builder.
type TCPFlags uint8

const (
	FlagFIN TCPFlags = 0x01
	FlagSYN TCPFlags = 0x02
	FlagRST TCPFlags = 0x04
	FlagPSH TCPFlags = 0x08
	FlagACK TCPFlags = 0x10
)

// TCPEnd describes one TCP segment for BuildFrame.
type TCPEnd struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   TCPFlags
	Payload []byte
}

// BuildFrame constructs an Ethernet/IPv4/TCP frame (no options, no VLAN).
// Checksums are zeroed: reassembly does not validate them and the builder
// exists solely to create deterministic offline evidence.
func BuildFrame(t TCPEnd) []byte {
	src4 := t.SrcIP.To4()
	dst4 := t.DstIP.To4()
	tcpLen := 20 + len(t.Payload)
	ipLen := 20 + tcpLen
	frame := make([]byte, 14+ipLen)

	// Ethernet
	frame[0], frame[1], frame[2] = 0x02, 0x00, 0x00
	copy(frame[0:6], macFor(t.SrcIP))
	copy(frame[6:12], macFor(t.DstIP))
	frame[12], frame[13] = 0x08, 0x00

	// IPv4
	ip := frame[14:]
	ip[0] = 0x45
	ip[1] = 0x00
	ip[2] = byte(ipLen >> 8)
	ip[3] = byte(ipLen)
	ip[4], ip[5] = 0x12, 0x34 // identification
	ip[6], ip[7] = 0x00, 0x00 // DF off, no frag
	ip[8] = 64
	ip[9] = 6
	// checksum left zero
	copy(ip[12:16], src4)
	copy(ip[16:20], dst4)

	// TCP
	tcp := ip[20:]
	tcp[0] = byte(t.SrcPort >> 8)
	tcp[1] = byte(t.SrcPort)
	tcp[2] = byte(t.DstPort >> 8)
	tcp[3] = byte(t.DstPort)
	tcp[4] = byte(t.Seq >> 24)
	tcp[5] = byte(t.Seq >> 16)
	tcp[6] = byte(t.Seq >> 8)
	tcp[7] = byte(t.Seq)
	tcp[8] = byte(t.Ack >> 24)
	tcp[9] = byte(t.Ack >> 16)
	tcp[10] = byte(t.Ack >> 8)
	tcp[11] = byte(t.Ack)
	tcp[12] = 5 << 4 // data offset 5
	tcp[13] = byte(t.Flags)
	tcp[14], tcp[15] = 0x20, 0x00 // window 8192
	// checksum/urgent zero
	copy(tcp[20:], t.Payload)

	// IPv4 header checksum
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(ip[i])<<8 | uint32(ip[i+1])
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	cs := ^uint16(sum)
	ip[10], ip[11] = byte(cs>>8), byte(cs)
	return frame
}

func macFor(ip net.IP) []byte {
	ip4 := ip.To4()
	return []byte{0x02, 0x00, 0x00, ip4[1], ip4[2], ip4[3]}
}
