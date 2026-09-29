package pcapio

import "net"

// Segment is a parsed TCP segment with a reference to its raw frame.
type Segment struct {
	Frame      *Frame
	SrcIP      net.IP
	DstIP      net.IP
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	Data       []byte
	SYN, FIN   bool
	RST, PSH   bool
	ACK        bool
	IPProto    uint8
	IPCapLen   int // bytes of IP datagram captured (truncated if smaller than total length)
	IPTotalLen int
	TCPHdrLen  int
}

// DecodeFrame extracts a TCP segment from a captured link-layer frame.
// Non-TCP / non-IP frames return (nil, nil) so callers can simply skip them.
func DecodeFrame(f *Frame, link LinkType) (*Segment, error) {
	var ipPayload []byte
	var proto uint8
	var totalLen int
	switch link {
	case LinkEthernet:
		if len(f.Data) < 14 {
			return nil, nil
		}
		ethertype := uint16(f.Data[12])<<8 | uint16(f.Data[13])
		ipPayload = f.Data[14:]
		if ethertype == 0x8100 { // 802.1Q VLAN tag
			if len(f.Data) < 18 {
				return nil, nil
			}
			ethertype = uint16(f.Data[16])<<8 | uint16(f.Data[17])
			ipPayload = f.Data[18:]
		}
		switch ethertype {
		case 0x0800:
			proto = 6 // may be overwritten from IP header
		case 0x86dd:
			proto = 41
		default:
			return nil, nil
		}
	case LinkLinuxSLL:
		if len(f.Data) < 16 {
			return nil, nil
		}
		ethertype := uint16(f.Data[14])<<8 | uint16(f.Data[15])
		ipPayload = f.Data[16:]
		switch ethertype {
		case 0x0800, 0x86dd:
		default:
			return nil, nil
		}
	default:
		return nil, nil
	}

	var srcIP, dstIP net.IP
	var tcpData []byte
	var srcPort, dstPort, seq, ack uint32
	var dataOff, flags uint8

	if len(ipPayload) > 0 && ipPayload[0]>>4 == 4 {
		if len(ipPayload) < 20 {
			return nil, nil
		}
		ihl := int(ipPayload[0]&0x0f) * 4
		if ihl < 20 || len(ipPayload) < ihl {
			return nil, nil
		}
		proto = ipPayload[9]
		if proto != 6 {
			return nil, nil
		}
		totalLen = int(uint16(ipPayload[2])<<8 | uint16(ipPayload[3]))
		if totalLen == 0 {
			totalLen = len(ipPayload) // IP trailer / TSO fallback
		}
		if totalLen > len(ipPayload) {
			// Captured truncation: work with what we have but record it.
			totalLen = len(ipPayload)
		}
		end := totalLen
		if end > len(ipPayload) {
			end = len(ipPayload)
		}
		srcIP = append(net.IP(nil), ipPayload[12:16]...)
		dstIP = append(net.IP(nil), ipPayload[16:20]...)
		tcpData = ipPayload[ihl:end]
	} else if len(ipPayload) > 0 && ipPayload[0]>>4 == 6 {
		if len(ipPayload) < 40 {
			return nil, nil
		}
		proto = 41
		if ipPayload[6] != 6 {
			return nil, nil
		}
		payloadLen := int(uint16(ipPayload[4])<<8 | uint16(ipPayload[5]))
		totalLen = 40 + payloadLen
		if totalLen > len(ipPayload) {
			totalLen = len(ipPayload)
		}
		srcIP = append(net.IP(nil), ipPayload[8:24]...)
		dstIP = append(net.IP(nil), ipPayload[24:40]...)
		tcpData = ipPayload[40:totalLen]
	} else {
		return nil, nil
	}

	if len(tcpData) < 20 {
		return nil, nil
	}
	srcPort = uint32(tcpData[0])<<8 | uint32(tcpData[1])
	dstPort = uint32(tcpData[2])<<8 | uint32(tcpData[3])
	seq = uint32(tcpData[4])<<24 | uint32(tcpData[5])<<16 | uint32(tcpData[6])<<8 | uint32(tcpData[7])
	ack = uint32(tcpData[8])<<24 | uint32(tcpData[9])<<16 | uint32(tcpData[10])<<8 | uint32(tcpData[11])
	dataOff = tcpData[12] >> 4
	flags = tcpData[13]
	hdrLen := int(dataOff) * 4
	if hdrLen < 20 || hdrLen > len(tcpData) {
		return nil, nil
	}
	payload := tcpData[hdrLen:]

	return &Segment{
		Frame:      f,
		SrcIP:      srcIP,
		DstIP:      dstIP,
		SrcPort:    uint16(srcPort),
		DstPort:    uint16(dstPort),
		Seq:        seq,
		Ack:        ack,
		Data:       payload,
		SYN:        flags&0x02 != 0,
		FIN:        flags&0x01 != 0,
		RST:        flags&0x04 != 0,
		PSH:        flags&0x08 != 0,
		ACK:        flags&0x10 != 0,
		IPProto:    proto,
		IPCapLen:   len(ipPayload),
		IPTotalLen: totalLen,
		TCPHdrLen:  hdrLen,
	}, nil
}
