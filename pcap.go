package netforensics

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	pcapMagicMicro = 0xa1b2c3d4
	pcapMagicNano  = 0xa1b23c4d
)

type pcapHeader struct {
	Magic        uint32
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

func ReadPCAP(r io.Reader) ([]RawPacket, error) {
	rawHeader := make([]byte, 24)
	if _, err := io.ReadFull(r, rawHeader); err != nil {
		return nil, fmt.Errorf("read pcap header: %w", err)
	}
	magicLE := binary.LittleEndian.Uint32(rawHeader[0:4])
	var order binary.ByteOrder = binary.LittleEndian
	nanos := false
	switch magicLE {
	case pcapMagicMicro, pcapMagicNano:
		if magicLE == pcapMagicNano {
			nanos = true
		}
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.BigEndian
		if magicLE == 0x4d3cb2a1 {
			nanos = true
		}
	default:
		return nil, errors.New("unsupported pcap magic")
	}
	hdr := pcapHeader{
		Magic:        magicLE,
		VersionMajor: order.Uint16(rawHeader[4:6]),
		VersionMinor: order.Uint16(rawHeader[6:8]),
		ThisZone:     int32(order.Uint32(rawHeader[8:12])),
		SigFigs:      order.Uint32(rawHeader[12:16]),
		SnapLen:      order.Uint32(rawHeader[16:20]),
		Network:      order.Uint32(rawHeader[20:24]),
	}
	if hdr.Network != 1 {
		return nil, fmt.Errorf("unsupported link type %d: only Ethernet is supported", hdr.Network)
	}

	var packets []RawPacket
	index := 0
	for {
		var rec struct {
			TsSec      uint32
			TsFraction uint32
			InclLen    uint32
			OrigLen    uint32
		}
		if err := binary.Read(r, order, &rec); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("read pcap record header: %w", err)
		}
		frame := make([]byte, rec.InclLen)
		if _, err := io.ReadFull(r, frame); err != nil {
			return nil, fmt.Errorf("read pcap frame %d: %w", index, err)
		}
		pkt, err := parseEthernetFrame(frame)
		if err != nil {
			return nil, fmt.Errorf("parse frame %d: %w", index, err)
		}
		pkt.Index = index
		pkt.CaptureLen = int(rec.InclLen)
		pkt.OriginalLen = int(rec.OrigLen)
		if nanos {
			pkt.Timestamp = time.Unix(int64(rec.TsSec), int64(rec.TsFraction)).UTC()
		} else {
			pkt.Timestamp = time.Unix(int64(rec.TsSec), int64(rec.TsFraction)*1000).UTC()
		}
		packets = append(packets, pkt)
		index++
	}
	return packets, nil
}

func parseEthernetFrame(frame []byte) (RawPacket, error) {
	if len(frame) < 14 {
		return RawPacket{}, errors.New("short Ethernet frame")
	}
	if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return RawPacket{}, errors.New("non-IPv4 Ethernet frame")
	}
	ip := frame[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return RawPacket{}, errors.New("short or non-IPv4 packet")
	}
	hdrLen := int(ip[0]&0x0f) * 4
	if hdrLen < 20 || len(ip) < hdrLen {
		return RawPacket{}, errors.New("invalid IPv4 header length")
	}
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < hdrLen || totalLen > len(ip) {
		return RawPacket{}, errors.New("invalid IPv4 total length")
	}
	ip = ip[:totalLen]
	if ip[9] != 6 {
		return RawPacket{}, fmt.Errorf("unsupported IP protocol %d", ip[9])
	}
	tcpBuf := ip[hdrLen:]
	if len(tcpBuf) < 20 {
		return RawPacket{}, errors.New("short TCP header")
	}
	dataOff := int(tcpBuf[12]>>4) * 4
	if dataOff < 20 || len(tcpBuf) < dataOff {
		return RawPacket{}, errors.New("invalid TCP data offset")
	}
	flags := TCPFlags{
		FIN: tcpBuf[13]&0x01 != 0,
		SYN: tcpBuf[13]&0x02 != 0,
		RST: tcpBuf[13]&0x04 != 0,
		PSH: tcpBuf[13]&0x08 != 0,
		ACK: tcpBuf[13]&0x10 != 0,
		URG: tcpBuf[13]&0x20 != 0,
	}
	payload := append([]byte(nil), tcpBuf[dataOff:]...)
	return RawPacket{
		Timestamp: time.Time{},
		SrcIP:     net.IP(ip[12:16]).String(),
		DstIP:     net.IP(ip[16:20]).String(),
		SrcPort:   binary.BigEndian.Uint16(tcpBuf[0:2]),
		DstPort:   binary.BigEndian.Uint16(tcpBuf[2:4]),
		Seq:       binary.BigEndian.Uint32(tcpBuf[4:8]),
		Ack:       binary.BigEndian.Uint32(tcpBuf[8:12]),
		Flags:     flags,
		IPID:      binary.BigEndian.Uint16(ip[4:6]),
		TTL:       ip[8],
		Window:    binary.BigEndian.Uint16(tcpBuf[14:16]),
		Payload:   payload,
		Frame:     append([]byte(nil), frame...),
	}, nil
}
