package netforensics

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"
)

type TCPFrameSpec struct {
	Time    time.Time
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   byte
	Payload []byte
	IPID    uint16
}

func WritePCAP(frames []TCPFrameSpec) ([]byte, error) {
	var buf bytes.Buffer
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagicMicro)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	buf.Write(hdr)
	for _, f := range frames {
		frame, err := buildEthernetIPv4TCP(f)
		if err != nil {
			return nil, err
		}
		rec := make([]byte, 16)
		sec := f.Time.Unix()
		if f.Time.IsZero() {
			sec = 0
		}
		usec := int64(0)
		if !f.Time.IsZero() {
			usec = int64(f.Time.Nanosecond()) / 1000
		}
		binary.LittleEndian.PutUint32(rec[0:4], uint32(sec))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(usec))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(frame)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(frame)))
		buf.Write(rec)
		buf.Write(frame)
	}
	return buf.Bytes(), nil
}

func buildEthernetIPv4TCP(f TCPFrameSpec) ([]byte, error) {
	src := net.ParseIP(f.SrcIP).To4()
	dst := net.ParseIP(f.DstIP).To4()
	if src == nil || dst == nil {
		return nil, ErrInvalidAddress
	}
	frame := make([]byte, 14+20+20+len(f.Payload))
	frame[12] = 0x08
	// frame[13] remains zero: EtherType IPv4.
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(40+len(f.Payload)))
	binary.BigEndian.PutUint16(ip[4:6], f.IPID)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	sum := checksum(ip[:20])
	binary.BigEndian.PutUint16(ip[10:12], sum)
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], f.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], f.DstPort)
	binary.BigEndian.PutUint32(tcp[4:8], f.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], f.Ack)
	tcp[12] = 5 << 4
	tcp[13] = f.Flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:], f.Payload)
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(pseudo))
	return frame, nil
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
