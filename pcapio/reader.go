// Package pcapio reads and writes classic libpcap capture files.
// Only the pieces needed for offline TCP forensics are implemented:
// Ethernet / Linux SLL link layers, IPv4/IPv6 and TCP.
package pcapio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// LinkType selects the data-link framing used inside the capture.
type LinkType uint32

const (
	LinkEthernet LinkType = 1
	LinkLinuxSLL LinkType = 113
)

// GlobalHeader is the 24-byte pcap global header.
type GlobalHeader struct {
	Magic    uint32
	VersionM uint16
	VersionN uint16
	Thiszone int32
	Sigfigs  uint32
	Snaplen  uint32
	Network  LinkType
}

// Frame is one captured link-layer frame.
type Frame struct {
	TSec    int64
	TSusec  int64
	CapLen  int
	OrigLen int
	Data    []byte
	Index   int // zero-based position of the frame within the capture
}

// Reader streams frames from a pcap file.
type Reader struct {
	r       io.Reader
	bo      binary.ByteOrder
	nano    bool
	Header  GlobalHeader
	nextIdx int
}

const pcapMagicMicro = 0xa1b2c3d4
const pcapMagicNano = 0xa1b23c4d

// NewReader parses the global header and returns a streaming reader.
func NewReader(r io.Reader) (*Reader, error) {
	var buf [24]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, fmt.Errorf("read pcap global header: %w", err)
	}
	m := binary.LittleEndian.Uint32(buf[0:4])
	pr := &Reader{r: r}
	switch m {
	case pcapMagicMicro, pcapMagicNano:
		pr.bo = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		pr.bo = binary.BigEndian
	default:
		return nil, errors.New("not a pcap file (bad magic)")
	}
	pr.nano = m == pcapMagicNano || m == 0x4d3cb2a1
	h := GlobalHeader{
		Magic:    m,
		VersionM: pr.bo.Uint16(buf[4:6]),
		VersionN: pr.bo.Uint16(buf[6:8]),
		Thiszone: int32(pr.bo.Uint32(buf[8:12])),
		Sigfigs:  pr.bo.Uint32(buf[12:16]),
		Snaplen:  pr.bo.Uint32(buf[16:20]),
		Network:  LinkType(pr.bo.Uint32(buf[20:24])),
	}
	if h.Network != LinkEthernet && h.Network != LinkLinuxSLL {
		return nil, fmt.Errorf("unsupported link type %d", h.Network)
	}
	pr.Header = h
	return pr, nil
}

// Next returns the next frame or io.EOF.
func (pr *Reader) Next() (*Frame, error) {
	var hdr [16]byte
	if _, err := io.ReadFull(pr.r, hdr[:]); err != nil {
		return nil, err
	}
	sec := int64(pr.bo.Uint32(hdr[0:4]))
	sub := int64(pr.bo.Uint32(hdr[4:8]))
	if pr.nano {
		sub /= 1000 // nanoseconds -> microseconds
	}
	capLen := int(pr.bo.Uint32(hdr[8:12]))
	origLen := int(pr.bo.Uint32(hdr[12:16]))
	if capLen < 0 || capLen > 0x40000000 {
		return nil, fmt.Errorf("implausible captured length %d at frame %d", capLen, pr.nextIdx)
	}
	data := make([]byte, capLen)
	if _, err := io.ReadFull(pr.r, data); err != nil {
		return nil, fmt.Errorf("truncated frame %d: %w", pr.nextIdx, err)
	}
	f := &Frame{TSec: sec, TSusec: sub, CapLen: capLen, OrigLen: origLen, Data: data, Index: pr.nextIdx}
	pr.nextIdx++
	return f, nil
}

// ReadAll consumes the reader and returns every frame.
func (pr *Reader) ReadAll() ([]*Frame, error) {
	var out []*Frame
	for {
		f, err := pr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, f)
	}
}
