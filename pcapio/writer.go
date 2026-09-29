package pcapio

import (
	"encoding/binary"
	"io"
)

// Writer emits classic little-endian microsecond-resolution pcap files.
type Writer struct {
	w io.Writer
}

// NewWriter writes a global header for the given link type.
func NewWriter(w io.Writer, link LinkType, snaplen uint32) (*Writer, error) {
	if snaplen == 0 {
		snaplen = 65535
	}
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], pcapMagicMicro)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], snaplen)
	binary.LittleEndian.PutUint32(hdr[20:24], uint32(link))
	if _, err := w.Write(hdr[:]); err != nil {
		return nil, err
	}
	return &Writer{w: w}, nil
}

// WriteFrame records one frame.
func (pw *Writer) WriteFrame(f *Frame) error {
	var hdr [16]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(f.TSec))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(f.TSusec))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(len(f.Data)))
	orig := f.OrigLen
	if orig == 0 {
		orig = len(f.Data)
	}
	binary.LittleEndian.PutUint32(hdr[12:16], uint32(orig))
	if _, err := pw.w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := pw.w.Write(f.Data)
	return err
}
