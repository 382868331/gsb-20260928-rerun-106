package pcapio_test

import (
	"bytes"
	"net"
	"testing"

	"tcprecon/pcapio"
)

func TestWriteReadRoundTrip(t *testing.T) {
	frames := []*pcapio.Frame{
		{TSec: 100, TSusec: 250, Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{TSec: 100, TSusec: 750, Data: bytes.Repeat([]byte{0xAB}, 64)},
	}
	var buf bytes.Buffer
	w, err := pcapio.NewWriter(&buf, pcapio.LinkEthernet, 128)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		if err := w.WriteFrame(f); err != nil {
			t.Fatal(err)
		}
	}
	r, err := pcapio.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if r.Header.Network != pcapio.LinkEthernet {
		t.Fatalf("network = %d", r.Header.Network)
	}
	got, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(frames) {
		t.Fatalf("frames = %d", len(got))
	}
	for i, f := range got {
		if f.TSec != frames[i].TSec || f.TSusec != frames[i].TSusec {
			t.Errorf("frame %d timestamp = %d.%d", i, f.TSec, f.TSusec)
		}
		if !bytes.Equal(f.Data, frames[i].Data) {
			t.Errorf("frame %d payload mismatch", i)
		}
	}
}

func TestDecodeBuildTCPSegment(t *testing.T) {
	payload := []byte("xyz")
	frame := &pcapio.Frame{Data: pcapio.BuildFrame(pcapio.TCPEnd{
		SrcIP:   net.ParseIP("10.1.2.3"),
		DstIP:   net.ParseIP("10.4.5.6"),
		SrcPort: 1234, DstPort: 80,
		Seq: 42, Ack: 99,
		Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: payload,
	})}
	seg, err := pcapio.DecodeFrame(frame, pcapio.LinkEthernet)
	if err != nil || seg == nil {
		t.Fatalf("seg=%v err=%v", seg, err)
	}
	if seg.Seq != 42 || seg.Ack != 99 || !seg.PSH || !seg.ACK {
		t.Fatalf("flags/seq wrong: %+v", seg)
	}
	if !bytes.Equal(seg.Data, payload) {
		t.Fatalf("payload = %q", seg.Data)
	}
}
