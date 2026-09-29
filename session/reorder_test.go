package session_test

import (
	"bytes"
	"net"
	"testing"

	"tcprecon/pcapio"
	"tcprecon/session"
)

// miniCapture builds an in-memory pcap set of TCP frames.
type mini struct {
	frames []*pcapio.Frame
}

func (m *mini) frame(t pcapio.TCPEnd) {
	m.frames = append(m.frames, &pcapio.Frame{Data: pcapio.BuildFrame(t)})
}

func runMini(t *testing.T, m *mini, b session.Budget) *session.Engine {
	eng := session.NewEngine(b)
	if err := eng.Process(m.frames, pcapio.LinkEthernet); err != nil {
		t.Fatalf("process: %v", err)
	}
	return eng
}

// TestOutOfOrderHoleFilled verifies that a temporarily missing range is
// reported as a gap, then disappears once the late in-order chunk arrives.
func TestOutOfOrderHoleFilled(t *testing.T) {
	c, s := net.ParseIP("1.1.1.1").To4(), net.ParseIP("2.2.2.2").To4()
	cp, sp := uint16(5000), uint16(6000)
	cISN, sISN := uint32(100), uint32(900)
	seg := func(seq, ack uint32, fl pcapio.TCPFlags, p []byte, fromC bool) pcapio.TCPEnd {
		var si, di net.IP
		var sp2, dp uint16
		if fromC {
			si, di, sp2, dp = c, s, cp, sp
		} else {
			si, di, sp2, dp = s, c, sp, cp
		}
		return pcapio.TCPEnd{SrcIP: si, DstIP: di, SrcPort: sp2, DstPort: dp, Seq: seq, Ack: ack, Flags: fl, Payload: p}
	}

	m1 := &mini{}
	m1.frame(seg(cISN, 0, pcapio.FlagSYN, nil, true))
	m1.frame(seg(sISN, cISN+1, pcapio.FlagSYN|pcapio.FlagACK, nil, false))
	m1.frame(seg(cISN+1, sISN+1, pcapio.FlagACK, nil, true))
	// rel 11..15 arrives before rel 1..10
	m1.frame(seg(sISN+11, cISN+1, pcapio.FlagPSH|pcapio.FlagACK, []byte("KLMNO"), false))
	e1 := runMini(t, m1, session.Budget{})
	sess := e1.Sessions()[0]
	if len(sess.Gaps(session.S2C)) == 0 {
		t.Fatal("expected a gap while first chunk missing")
	}
	if len(sess.Payload(session.S2C)) != 0 {
		t.Fatalf("nothing in-order should be delivered, got %q", sess.Payload(session.S2C))
	}

	m1.frame(seg(sISN+1, cISN+1, pcapio.FlagPSH|pcapio.FlagACK, []byte("ABCDEFGHIJ"), false))
	e2 := runMini(t, m1, session.Budget{})
	sess = e2.Sessions()[0]
	if len(sess.Gaps(session.S2C)) != 0 {
		t.Fatalf("gap should be resolved, got %+v", sess.Gaps(session.S2C))
	}
	if !bytes.Equal(sess.Payload(session.S2C), []byte("ABCDEFGHIJKLMNO")) {
		t.Fatalf("reassembled = %q", sess.Payload(session.S2C))
	}
}

// TestSequenceNumberWrapping makes sure relative coords work near 2^32.
func TestSequenceNumberWrapping(t *testing.T) {
	c, s := net.ParseIP("1.1.1.1").To4(), net.ParseIP("2.2.2.2").To4()
	cp, sp := uint16(5100), uint16(6100)
	sISN := uint32(0xFFFFFFFA) // wraps after 5 bytes
	m := &mini{}
	syn := pcapio.TCPEnd{SrcIP: c, DstIP: s, SrcPort: cp, DstPort: sp, Seq: 1, Flags: pcapio.FlagSYN}
	m.frame(syn)
	m.frame(pcapio.TCPEnd{SrcIP: s, DstIP: c, SrcPort: sp, DstPort: cp, Seq: sISN, Ack: 2, Flags: pcapio.FlagSYN | pcapio.FlagACK})
	m.frame(pcapio.TCPEnd{SrcIP: c, DstIP: s, SrcPort: cp, DstPort: sp, Seq: 2, Ack: sISN + 1, Flags: pcapio.FlagACK})
	// 12 bytes starting 6 bytes before the wrap boundary.
	m.frame(pcapio.TCPEnd{SrcIP: s, DstIP: c, SrcPort: sp, DstPort: cp, Seq: sISN + 1, Ack: 2,
		Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: []byte("abcdef123456")})
	eng := runMini(t, m, session.Budget{})
	got := string(eng.Sessions()[0].Payload(session.S2C))
	if got != "abcdef123456" {
		t.Fatalf("wrap reassembly = %q", got)
	}
}
