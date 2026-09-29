package netforensics

import "time"

const (
	GoldenClientIP   = "10.0.0.10"
	GoldenServerIP   = "10.0.0.20"
	GoldenClientPort = 41000
	GoldenServerPort = 8080
)

func GoldenFrames() []TCPFrameSpec {
	t := time.Unix(1_700_000_000, 0).UTC()
	cISN := uint32(1000)
	sISN := uint32(5000)
	cNext := cISN + 1
	sNext := sISN + 1
	clientRequest := []byte("HELLO\n")
	serverReply1 := []byte("ECHO:")
	serverReply2 := []byte("HELLO")
	frames := []TCPFrameSpec{
		goldenFrame(t, true, cISN, sISN, 0x02, nil, 1),
		goldenFrame(t.Add(time.Millisecond), false, sISN, cISN+1, 0x12, nil, 1),
		goldenFrame(t.Add(2*time.Millisecond), true, cISN+1, sISN+1, 0x10, nil, 1),
	}
	cNext += uint32(len(clientRequest))
	frames = append(frames,
		// Client data arrives after a later server segment to prove c2s/s2c
		// streams are independent.
		goldenFrame(t.Add(4*time.Millisecond), false, sNext, cISN+1, 0x18, serverReply1, 10),
		goldenFrame(t.Add(5*time.Millisecond), true, cISN+1, sISN+1, 0x18, clientRequest, 10),
	)
	sNext += uint32(len(serverReply1))
	frames = append(frames,
		// Exact retransmission of first server payload.
		goldenFrame(t.Add(6*time.Millisecond), false, sISN+1, cISN+1, 0x18, serverReply1, 10),
		// Same start, different overlapping content: first observation wins.
		goldenFrame(t.Add(7*time.Millisecond), false, sISN+1, cISN+1, 0x18, []byte("XXXX:"), 11),
	)
	serverReply2 = append(serverReply2, '!')
	frames = append(frames,
		// Out-of-order tail; gap exists briefly before the following middle.
		goldenFrame(t.Add(8*time.Millisecond), false, sNext+2, cNext, 0x18, serverReply2[2:], 12),
		goldenFrame(t.Add(9*time.Millisecond), false, sNext, cNext, 0x18, serverReply2[:2], 13),
	)
	sNext += uint32(len(serverReply2))
	cFin := cNext
	sFin := sNext
	frames = append(frames,
		goldenFrame(t.Add(10*time.Millisecond), true, cFin, sFin, 0x11, nil, 20),
		goldenFrame(t.Add(11*time.Millisecond), false, sFin, cFin+1, 0x11, nil, 20),
		goldenFrame(t.Add(12*time.Millisecond), true, cFin+1, sFin+1, 0x10, nil, 20),
		// Late frame after close; must be retained only as evidence.
		goldenFrame(t.Add(20*time.Millisecond), false, sISN+1, cFin+1, 0x18, []byte("LATE"), 99),
	)
	return frames
}

func GoldenPCAP() ([]byte, error) {
	return WritePCAP(GoldenFrames())
}

func GoldenExpectedClient() []byte {
	return []byte("HELLO\n")
}

func GoldenExpectedServer() []byte {
	return []byte("ECHO:HELLO!")
}

func goldenFrame(at time.Time, clientToServer bool, seq, ack uint32, flags byte, payload []byte, ipid uint16) TCPFrameSpec {
	f := TCPFrameSpec{
		Time:    at,
		SrcIP:   GoldenClientIP,
		DstIP:   GoldenServerIP,
		SrcPort: GoldenClientPort,
		DstPort: GoldenServerPort,
		Seq:     seq,
		Ack:     ack,
		Flags:   flags,
		Payload: append([]byte(nil), payload...),
		IPID:    ipid,
	}
	if !clientToServer {
		f.SrcIP, f.DstIP = GoldenServerIP, GoldenClientIP
		f.SrcPort, f.DstPort = GoldenServerPort, GoldenClientPort
	}
	return f
}
