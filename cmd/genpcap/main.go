// Command genpcap creates the bundled hand-crafted capture used by the
// forensic reassembly tests. It writes testdata/capture.pcap by default.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"tcprecon/pcapio"
)

func ip(s string) net.IP { return net.ParseIP(s).To4() }

type script struct {
	w     *pcapio.Writer
	idx   int
	clock int64
}

func (sc *script) emit(fr *pcapio.Frame) {
	fr.Index = sc.idx
	sc.idx++
	if fr.TSec == 0 {
		fr.TSec = 1700000000
		fr.TSusec = sc.clock
		sc.clock += 1000
	}
	if err := sc.w.WriteFrame(fr); err != nil {
		panic(err)
	}
}

func (sc *script) tcp(t pcapio.TCPEnd) {
	sc.emit(&pcapio.Frame{Data: pcapio.BuildFrame(t)})
}

func main() {
	out := flag.String("out", "testdata/capture.pcap", "output pcap path")
	flag.Parse()
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		panic(err)
	}
	f, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	w, err := pcapio.NewWriter(f, pcapio.LinkEthernet, 65535)
	if err != nil {
		panic(err)
	}
	sc := &script{w: w}

	client := ip("10.0.0.10")
	server := ip("10.0.0.1")
	const cp, sp = 41000, 80

	// ---------- Session A: clean request + out-of-order/overlap response -----
	cISN := uint32(1000)
	sISN := uint32(5000)
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cISN, Flags: pcapio.FlagSYN})
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN, Ack: cISN + 1, Flags: pcapio.FlagSYN | pcapio.FlagACK})
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cISN + 1, Ack: sISN + 1, Flags: pcapio.FlagACK})

	req := []byte("HELLO FORENSICS\n")
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cISN + 1, Ack: sISN + 1, Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: req})
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN + 1, Ack: cISN + 1 + uint32(len(req)), Flags: pcapio.FlagACK})

	// Response delivered in two chunks; second chunk arrives first (reorder).
	r1 := []byte("AAAA-BBBB-") // rel 1..10
	r2 := []byte("CCCC-DDDD")  // rel 11..20
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cISN + 1 + uint32(len(req)), Ack: sISN + 1, Flags: pcapio.FlagACK})
	// out-of-order: r2 first
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN + 1 + 10, Ack: cISN + 1 + uint32(len(req)),
		Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: r2})
	// retransmit of r2 (identical) while still waiting on r1
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN + 1 + 10, Ack: cISN + 1 + uint32(len(req)),
		Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: append([]byte(nil), r2...)})
	// r1 arrives, filling the hole
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN + 1, Ack: cISN + 1 + uint32(len(req)),
		Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: r1})

	// full-response identical retransmit after assembly (retransmit evidence)
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN + 1, Ack: cISN + 1 + uint32(len(req)), Flags: pcapio.FlagACK,
		Payload: append(append([]byte(nil), r1...), r2...)})

	// Teardown: client FIN, server ACK, server FIN, client ACK.
	cNext := cISN + 1 + uint32(len(req))
	sNext := sISN + 1 + uint32(len(r1)) + uint32(len(r2))
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cNext, Ack: sNext, Flags: pcapio.FlagFIN | pcapio.FlagACK})
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sNext, Ack: cNext + 1, Flags: pcapio.FlagACK})
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sNext, Ack: cNext + 1, Flags: pcapio.FlagFIN | pcapio.FlagACK})
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cNext + 1, Ack: sNext + 1, Flags: pcapio.FlagACK})

	// Late data for the CLOSED session A: must NOT join session B.
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sNext - 5, Ack: cNext + 1, Flags: pcapio.FlagPSH | pcapio.FlagACK,
		Payload: []byte("LATE-LATE")})

	// ---------- Session B: reused 4-tuple, new incarnation, overlap conflict + gap --
	cISN2 := uint32(9000)
	sISN2 := uint32(3000)
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cISN2, Flags: pcapio.FlagSYN})
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN2, Ack: cISN2 + 1, Flags: pcapio.FlagSYN | pcapio.FlagACK})
	sc.tcp(pcapio.TCPEnd{SrcIP: client, DstIP: server, SrcPort: cp, DstPort: sp,
		Seq: cISN2 + 1, Ack: sISN2 + 1, Flags: pcapio.FlagACK})

	// server data rel 1..12 then a gap (13..16 missing) then rel 17..24
	b1 := []byte("0123456789AB") // 12 bytes
	b3 := []byte("QRSTUVWX")     // 8 bytes at rel 17
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN2 + 1, Ack: cISN2 + 1, Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: b1})
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN2 + 1 + 16, Ack: cISN2 + 1, Flags: pcapio.FlagPSH | pcapio.FlagACK, Payload: b3})

	// conflicting retransmit of the tail of b1 (rel 9..12) with wrong bytes
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN2 + 1 + 8, Ack: cISN2 + 1, Flags: pcapio.FlagPSH | pcapio.FlagACK,
		Payload: []byte("ZZZZ")})

	// close B with RST (immediate close); late data follows and must be late evidence
	bNext := sISN2 + 1 + 24
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: bNext, Ack: cISN2 + 1, Flags: pcapio.FlagRST | pcapio.FlagACK})
	sc.tcp(pcapio.TCPEnd{SrcIP: server, DstIP: client, SrcPort: sp, DstPort: cp,
		Seq: sISN2 + 1, Ack: cISN2 + 1, Flags: pcapio.FlagPSH | pcapio.FlagACK,
		Payload: []byte("AFTER-RST")})

	fmt.Printf("wrote %s (%d frames)\n", *out, sc.idx)
}
