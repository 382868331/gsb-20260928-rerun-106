// Command tcprecon performs offline bidirectional TCP session reassembly
// from a libpcap capture. It never touches a network interface.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"tcprecon/pcapio"
	"tcprecon/session"
)

func main() {
	path := flag.String("f", "testdata/capture.pcap", "pcap file to analyze")
	maxBytes := flag.Int("max-bytes-per-dir", 0, "budget: max reassembled bytes per direction (0=unlimited)")
	maxTotal := flag.Int("max-total-bytes", 0, "budget: max total reassembled bytes (0=unlimited)")
	maxSessions := flag.Int("max-sessions", 0, "budget: max sessions (0=unlimited)")
	maxFrames := flag.Int("max-frames", 0, "budget: max capture frames processed (0=unlimited)")
	flag.Parse()

	f, err := os.Open(*path)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	r, err := pcapio.NewReader(f)
	if err != nil {
		fatal(err)
	}
	frames, err := r.ReadAll()
	if err != nil {
		fatal(err)
	}

	eng := session.NewEngine(session.Budget{
		MaxSessions:    *maxSessions,
		MaxFrames:      *maxFrames,
		MaxBytesPerDir: *maxBytes,
		MaxTotalBytes:  *maxTotal,
	})
	if err := eng.Process(frames, r.Header.Network); err != nil {
		fatal(err)
	}

	for _, s := range eng.Sessions() {
		printSession(s)
	}
	st := eng.Stats()
	fmt.Printf("\n== summary ==\nframes=%d tcp=%d non-tcp=%d sessions=%d late=%d orphans=%d dropped=%d\n",
		st.Frames, st.TCPSegments, st.NonTCP, st.Sessions, st.LateSegments, st.Orphans, st.DroppedFrames)
	if st.Exhausted {
		fmt.Printf("BUDGET EXHAUSTED: %s\n", st.ExhaustReason)
	}
}

func printSession(s *session.Session) {
	state := "open"
	if s.Closed() {
		state = "closed(" + s.CloseReason() + ")"
	}
	fmt.Printf("\n===== session #%d incarnation=%d  %s -> %s  [%s] =====\n",
		s.ID, s.Incarnation, s.Client, s.Server, state)
	for _, dir := range []int{session.C2S, session.S2C} {
		name := session.DirName(dir)
		fmt.Printf("--- %s ---\n", name)
		spans := s.Spans(dir)
		if len(spans) == 0 {
			fmt.Println("(no data)")
		} else {
			for _, sp := range spans {
				if sp.Gap {
					fmt.Printf("  [GAP rel=%d..%d %d bytes missing]\n", sp.Start, sp.End, sp.End-sp.Start)
					continue
				}
				fmt.Printf("  [DATA rel=%d..%d] %q\n", sp.Start, sp.End, string(sp.Data))
			}
		}
		for _, g := range s.Gaps(dir) {
			fmt.Printf("  GAP %s rel=%d..%d (%d bytes never recovered)\n", name, g.Start, g.End, g.End-g.Start)
		}
	}
	for _, c := range s.Conflicts() {
		kind := "retransmit"
		if c.Kind == session.KindOverwrite {
			kind = "OVERWRITE-CONFLICT"
		}
		if c.Kind == session.KindOverwrite {
			fmt.Printf("  EVIDENCE frame=%d %s %s at rel=%d existing=0x%02x new=0x%02x (%s)\n",
				c.FrameIndex, session.DirName(c.Dir), kind, c.OverlapAt, c.Existing, c.New, c.Resolution)
		} else {
			fmt.Printf("  EVIDENCE frame=%d %s %s overlap@rel=%d (%s)\n",
				c.FrameIndex, session.DirName(c.Dir), kind, c.OverlapAt, c.Resolution)
		}
	}
	late := 0
	for _, ev := range s.Frames() {
		if ev.Disposition == "late-after-close" {
			late++
		}
	}
	if late > 0 {
		fmt.Printf("  LATE-EVIDENCE %d segment(s) after close kept out of reassembly\n", late)
	}
	for _, d := range s.Drops() {
		dir := "c2s"
		if d.Dir == session.S2C {
			dir = "s2c"
		}
		fmt.Printf("  DROP frame=%d %s %s\n", d.FrameIndex, dir, strings.ToUpper(d.Reason))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "tcprecon:", err)
	os.Exit(1)
}
