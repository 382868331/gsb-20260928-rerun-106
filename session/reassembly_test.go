package session_test

import (
	"os"
	"testing"

	"tcprecon/pcapio"
	"tcprecon/session"
)

func loadCapture(t *testing.T, path string) ([]*pcapio.Frame, pcapio.LinkType) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	r, err := pcapio.NewReader(f)
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	frames, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read frames: %v", err)
	}
	return frames, r.Header.Network
}

func analyze(t *testing.T, path string, b session.Budget) *session.Engine {
	t.Helper()
	frames, link := loadCapture(t, path)
	eng := session.NewEngine(b)
	if err := eng.Process(frames, link); err != nil {
		t.Fatalf("process: %v", err)
	}
	return eng
}

// TestBundledCaptureAgainstOracle independently derives the expected byte
// streams from the known communication script (not from the reassembler) and
// verifies the engine reproduces them exactly.
func TestBundledCaptureAgainstOracle(t *testing.T) {
	eng := analyze(t, "../testdata/capture.pcap", session.Budget{})
	stats := eng.Stats()
	if stats.Sessions != 2 {
		t.Fatalf("sessions: got %d, want 2", stats.Sessions)
	}

	ss := eng.Sessions()
	s0, s1 := ss[0], ss[1]

	// Session A: independent oracle strings.
	wantC2S_A := "HELLO FORENSICS\n"
	wantS2C_A := "AAAA-BBBB-" + "CCCC-DDDD"
	if got := string(s0.Payload(session.C2S)); got != wantC2S_A {
		t.Errorf("A c2s = %q, want %q", got, wantC2S_A)
	}
	if got := string(s0.Payload(session.S2C)); got != wantS2C_A {
		t.Errorf("A s2c = %q, want %q", got, wantS2C_A)
	}
	if len(s0.Gaps(session.C2S)) != 0 || len(s0.Gaps(session.S2C)) != 0 {
		t.Errorf("A should have no gaps: c2s=%v s2c=%v", s0.Gaps(session.C2S), s0.Gaps(session.S2C))
	}
	if !s0.Closed() || s0.CloseReason() != "fin-ack fin-ack" {
		t.Errorf("A close: closed=%v reason=%q", s0.Closed(), s0.CloseReason())
	}
	if s0.Incarnation != 0 || s1.Incarnation != 1 {
		t.Errorf("incarnations: %d,%d want 0,1", s0.Incarnation, s1.Incarnation)
	}

	// Session B: gap in the middle; oracle describes the recovered sides.
	if got := string(s1.Payload(session.C2S)); got != "" {
		t.Errorf("B c2s unexpectedly has data %q", got)
	}
	if got := string(s1.Payload(session.S2C)); got != "0123456789AB" {
		t.Errorf("B contiguous s2c = %q, want first chunk only", got)
	}
	gaps := s1.Gaps(session.S2C)
	if len(gaps) != 1 {
		t.Fatalf("B gaps: %+v", gaps)
	}
	if gaps[0].Start != 13 || gaps[0].End != 17 {
		t.Errorf("B gap range = rel %d..%d, want 13..17", gaps[0].Start, gaps[0].End)
	}
	// Spans preserve the post-gap fragment WITHOUT zero-filling the hole.
	spans := s1.Spans(session.S2C)
	if len(spans) != 3 || !spans[1].Gap {
		t.Fatalf("B spans structure wrong: %+v", spans)
	}
	if string(spans[2].Data) != "QRSTUVWX" {
		t.Errorf("B post-gap data = %q", string(spans[2].Data))
	}
	if !s1.Closed() || s1.CloseReason() != "rst" {
		t.Errorf("B close: %v %q", s1.Closed(), s1.CloseReason())
	}
}

// TestRetransmitAndOverwriteEvidence requires both evidence classes.
func TestRetransmitAndOverwriteEvidence(t *testing.T) {
	eng := analyze(t, "../testdata/capture.pcap", session.Budget{})
	ss := eng.Sessions()

	var ret, over int
	for _, c := range ss[0].Conflicts() {
		switch c.Kind {
		case session.KindRetransmit:
			ret++
		case session.KindOverwrite:
			over++
		}
	}
	if ret < 2 {
		t.Errorf("session A retransmit records = %d, want >= 2", ret)
	}
	if over != 0 {
		t.Errorf("session A must keep clean bytes, got overwrites=%d", over)
	}

	var gotOver bool
	for _, c := range ss[1].Conflicts() {
		if c.Kind == session.KindOverwrite {
			gotOver = true
			if c.Existing == c.New {
				t.Errorf("overwrite recorded with equal bytes at %d", c.OverlapAt)
			}
			if c.Resolution != "kept-first" {
				t.Errorf("resolution = %q", c.Resolution)
			}
		}
	}
	if !gotOver {
		t.Fatal("session B overwrite conflict not detected")
	}
	// First-seen bytes must survive: "89AB" at rel 9..12, not "ZZZZ".
	if got := string(ss[1].Spans(session.S2C)[0].Data[8:12]); got != "89AB" {
		t.Errorf("conflicting bytes resolved wrong: %q", got)
	}
}

// TestLateSegmentsStayWithClosedIncarnation ensures a late payload on a
// closed connection is never spliced into a later reused 4-tuple session.
func TestLateSegmentsStayWithClosedIncarnation(t *testing.T) {
	eng := analyze(t, "../testdata/capture.pcap", session.Budget{})
	ss := eng.Sessions()

	lateOnA, lateOnB := 0, 0
	for _, ev := range ss[0].Frames() {
		if ev.Disposition == "late-after-close" {
			lateOnA++
			if ev.PayloadLen == 0 {
				t.Error("expected late payload evidence on A")
			}
		}
	}
	for _, ev := range ss[1].Frames() {
		if ev.Disposition == "late-after-close" {
			lateOnB++
		}
	}
	if lateOnA != 1 || lateOnB != 1 {
		t.Fatalf("late counts A=%d B=%d, want 1/1", lateOnA, lateOnB)
	}
	if eng.Stats().LateSegments != 2 {
		t.Errorf("late counter = %d", eng.Stats().LateSegments)
	}
	// Crucially, session B payload contains no bytes from A's "LATE-LATE".
	for _, sp := range ss[1].Spans(session.S2C) {
		if !sp.Gap && string(sp.Data) == "LATE-LATE" {
			t.Fatal("late bytes leaked into reused session")
		}
	}
}

// TestGapIsNotZeroFilled verifies missing ranges are marked, never padded.
func TestGapIsNotZeroFilled(t *testing.T) {
	eng := analyze(t, "../testdata/capture.pcap", session.Budget{})
	s1 := eng.Sessions()[1]
	payload := s1.Payload(session.S2C)
	if len(payload) != 12 {
		t.Fatalf("contiguous payload len = %d, must not include gap", len(payload))
	}
	gapCount := 0
	for _, sp := range s1.Spans(session.S2C) {
		if sp.Gap {
			gapCount++
			if sp.Data != nil {
				t.Fatal("gap span must carry no bytes")
			}
		}
	}
	if gapCount != 1 {
		t.Fatalf("gap spans = %d", gapCount)
	}
}

// TestBudgetExhaustion exercises resource limit outcomes.
func TestBudgetExhaustion(t *testing.T) {
	eng := analyze(t, "../testdata/capture.pcap", session.Budget{MaxBytesPerDir: 13})
	st := eng.Stats()
	if !st.Exhausted || st.DroppedFrames == 0 {
		t.Fatalf("expected exhaustion, got %+v", st)
	}
	if len(eng.Drops()) == 0 {
		t.Fatal("engine drop ledger empty")
	}
	// Session B's 12-byte first chunk still fits exactly.
	s1 := eng.Sessions()[1]
	if got := len(s1.Payload(session.S2C)); got != 12 {
		t.Errorf("B delivered bytes = %d, want 12 that fit budget", got)
	}

	// Total-byte cap across all directions.
	eng2 := analyze(t, "../testdata/capture.pcap", session.Budget{MaxTotalBytes: 20})
	if eng2.Stats().DroppedFrames == 0 {
		t.Fatal("total-byte cap produced no drops")
	}

	// Session cap: only the first incarnation exists.
	eng3 := analyze(t, "../testdata/capture.pcap", session.Budget{MaxSessions: 1})
	if eng3.Stats().Sessions != 1 {
		t.Fatalf("sessions under cap = %d", 1)
	}
	if eng3.Stats().DroppedFrames == 0 {
		t.Fatal("session cap produced no drop event")
	}
}
