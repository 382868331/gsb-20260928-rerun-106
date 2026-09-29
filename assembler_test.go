package netforensics

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestGoldenPCAPBidirectionalReassembly(t *testing.T) {
	data, err := GoldenPCAP()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(BundledPCAP(), data) {
		t.Fatal("bundled testdata/known.pcap does not match generated known communication")
	}
	packets, err := ReadPCAP(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, packets); err != nil {
		t.Fatal(err)
	}
	sessions := a.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	sess := sessions[0]
	if sess.State != StateClosed {
		t.Fatalf("state = %s, want closed", sess.State)
	}
	c2s := sess.Result(DirectionClientToServer)
	s2c := sess.Result(DirectionServerToClient)
	if !bytes.Equal(c2s.Bytes, GoldenExpectedClient()) {
		t.Fatalf("client payload = %q, want %q", c2s.Bytes, GoldenExpectedClient())
	}
	if !bytes.Equal(s2c.Bytes, GoldenExpectedServer()) {
		t.Fatalf("server payload = %q, want %q", s2c.Bytes, GoldenExpectedServer())
	}
	if len(c2s.Gaps) != 0 || len(s2c.Gaps) != 0 {
		t.Fatalf("golden capture has gaps: c2s=%#v s2c=%#v", c2s.Gaps, s2c.Gaps)
	}
	wantKinds := map[EvidenceKind]bool{
		EvidenceRetransmission:  false,
		EvidenceOverlapConflict: false,
		EvidenceOutOfOrder:      false,
		EvidenceLateSegment:     false,
		EvidenceConnectionClose: false,
	}
	for _, ev := range sess.Evidence {
		if _, ok := wantKinds[ev.Kind]; ok {
			wantKinds[ev.Kind] = true
		}
	}
	for kind, found := range wantKinds {
		if !found {
			t.Errorf("missing evidence kind %s", kind)
		}
	}
}

func TestReusedAddressCreatesIsolatedSession(t *testing.T) {
	first := GoldenFrames()
	second := buildReusedSessionFrames()
	all := append(first, second...)
	data, err := WritePCAP(all)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := ReadPCAP(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, packets); err != nil {
		t.Fatal(err)
	}
	sessions := a.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2", len(sessions))
	}
	if sessions[0].ID == sessions[1].ID || sessions[0].Key != sessions[1].Key {
		t.Fatalf("reused address should produce distinct identities for same key: %+v", sessions)
	}
	newClient := sessions[1].Result(DirectionClientToServer)
	if !bytes.Equal(newClient.Bytes, []byte("NEW")) {
		t.Fatalf("new client payload = %q, want NEW", newClient.Bytes)
	}
	lateCount := 0
	for _, ev := range sessions[0].Evidence {
		if ev.Kind == EvidenceLateSegment {
			lateCount++
		}
	}
	if lateCount != 1 {
		t.Fatalf("late evidence = %d, want 1", lateCount)
	}
}

func TestMissingSegmentMarksGapWithoutZeroFill(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := []TCPFrameSpec{
		goldenFrame(zeroTime(0), true, cISN, sISN, 0x02, nil, 1),
		goldenFrame(zeroTime(1), false, sISN, cISN+1, 0x12, nil, 1),
		goldenFrame(zeroTime(2), true, cISN+1, sISN+1, 0x10, nil, 1),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("AAA"), 2),
		goldenFrame(zeroTime(4), true, cISN+7, sISN+1, 0x19, []byte("BBB"), 3),
	}
	sess := ingestFrames(t, frames, DefaultLimits())
	result := sess.Result(DirectionClientToServer)
	if len(result.Blocks) != 3 {
		t.Fatalf("blocks = %#v, want data/gap/data", result.Blocks)
	}
	if result.Blocks[0].Kind != BlockData || result.Blocks[1].Kind != BlockGap || result.Blocks[2].Kind != BlockData {
		t.Fatalf("block kinds = %#v, want data/gap/data", result.Blocks)
	}
	if result.Blocks[1].Length != 3 {
		t.Fatalf("gap length = %d, want 3", result.Blocks[1].Length)
	}
	if !bytes.Equal(result.Bytes, []byte("AAABBB")) {
		t.Fatalf("materialized bytes must not zero-fill gap, got %q", result.Bytes)
	}
	hasGapEvidence := false
	for _, ev := range sess.Evidence {
		hasGapEvidence = hasGapEvidence || ev.Kind == EvidenceGap
	}
	if !hasGapEvidence {
		t.Fatal("missing gap evidence")
	}
}

func TestBudgets(t *testing.T) {
	t.Run("packets", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxPackets = 4
		_, err := ingestGolden(limits)
		if !errors.Is(err, ErrPacketBudgetExhausted) {
			t.Fatalf("error = %v, want packet budget", err)
		}
	})
	t.Run("sessions", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxSessions = 1
		a := NewAssembler(limits)
		packets := mustReadFrames(t, GoldenFrames())
		if err := ingestAll(a, packets); err != nil {
			t.Fatal(err)
		}
		reused := buildReusedSessionFrames()
		err := ingestAll(a, mustReadFrames(t, reused))
		if !errors.Is(err, ErrSessionBudgetExhausted) {
			t.Fatalf("error = %v, want session budget", err)
		}
		if len(a.Sessions()) != 1 {
			t.Fatalf("sessions after budget exhaustion = %d, want 1", len(a.Sessions()))
		}
	})
	t.Run("accepted stream bytes", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxStreamBytes = 4
		_, err := ingestGolden(limits)
		if !errors.Is(err, ErrStreamBudgetExhausted) {
			t.Fatalf("error = %v, want stream byte budget", err)
		}
	})
	t.Run("pending bytes", func(t *testing.T) {
		limits := DefaultLimits()
		limits.MaxPendingBytes = 2
		cISN := uint32(100)
		sISN := uint32(200)
		frames := []TCPFrameSpec{
			goldenFrame(zeroTime(0), true, cISN, sISN, 0x02, nil, 1),
			goldenFrame(zeroTime(1), false, sISN, cISN+1, 0x12, nil, 1),
			goldenFrame(zeroTime(2), true, cISN+1, sISN+1, 0x10, nil, 1),
			goldenFrame(zeroTime(3), true, cISN+10, sISN+1, 0x18, []byte("abc"), 2),
		}
		_, err := ingestFramesWithError(frames, limits)
		if !errors.Is(err, ErrPendingBudgetExhausted) {
			t.Fatalf("error = %v, want pending byte budget", err)
		}
	})
}

func ingestGolden(limits Limits) (*Session, error) {
	return ingestFramesWithError(GoldenFrames(), limits)
}

func ingestFrames(t *testing.T, frames []TCPFrameSpec, limits Limits) *Session {
	t.Helper()
	sess, err := ingestFramesWithError(frames, limits)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func ingestFramesWithError(frames []TCPFrameSpec, limits Limits) (*Session, error) {
	a := NewAssembler(limits)
	packets := mustReadFrames(nil, frames)
	if err := ingestAll(a, packets); err != nil {
		return nil, err
	}
	sessions := a.Sessions()
	if len(sessions) != 1 {
		return nil, errors.New("expected exactly one session")
	}
	return sessions[0], nil
}

func mustReadFrames(t *testing.T, frames []TCPFrameSpec) []RawPacket {
	if t != nil {
		t.Helper()
	}
	data, err := WritePCAP(frames)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	packets, err := ReadPCAP(bytes.NewReader(data))
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
		panic(err)
	}
	return packets
}

func ingestAll(a *Assembler, packets []RawPacket) error {
	for _, p := range packets {
		if err := a.Ingest(p); err != nil {
			return err
		}
	}
	return nil
}

func buildReusedSessionFrames() []TCPFrameSpec {
	t := GoldenFrames()[0].Time.Add(time.Second)
	cISN := uint32(9000)
	sISN := uint32(8000)
	return []TCPFrameSpec{
		goldenFrame(t, true, cISN, sISN, 0x02, nil, 30),
		goldenFrame(t.Add(time.Millisecond), false, sISN, cISN+1, 0x12, nil, 30),
		goldenFrame(t.Add(2*time.Millisecond), true, cISN+1, sISN+1, 0x10, nil, 30),
		goldenFrame(t.Add(3*time.Millisecond), true, cISN+1, sISN+1, 0x18, []byte("NEW"), 31),
		goldenFrame(t.Add(4*time.Millisecond), true, cISN+5, sISN+1, 0x11, nil, 32),
		goldenFrame(t.Add(5*time.Millisecond), false, sISN, cISN+6, 0x11, nil, 32),
	}
}
