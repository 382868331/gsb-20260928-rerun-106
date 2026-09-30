package netforensics

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestOverlappingConflictExposesBothCandidateStreams(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("ABCDE"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("AxCDE"), 11),
	)
	result := ingestFrames(t, frames, DefaultLimits()).Result(DirectionServerToClient)

	var conflicts []Block
	for _, block := range result.Blocks {
		if block.Kind == BlockConflict {
			conflicts = append(conflicts, block)
		}
	}
	if len(conflicts) != 1 {
		t.Fatalf("blocks = %#v, want one conflict subrange", result.Blocks)
	}
	if !bytes.Equal(conflicts[0].Data, []byte("B")) {
		t.Fatalf("primary conflict bytes = %q, want first observed B", conflicts[0].Data)
	}
	if len(conflicts[0].Alternatives) != 2 {
		t.Fatalf("alternatives = %#v, want both distinct byte values", conflicts[0].Alternatives)
	}
	if len(conflicts[0].Sources) != 2 || conflicts[0].Sources[0].Packet != 3 || conflicts[0].Sources[1].Packet != 4 {
		t.Fatalf("sources = %#v, want both packet fragments", conflicts[0].Sources)
	}
	if len(result.UncertainRanges) != 1 || result.UncertainRanges[0] != (ByteRange{Offset: 1, Length: 1}) {
		t.Fatalf("uncertain ranges = %#v, want only conflicting byte", result.UncertainRanges)
	}
	first, ok := result.Candidate(CandidateFirstObserved)
	if !ok || !bytes.Equal(first.Bytes, []byte("ABCDE")) {
		t.Fatalf("first candidate = %#v, ok=%v", first, ok)
	}
	last, ok := result.Candidate(CandidateLastObserved)
	if !ok || !bytes.Equal(last.Bytes, []byte("AxCDE")) {
		t.Fatalf("last candidate = %#v, ok=%v", last, ok)
	}
}

func TestMessagesDoNotCrossGapOrConflict(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("A\nB"), 10),
		goldenFrame(zeroTime(4), true, cISN+5, sISN+1, 0x18, []byte("C\nD"), 11),
	)
	result := ingestFrames(t, frames, DefaultLimits()).Result(DirectionClientToServer)
	messages := result.Messages('\n')
	if len(messages) != 2 || !bytes.Equal(messages[0].Data, []byte("A")) || !bytes.Equal(messages[1].Data, []byte("C")) {
		t.Fatalf("messages = %#v, want A and C only", messages)
	}

	frames = append(handshakeFrames(cISN, sISN, 20),
		goldenFrame(zeroTime(23), false, sISN+1, cISN+1, 0x18, []byte("A\n"), 30),
		goldenFrame(zeroTime(24), false, sISN+1, cISN+1, 0x18, []byte("x\n"), 31),
	)
	result = ingestFrames(t, frames, DefaultLimits()).Result(DirectionServerToClient)
	if messages = result.Messages('\n'); len(messages) != 0 {
		t.Fatalf("messages over conflict = %#v, want none", messages)
	}
}

func TestBudgetExhaustionExportsDeterminedAndIncompleteRanges(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("ABC"), 10),
		goldenFrame(zeroTime(4), true, cISN+10, sISN+1, 0x18, []byte("XYZ"), 11),
	)
	limits := DefaultLimits()
	limits.MaxPendingBytes = 2
	a := NewAssembler(limits)
	if err := ingestAll(a, mustReadFrames(t, frames)); !errors.Is(err, ErrPendingBudgetExhausted) {
		t.Fatalf("error = %v, want pending budget", err)
	}
	result := a.Sessions()[0].Result(DirectionClientToServer)
	if !bytes.Equal(result.Bytes, []byte("ABC")) {
		t.Fatalf("determined bytes = %q, want ABC", result.Bytes)
	}
	if len(result.IncompleteRanges) != 1 || result.IncompleteRanges[0] != (ByteRange{Offset: 3, Length: 9}) {
		t.Fatalf("incomplete ranges = %#v, want unresolved range from offset 3 through 11", result.IncompleteRanges)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var reread StreamResult
	if err := json.Unmarshal(encoded, &reread); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reread.Bytes, result.Bytes) || len(reread.IncompleteRanges) != len(result.IncompleteRanges) || len(reread.Candidates) != len(result.Candidates) {
		t.Fatalf("reread result lost uncertainty: %#v", reread)
	}
}

func TestOutOfOrderPartialOverlapFillsGapAndKeepsProvenance(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("AB"), 10),
		goldenFrame(zeroTime(4), true, cISN+5, sISN+1, 0x18, []byte("EF"), 11),
		goldenFrame(zeroTime(5), true, cISN+3, sISN+1, 0x18, []byte("CDE"), 12),
	)
	result := ingestFrames(t, frames, DefaultLimits()).Result(DirectionClientToServer)
	if !bytes.Equal(result.Bytes, []byte("ABCDEF")) {
		t.Fatalf("bytes = %q, want ABCDEF", result.Bytes)
	}
	if len(result.Gaps) != 0 || len(result.UncertainRanges) != 0 {
		t.Fatalf("gaps=%#v uncertain=%#v", result.Gaps, result.UncertainRanges)
	}
	if len(result.Fragments) != 3 {
		t.Fatalf("fragments = %#v, want all raw payload observations", result.Fragments)
	}
}

func TestPendingSegmentPartiallyOverlapsAcceptedBoundary(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("AB"), 10),
		goldenFrame(zeroTime(4), true, cISN+5, sISN+1, 0x18, []byte("EF"), 11),
		goldenFrame(zeroTime(5), true, cISN+2, sISN+1, 0x18, []byte("BCDE"), 12),
	)
	result := ingestFrames(t, frames, DefaultLimits()).Result(DirectionClientToServer)
	if !bytes.Equal(result.Bytes, []byte("ABCDEF")) {
		t.Fatalf("bytes = %q, want ABCDEF", result.Bytes)
	}
	if len(result.Gaps) != 0 {
		t.Fatalf("gaps = %#v, want overlapping pending segment to fill hole", result.Gaps)
	}
}

func handshakeFrames(cISN, sISN uint32, ipid uint16) []TCPFrameSpec {
	return []TCPFrameSpec{
		goldenFrame(zeroTime(0), true, cISN, sISN, 0x02, nil, ipid),
		goldenFrame(zeroTime(1), false, sISN, cISN+1, 0x12, nil, ipid),
		goldenFrame(zeroTime(2), true, cISN+1, sISN+1, 0x10, nil, ipid),
	}
}
