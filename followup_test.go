package netforensics

import (
	"bytes"
	"testing"
)

func TestOppositeDirectionACKStrengthensGap(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("AAA"), 10),
		goldenFrame(zeroTime(4), true, cISN+7, sISN+1, 0x18, []byte("BBB"), 11),
		goldenFrame(zeroTime(5), false, sISN+1, cISN+10, 0x10, nil, 12),
	)
	sess := ingestFrames(t, frames, DefaultLimits())
	result := sess.Result(DirectionClientToServer)
	if len(result.Gaps) != 1 || !result.Gaps[0].Acknowledged || result.Gaps[0].ConfirmingPacket != 5 {
		t.Fatalf("gaps = %#v, want opposite-direction ACK confirmation", result.Gaps)
	}
	hasConfirmation := false
	for _, ev := range sess.Evidence {
		if ev.Kind == EvidenceAckConfirmation && ev.Direction == DirectionClientToServer && ev.AcknowledgingDirection == DirectionServerToClient {
			hasConfirmation = true
		}
	}
	if !hasConfirmation {
		t.Fatal("missing ACK confirmation evidence")
	}
}

func TestInterpretationLabelsAdoptedEvidenceAndUnresolvedRange(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("A\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("x\n"), 11),
	)
	result := ingestFrames(t, frames, DefaultLimits()).Result(DirectionServerToClient)
	interp, err := result.Interpret(CandidateFirstObserved)
	if err != nil {
		t.Fatal(err)
	}
	if len(interp.Messages) != 1 || !bytes.Equal(interp.Messages[0].Data, []byte("A")) {
		t.Fatalf("messages = %#v, want A", interp.Messages)
	}
	if len(interp.Messages[0].Sources) != 1 || interp.Messages[0].Sources[0].Packet != 3 {
		t.Fatalf("message sources = %#v, want adopted packet only", interp.Messages[0].Sources)
	}
	if len(interp.UnresolvedRanges) != 1 || interp.UnresolvedRanges[0] != (ByteRange{Offset: 0, Length: 1}) {
		t.Fatalf("unresolved ranges = %#v, want contested range", interp.UnresolvedRanges)
	}
}

func TestCompareResultsMarksGapResolutionAndACKStrengthening(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("AB"), 10),
		goldenFrame(zeroTime(4), true, cISN+5, sISN+1, 0x18, []byte("EF"), 11),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	before := a.Sessions()[0].Result(DirectionClientToServer)
	middle := []TCPFrameSpec{goldenFrame(zeroTime(5), true, cISN+3, sISN+1, 0x18, []byte("CDE"), 12)}
	if err := ingestAll(a, mustReadFrames(t, middle)); err != nil {
		t.Fatal(err)
	}
	afterFill := a.Sessions()[0].Result(DirectionClientToServer)
	filled := CompareStreamResults(before, afterFill)
	if len(filled.Resolved) != 1 || filled.Resolved[0].Range != (ByteRange{Offset: 2, Length: 2}) {
		t.Fatalf("resolved = %#v", filled.Resolved)
	}

	ackFrames := append(append([]TCPFrameSpec{}, frames...), goldenFrame(zeroTime(6), false, sISN+1, cISN+7, 0x10, nil, 13))
	ackAssembler := NewAssembler(DefaultLimits())
	if err := ingestAll(ackAssembler, mustReadFrames(t, ackFrames)); err != nil {
		t.Fatal(err)
	}
	afterACK := ackAssembler.Sessions()[0].Result(DirectionClientToServer)
	compared := CompareStreamResults(before, afterACK)
	if len(compared.Strengthened) != 1 || compared.Strengthened[0].Range != (ByteRange{Offset: 2, Length: 2}) {
		t.Fatalf("strengthened = %#v", compared.Strengthened)
	}
}

func TestSnapshotResumePreservesFragmentsAndFillsGap(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("AB"), 10),
		goldenFrame(zeroTime(4), true, cISN+5, sISN+1, 0x18, []byte("EF"), 11),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	data, err := a.SaveSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LoadAssemblerSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	middle := []TCPFrameSpec{goldenFrame(zeroTime(5), true, cISN+3, sISN+1, 0x18, []byte("CDE"), 12)}
	if err := ingestAll(restored, mustReadFrames(t, middle)); err != nil {
		t.Fatal(err)
	}
	result := restored.Sessions()[0].Result(DirectionClientToServer)
	if !bytes.Equal(result.Bytes, []byte("ABCDEF")) || len(result.Gaps) != 0 {
		t.Fatalf("after restore bytes=%q gaps=%#v", result.Bytes, result.Gaps)
	}
	if len(result.Fragments) != 3 {
		t.Fatalf("fragments = %#v, want original and late fragments preserved", result.Fragments)
	}
}
