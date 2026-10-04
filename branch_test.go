package netforensics

import (
	"bytes"
	"testing"
)

// Two branches adopt different fragments at one contested byte. Shared
// confirmed content stays identical; the sibling branch keeps the range
// unresolved instead of inheriting the assumption.
func TestBranchForkKeepsAssumptionsLocal(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("A\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("x\n"), 11),
	)
	sess := ingestFrames(t, frames, DefaultLimits())
	result := sess.Result(DirectionServerToClient)

	set := NewBranchSet(sess.ID, DirectionServerToClient)
	choice := BranchChoice{Range: ByteRange{Offset: 0, Length: 1}, Packet: 3, Rationale: "first observation arrived before retransmission"}
	branchID, err := set.Fork(BaseBranchID, choice)
	if err != nil {
		t.Fatal(err)
	}

	adopted, err := set.Interpret(result, branchID)
	if err != nil {
		t.Fatal(err)
	}
	if len(adopted.Messages) != 1 || !bytes.Equal(adopted.Messages[0].Data, []byte("A")) {
		t.Fatalf("adopting branch messages = %#v, want A", adopted.Messages)
	}
	if len(adopted.UnresolvedRanges) != 0 {
		t.Fatalf("adopting branch unresolved = %#v, want none", adopted.UnresolvedRanges)
	}

	base, err := set.Interpret(result, BaseBranchID)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Messages) != 0 {
		t.Fatalf("base branch messages = %#v, want none; sibling assumption must not leak", base.Messages)
	}
	if len(base.UnresolvedRanges) != 1 || base.UnresolvedRanges[0] != (ByteRange{Offset: 0, Length: 1}) {
		t.Fatalf("base branch unresolved = %#v, want contested range kept", base.UnresolvedRanges)
	}

	// Confirmed content outside the contested range is identical on both.
	if !bytes.Equal(base.Blocks[1].Data, adopted.Blocks[1].Data) || base.Blocks[1].Offset != adopted.Blocks[1].Offset {
		t.Fatalf("shared confirmed block diverged: base=%#v adopted=%#v", base.Blocks[1], adopted.Blocks[1])
	}
}

// Ambiguity spans a message boundary: one alternative carries the delimiter,
// the other does not, so the two branches disagree on segmentation, not only
// on content.
func TestBranchComparisonSeparatesContentBoundaryAndConfidence(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("200 OK\nBODY\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("200 OKXBODY\n"), 11),
	)
	sess := ingestFrames(t, frames, DefaultLimits())
	result := sess.Result(DirectionServerToClient)

	set := NewBranchSet(sess.ID, DirectionServerToClient)
	withDelim, err := set.Fork(BaseBranchID, BranchChoice{Range: ByteRange{Offset: 6, Length: 1}, Packet: 3, Rationale: "delimiter variant matches protocol grammar"})
	if err != nil {
		t.Fatal(err)
	}
	noDelim, err := set.Fork(BaseBranchID, BranchChoice{Range: ByteRange{Offset: 6, Length: 1}, Packet: 4, Rationale: "later observation may be a correction"})
	if err != nil {
		t.Fatal(err)
	}

	a, err := set.Interpret(result, withDelim)
	if err != nil {
		t.Fatal(err)
	}
	b, err := set.Interpret(result, noDelim)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Messages) != 2 || len(b.Messages) != 1 {
		t.Fatalf("messages a=%#v b=%#v, want 2 vs 1 across the boundary", a.Messages, b.Messages)
	}

	diffs := CompareInterpretations(a, b)
	if len(diffs) != 1 || diffs[0].Kind != DifferenceContent || diffs[0].Range != (ByteRange{Offset: 6, Length: 1}) {
		t.Fatalf("diffs = %#v, want one content change at the contested byte", diffs)
	}

	// Boundary-only difference: same adopted bytes, different segmentation.
	a2 := Interpretation{Rule: "branch:x", Messages: []Message{{Data: []byte("AB"), StartOffset: 0, EndOffset: 3}, {Data: []byte("C"), StartOffset: 3, EndOffset: 4}}}
	b2 := Interpretation{Rule: "branch:y", Messages: []Message{{Data: []byte("ABC"), StartOffset: 0, EndOffset: 4}}}
	boundary := CompareInterpretations(a2, b2)
	if len(boundary) != 1 || boundary[0].Kind != DifferenceBoundary {
		t.Fatalf("boundary diffs = %#v, want boundary_change only", boundary)
	}

	// Confidence-only difference: identical message, different sources.
	a3 := Interpretation{Rule: "branch:x", Messages: []Message{{Data: []byte("AB"), StartOffset: 0, EndOffset: 3, Sources: []Fragment{{Packet: 3}}}}}
	b3 := Interpretation{Rule: "branch:y", Messages: []Message{{Data: []byte("AB"), StartOffset: 0, EndOffset: 3, Sources: []Fragment{{Packet: 7}}}}}
	confidence := CompareInterpretations(a3, b3)
	if len(confidence) != 1 || confidence[0].Kind != DifferenceConfidence {
		t.Fatalf("confidence diffs = %#v, want confidence_change only", confidence)
	}
}

// Late bytes fill a gap: the message before the gap stays usable, the
// resolved range is reported. A contradicting overlap invalidates the
// previously exported message that covers it.
func TestBranchReassessMarksMessagesForReinterpretation(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("MSG1\n"), 10),
		goldenFrame(zeroTime(4), true, cISN+9, sISN+1, 0x18, []byte("MSG2\n"), 11),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	sess := a.Sessions()[0]
	before := sess.Result(DirectionClientToServer)
	set := NewBranchSet(sess.ID, DirectionClientToServer)

	late := []TCPFrameSpec{goldenFrame(zeroTime(5), true, cISN+6, sISN+1, 0x18, []byte("MID"), 12)}
	if err := ingestAll(a, mustReadFrames(t, late)); err != nil {
		t.Fatal(err)
	}
	after := a.Sessions()[0].Result(DirectionClientToServer)
	reassessed, err := set.Reassess(BaseBranchID, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(reassessed.Changes.Resolved) != 1 {
		t.Fatalf("resolved = %#v, want gap resolution", reassessed.Changes.Resolved)
	}
	if len(reassessed.Messages) != 2 {
		t.Fatalf("impacts = %#v, want MSG1 and MSG2", reassessed.Messages)
	}
	var msg1Gap, msg2Gap *MessageImpact
	for i := range reassessed.Messages {
		switch {
		case bytes.Equal(reassessed.Messages[i].Message.Data, []byte("MSG1")):
			msg1Gap = &reassessed.Messages[i]
		case bytes.Equal(reassessed.Messages[i].Message.Data, []byte("MSG2")):
			msg2Gap = &reassessed.Messages[i]
		}
	}
	// MSG1 is untouched by the late gap fill: content, boundary and the
	// adopted fragment are identical, so the old conclusion stays citable.
	if msg1Gap == nil || msg1Gap.Change != MessageUnchanged || msg1Gap.Usability != ConclusionCitable || msg1Gap.Reinterpret {
		t.Fatalf("MSG1 impact = %#v, want unchanged/citable", msg1Gap)
	}
	if len(msg1Gap.AdoptedFragments) != 1 || msg1Gap.AdoptedFragments[0].Packet != 3 {
		t.Fatalf("MSG1 adopted = %#v, want packet 3", msg1Gap.AdoptedFragments)
	}
	// The filled gap merges MSG2 into MIDMSG2: bytes at MSG2's offsets are
	// the same, but its message boundary moved, so the exported standalone
	// MSG2 conclusion must be reinterpreted.
	if msg2Gap == nil || msg2Gap.Change != MessageBoundaryChange || msg2Gap.Usability != ConclusionMustReinterpret || !msg2Gap.Reinterpret {
		t.Fatalf("MSG2 impact = %#v, want boundary_change/must_reinterpret", msg2Gap)
	}

	// Contradicting evidence invalidates the exported MSG1 conclusion.
	conflict := []TCPFrameSpec{goldenFrame(zeroTime(6), true, cISN+1, sISN+1, 0x18, []byte("MSX1\n"), 13)}
	if err := ingestAll(a, mustReadFrames(t, conflict)); err != nil {
		t.Fatal(err)
	}
	contradicted := a.Sessions()[0].Result(DirectionClientToServer)
	reassessed, err = set.Reassess(BaseBranchID, after, contradicted)
	if err != nil {
		t.Fatal(err)
	}
	if len(reassessed.Changes.Invalidated) != 1 {
		t.Fatalf("invalidated = %#v, want previously unique bytes invalidated", reassessed.Changes.Invalidated)
	}
	var msg1 *MessageImpact
	for i := range reassessed.Messages {
		if bytes.Equal(reassessed.Messages[i].Message.Data, []byte("MSG1")) {
			msg1 = &reassessed.Messages[i]
		}
	}
	if msg1 == nil || !msg1.Reinterpret {
		t.Fatalf("impacts = %#v, want MSG1 flagged for reinterpretation", reassessed.Messages)
	}
	for _, impact := range reassessed.Messages {
		if bytes.Equal(impact.Message.Data, []byte("MSG2")) && impact.Reinterpret {
			t.Fatalf("MSG2 must stay usable: %#v", impact)
		}
	}
}

// A saved branch set keeps its choice rationale; after reload, any branch
// can continue interpreting newly ingested evidence.
func TestBranchSnapshotResumeKeepsRationale(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("A\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("x\n"), 11),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	sess := a.Sessions()[0]
	set := NewBranchSet(sess.ID, DirectionServerToClient)
	branchID, err := set.Fork(BaseBranchID, BranchChoice{Range: ByteRange{Offset: 0, Length: 1}, Packet: 3, Rationale: "kept across save"})
	if err != nil {
		t.Fatal(err)
	}

	asmData, err := a.SaveSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	branchData, err := SaveBranchSet(set)
	if err != nil {
		t.Fatal(err)
	}
	restoredAsm, err := LoadAssemblerSnapshot(asmData)
	if err != nil {
		t.Fatal(err)
	}
	restoredSet, err := LoadBranchSet(branchData)
	if err != nil {
		t.Fatal(err)
	}
	branch, ok := restoredSet.Branch(branchID)
	if !ok || len(branch.Choices) != 1 || branch.Choices[0].Rationale != "kept across save" {
		t.Fatalf("restored branch = %#v, want rationale preserved", branch)
	}

	result := restoredAsm.Sessions()[0].Result(DirectionServerToClient)
	interp, err := restoredSet.Interpret(result, branchID)
	if err != nil {
		t.Fatal(err)
	}
	if len(interp.Messages) != 1 || !bytes.Equal(interp.Messages[0].Data, []byte("A")) {
		t.Fatalf("resumed branch messages = %#v, want A", interp.Messages)
	}
	if _, err := restoredSet.Interpret(result, BaseBranchID); err != nil {
		t.Fatalf("base branch must remain resumable: %v", err)
	}
}

// Bidirectional demo: c2s carries confirmed content shared by every branch;
// s2c has a local ambiguity spanning a message boundary. New evidence (a
// retransmission corroborating one alternative) lets both branches record
// the same choice and reconverge.
func TestBranchDemoBidirectionalAmbiguityAndReconvergence(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("GET /a\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+8, 0x18, []byte("200 OK\nBODY\n"), 11),
		goldenFrame(zeroTime(5), false, sISN+1, cISN+8, 0x18, []byte("200 OKXBODY\n"), 12),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	sess := a.Sessions()[0]
	s2c := sess.Result(DirectionServerToClient)

	set := NewBranchSet(sess.ID, DirectionServerToClient)
	optimist, err := set.Fork(BaseBranchID, BranchChoice{Range: ByteRange{Offset: 6, Length: 1}, Packet: 4, Rationale: "first response matches HTTP grammar"})
	if err != nil {
		t.Fatal(err)
	}
	skeptic, err := set.Fork(BaseBranchID, BranchChoice{Range: ByteRange{Offset: 6, Length: 1}, Packet: 5, Rationale: "later segment may be an evasion correction"})
	if err != nil {
		t.Fatal(err)
	}

	before1, err := set.Interpret(s2c, optimist)
	if err != nil {
		t.Fatal(err)
	}
	before2, err := set.Interpret(s2c, skeptic)
	if err != nil {
		t.Fatal(err)
	}
	if len(before1.Messages) != 2 || len(before2.Messages) != 1 {
		t.Fatalf("before convergence: %#v vs %#v, want 2 vs 1 messages", before1.Messages, before2.Messages)
	}
	if diffs := CompareInterpretations(before1, before2); len(diffs) == 0 {
		t.Fatal("branches must diverge before new evidence")
	}

	// New evidence: retransmission corroborates the first observation.
	corroboration := []TCPFrameSpec{goldenFrame(zeroTime(6), false, sISN+1, cISN+8, 0x18, []byte("200 OK\nBODY\n"), 13)}
	if err := ingestAll(a, mustReadFrames(t, corroboration)); err != nil {
		t.Fatal(err)
	}
	after := a.Sessions()[0].Result(DirectionServerToClient)
	corroPacket := -1
	for _, frag := range after.Fragments {
		if bytes.Equal(frag.Data, []byte("200 OK\nBODY\n")) && frag.Packet != 4 {
			corroPacket = frag.Packet
		}
	}
	if corroPacket < 0 {
		t.Fatal("corroborating retransmission not found among fragments")
	}
	choice := BranchChoice{Range: ByteRange{Offset: 6, Length: 1}, Packet: corroPacket, Rationale: "retransmission corroborates the delimiter variant"}
	for _, id := range []string{optimist, skeptic} {
		if err := set.AddChoice(id, choice); err != nil {
			t.Fatal(err)
		}
	}
	converged1, err := set.Interpret(after, optimist)
	if err != nil {
		t.Fatal(err)
	}
	converged2, err := set.Interpret(after, skeptic)
	if err != nil {
		t.Fatal(err)
	}
	if diffs := CompareInterpretations(converged1, converged2); len(diffs) != 0 {
		t.Fatalf("branches must reconverge after corroboration, diffs = %#v", diffs)
	}
	if len(converged1.Messages) != 2 {
		t.Fatalf("converged messages = %#v, want 200 OK and BODY", converged1.Messages)
	}

	// The c2s direction was never contested: identical on every branch.
	c2s := a.Sessions()[0].Result(DirectionClientToServer)
	if !bytes.Equal(c2s.Bytes, []byte("GET /a\n")) || len(c2s.UncertainRanges) != 0 {
		t.Fatalf("c2s = %q uncertain=%#v, want fully confirmed", c2s.Bytes, c2s.UncertainRanges)
	}
}
