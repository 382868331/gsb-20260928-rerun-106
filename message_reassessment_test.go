package netforensics

import (
	"bytes"
	"testing"
)

// A local conflict straddles the \n message boundary: packet 3 sends
// "AB\nCD\n", packet 4 sends "Ax\nCD\n" (only byte 1 differs). Under the
// first-observed branch the two messages AB and CD are exported. A later
// identical retransmission of the first-observed stream adds supporting
// evidence, and a second copy of the contradicting stream arrives as well:
// the evidence count for the other side must not be treated as fact.
func TestMessageReassessmentCrossBoundaryConflictAndCorroboration(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("AB\nCD\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("Ax\nCD\n"), 11),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	sess := a.Sessions()[0]
	before := sess.Result(DirectionServerToClient)

	set := NewBranchSet(sess.ID, DirectionServerToClient)
	first, err := set.Fork(BaseBranchID, BranchChoice{Range: ByteRange{Offset: 1, Length: 1}, Packet: 3, Rationale: "first observed at the contested byte"})
	if err != nil {
		t.Fatal(err)
	}
	beforeInterp, err := set.Interpret(before, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(beforeInterp.Messages) != 2 || !bytes.Equal(beforeInterp.Messages[0].Data, []byte("AB")) || !bytes.Equal(beforeInterp.Messages[1].Data, []byte("CD")) {
		t.Fatalf("before messages = %#v, want AB and CD across the boundary", beforeInterp.Messages)
	}

	// One supporting retransmission of the adopted stream, plus one more
	// copy of the contradicting stream.
	late := []TCPFrameSpec{
		goldenFrame(zeroTime(5), false, sISN+1, cISN+1, 0x18, []byte("AB\nCD\n"), 12),
		goldenFrame(zeroTime(6), false, sISN+1, cISN+1, 0x18, []byte("Ax\nCD\n"), 13),
	}
	if err := ingestAll(a, mustReadFrames(t, late)); err != nil {
		t.Fatal(err)
	}
	after := a.Sessions()[0].Result(DirectionServerToClient)
	supportPacket := packetNotIn(t, after.Fragments, before.Fragments, []byte("AB\nCD\n"))
	conflictPacket := packetNotIn(t, after.Fragments, before.Fragments, []byte("Ax\nCD\n"))

	// The range stays contested: two observations per side must not resolve
	// it by majority, and no branch may silently adopt the other variant.
	if len(after.UncertainRanges) != 1 || after.UncertainRanges[0] != (ByteRange{Offset: 1, Length: 1}) {
		t.Fatalf("uncertain = %#v, want the contested byte to remain unresolved regardless of evidence count", after.UncertainRanges)
	}

	reassessed, err := set.Reassess(first, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(reassessed.Messages) != 2 {
		t.Fatalf("impacts = %#v, want AB and CD", reassessed.Messages)
	}
	for _, impact := range reassessed.Messages {
		if impact.Change != MessageConfidenceChange || impact.Usability != ConclusionNeedsAddendum || impact.Reinterpret {
			t.Fatalf("impact = %#v, want confidence_change/needs_addendum", impact)
		}
		switch string(impact.Message.Data) {
		case "AB":
			// AB covers the contested byte 1: packet 12 supports it, packet 13
			// contradicts it.
			if len(impact.AdoptedFragments) != 1 || impact.AdoptedFragments[0].Packet != 3 {
				t.Fatalf("AB adopted = %#v, want only packet 3", impact.AdoptedFragments)
			}
			if len(impact.AddedSupportFragments) != 1 || impact.AddedSupportFragments[0].Packet != supportPacket {
				t.Fatalf("AB support = %#v, want packet %d", impact.AddedSupportFragments, supportPacket)
			}
			if len(impact.ContradictingFragments) != 1 || impact.ContradictingFragments[0].Packet != conflictPacket {
				t.Fatalf("AB contradiction = %#v, want packet %d", impact.ContradictingFragments, conflictPacket)
			}
		case "CD":
			// CD straddles the other side of the boundary but contains no
			// contested byte: both original observations adopt identical
			// bytes there, and both new packets corroborate it.
			if len(impact.AdoptedFragments) != 2 {
				t.Fatalf("CD adopted = %#v, want packets 3 and 4", impact.AdoptedFragments)
			}
			packets := []int{impact.AddedSupportFragments[0].Packet, impact.AddedSupportFragments[1].Packet}
			if len(impact.AddedSupportFragments) != 2 || !containsInt(packets, supportPacket) || !containsInt(packets, conflictPacket) {
				t.Fatalf("CD support = %#v, want packets %d and %d", impact.AddedSupportFragments, supportPacket, conflictPacket)
			}
			if len(impact.ContradictingFragments) != 0 {
				t.Fatalf("CD contradiction = %#v, want none", impact.ContradictingFragments)
			}
		default:
			t.Fatalf("unexpected message %q", impact.Message.Data)
		}
	}

	// Content on the adopted branch is still AB/CD; the extra copies did not
	// move any boundary or flip any byte.
	afterInterp, err := set.Interpret(after, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(afterInterp.Messages) != 2 || !bytes.Equal(afterInterp.Messages[0].Data, []byte("AB")) || !bytes.Equal(afterInterp.Messages[1].Data, []byte("CD")) {
		t.Fatalf("after messages = %#v, want AB and CD unchanged", afterInterp.Messages)
	}

	// The base branch still refuses to cross the contested byte: AB is not
	// exported there. Only CD, which starts after the contested range, is
	// visible; the sibling variant was never promoted by the extra copies.
	baseInterp, err := set.Interpret(after, BaseBranchID)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseInterp.Messages) != 1 || !bytes.Equal(baseInterp.Messages[0].Data, []byte("CD")) {
		t.Fatalf("base messages = %#v, want only CD after the unresolved byte", baseInterp.Messages)
	}
}

// Reassessments, including adopted/new/contradicting fragments, survive a
// save and reload of the branch set: a reopened investigation still knows
// which old conclusions are citable, need an addendum, or must be
// reinterpreted.
func TestMessageReassessmentPersistsAcrossSaveReload(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("AB\nCD\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("Ax\nCD\n"), 11),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	sess := a.Sessions()[0]
	before := sess.Result(DirectionServerToClient)
	set := NewBranchSet(sess.ID, DirectionServerToClient)
	first, err := set.Fork(BaseBranchID, BranchChoice{Range: ByteRange{Offset: 1, Length: 1}, Packet: 3, Rationale: "first observed"})
	if err != nil {
		t.Fatal(err)
	}
	late := []TCPFrameSpec{goldenFrame(zeroTime(5), false, sISN+1, cISN+1, 0x18, []byte("AB\nCD\n"), 12)}
	if err := ingestAll(a, mustReadFrames(t, late)); err != nil {
		t.Fatal(err)
	}
	after := a.Sessions()[0].Result(DirectionServerToClient)
	supportPacket := packetNotIn(t, after.Fragments, before.Fragments, []byte("AB\nCD\n"))
	if _, err := set.Reassess(first, before, after); err != nil {
		t.Fatal(err)
	}

	data, err := SaveBranchSet(set)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := LoadBranchSet(data)
	if err != nil {
		t.Fatal(err)
	}
	saved, ok := restored.Reassessments[first]
	if !ok {
		t.Fatalf("reassessments = %#v, want entry for %q", restored.Reassessments, first)
	}
	var ab *MessageImpact
	for i := range saved.Messages {
		if bytes.Equal(saved.Messages[i].Message.Data, []byte("AB")) {
			ab = &saved.Messages[i]
		}
	}
	if ab == nil {
		t.Fatalf("messages = %#v, want AB", saved.Messages)
	}
	if ab.Change != MessageConfidenceChange || ab.Usability != ConclusionNeedsAddendum {
		t.Fatalf("AB impact = %#v, want confidence change needing addendum", ab)
	}
	if len(ab.AdoptedFragments) != 1 || ab.AdoptedFragments[0].Packet != 3 {
		t.Fatalf("adopted = %#v, want packet 3 retained", ab.AdoptedFragments)
	}
	if len(ab.AddedSupportFragments) != 1 || ab.AddedSupportFragments[0].Packet != supportPacket {
		t.Fatalf("support = %#v, want packet %d retained", ab.AddedSupportFragments, supportPacket)
	}
}

func packetNotIn(t *testing.T, after, before []Fragment, payload []byte) int {
	t.Helper()
	type fragID struct {
		packet int
		offset int64
		size   int
	}
	old := make(map[fragID]bool, len(before))
	for _, frag := range before {
		old[fragID{frag.Packet, frag.Offset, len(frag.Data)}] = true
	}
	for _, frag := range after {
		if !old[fragID{frag.Packet, frag.Offset, len(frag.Data)}] && bytes.Equal(frag.Data, payload) {
			return frag.Packet
		}
	}
	t.Fatalf("new fragment with payload %q not found in %#v", payload, after)
	return -1
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
