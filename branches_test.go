package netforensics

import (
	"bytes"
	"testing"
)

// ambiguousDelimiterFrames builds a human, bidirectional capture where one
// overlapping byte is observed as a newline by one packet and as data by
// another. The local ambiguity therefore crosses the application message
// boundary: one reading yields two messages, the other a single longer one.
func ambiguousDelimiterFrames(cISN, sISN uint32, resolved bool) []TCPFrameSpec {
	frames := append(handshakeFrames(cISN, sISN, 0),
		// Five bytes; only offset 1 differs (newline vs payload). Both packets
		// agree on offsets 2..4, including the delimiter before trailing Y.
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("A\nX\nY"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("AXX\nY"), 11),
	)
	if resolved {
		// Two later, independent observations confirm the newline at offset 1.
		frames = append(frames,
			goldenFrame(zeroTime(5), false, sISN+1, cISN+1, 0x18, []byte("A\nX\nY"), 12),
			goldenFrame(zeroTime(6), false, sISN+1, cISN+1, 0x18, []byte("A\nX\nY"), 13),
		)
	}
	return frames
}

func TestInterpretationBranchesDivergeOnMessageBoundary(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	result := ingestFrames(t, ambiguousDelimiterFrames(cISN, sISN, false), DefaultLimits()).Result(DirectionServerToClient)
	if len(result.UncertainRanges) != 1 || result.UncertainRanges[0] != (ByteRange{Offset: 1, Length: 1}) {
		t.Fatalf("uncertain ranges = %#v, want only contested delimiter byte", result.UncertainRanges)
	}

	delim := NewBranch("newline", "", nil, '\n', "analyst A treats overlap byte as newline")
	data := NewBranch("single", "", nil, '\n', "analyst B treats overlap byte as payload")
	contested := ByteRange{Offset: 1, Length: 1}
	if err := delim.Choose(DirectionServerToClient, contested, 3, "", "packet 3 observed 0x0A at offset 1"); err != nil {
		t.Fatal(err)
	}
	if err := data.Choose(DirectionServerToClient, contested, 4, "", "packet 4 observed 0x58 at offset 1"); err != nil {
		t.Fatal(err)
	}

	left := delim.View(result)
	right := data.View(result)
	if len(left.Messages) != 2 || !bytes.Equal(left.Messages[0].Data, []byte("A")) || !bytes.Equal(left.Messages[1].Data, []byte("X")) {
		t.Fatalf("newline branch messages = %#v, want A and X", left.Messages)
	}
	if len(right.Messages) != 1 || !bytes.Equal(right.Messages[0].Data, []byte("AXX")) {
		t.Fatalf("payload branch messages = %#v, want one AXX message", right.Messages)
	}
	if Reconverged(left, right) {
		t.Fatal("branches must not reconverge while the boundary byte is contested")
	}

	// Each message traces back to the raw fragment its branch adopted for the
	// contested byte, while shared A/X bytes stay consistent across forks.
	if !messageCites(left.Messages[0], 3) {
		t.Fatalf("newline branch must cite packet 3, got %#v", left.Messages[0].Sources)
	}
	if !messageCites(right.Messages[0], 4) {
		t.Fatalf("payload branch must cite packet 4, got %#v", right.Messages[0].Sources)
	}
	if len(delim.Choices) != 1 || len(data.Choices) != 1 {
		t.Fatal("a branch hypothesis must not mutate the sibling fork")
	}
}

func TestNewEvidenceReconvergesBranches(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	before := ingestFrames(t, ambiguousDelimiterFrames(cISN, sISN, false), DefaultLimits()).Result(DirectionServerToClient)
	after := ingestFrames(t, ambiguousDelimiterFrames(cISN, sISN, true), DefaultLimits()).Result(DirectionServerToClient)

	reassessment := CompareStreamResults(before, after)
	if len(reassessment.Strengthened) == 0 {
		t.Fatalf("reassessment = %#v, want the newline reading corroborated", reassessment)
	}

	delim := NewBranch("newline", "", nil, '\n', "")
	data := NewBranch("single", "", nil, '\n', "")
	contested := ByteRange{Offset: 1, Length: 1}
	_ = delim.Choose(DirectionServerToClient, contested, 3, "", "")
	_ = data.Choose(DirectionServerToClient, contested, 4, "", "")

	leftBefore := delim.View(before)
	rightBefore := data.View(before)
	if Reconverged(leftBefore, rightBefore) {
		t.Fatal("branches start diverged")
	}
	// New evidence never auto-flips a branch: each analyst explicitly adopts the
	// repeatedly corroborated reading, with a recorded reason.
	delimMoves := delim.Reconcile(after, "two later witnesses confirm 0x0A")
	dataMoves := data.Reconcile(after, "two later witnesses confirm 0x0A; abandon 0x58")
	leftAfter := delim.View(after)
	rightAfter := data.View(after)
	if len(dataMoves) != 1 || !dataMoves[0].Reconciled {
		t.Fatalf("payload branch moves = %#v, want it to adopt the majority reading", dataMoves)
	}
	if len(delimMoves) != 1 || delimMoves[0].Reconciled {
		t.Fatalf("newline branch moves = %#v, want it to stay on its reading", delimMoves)
	}
	if !Reconverged(leftAfter, rightAfter) {
		t.Fatalf("branches must reconverge on corroborating evidence: left=%q right=%q",
			blocksToBytes(leftAfter.Blocks), blocksToBytes(rightAfter.Blocks))
	}
	if len(leftAfter.Messages) != 2 || !bytes.Equal(leftAfter.Messages[1].Data, []byte("X")) {
		t.Fatalf("reconverged messages = %#v, want A and X", leftAfter.Messages)
	}

	// The single-message hypothesis is a real content/framing change, so its
	// previously exported conclusion must not be reused.
	changes := CompareMessages(rightBefore.Messages, rightAfter.Messages, reassessment)
	found := false
	for _, change := range changes {
		if (change.Kind == MessageContentChanged || change.Kind == MessageBoundaryChanged) && !change.Usable {
			found = true
		}
	}
	if !found {
		t.Fatalf("changes = %#v, want old single-message conclusion invalidated", changes)
	}
}

func TestMessageContentBoundaryAndConfidenceChanges(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	packets := mustReadFrames(t, ambiguousDelimiterFrames(cISN, sISN, true))
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, packets[:5]); err != nil {
		t.Fatal(err)
	}
	before := a.Sessions()[0].Result(DirectionServerToClient)
	if err := ingestAll(a, packets[5:]); err != nil {
		t.Fatal(err)
	}
	after := a.Sessions()[0].Result(DirectionServerToClient)
	reassessment := CompareStreamResults(before, after)

	// Newline branch: "A" keeps bytes and offsets and merely gains corroborating
	// witnesses -> confidence-only change.
	delim := NewBranch("newline", "", nil, '\n', "")
	_ = delim.Choose(DirectionServerToClient, ByteRange{Offset: 1, Length: 1}, 3, "", "")
	changes := CompareMessages(delim.View(before).Messages, delim.View(after).Messages, reassessment)
	kinds := map[MessageChangeKind]bool{}
	for _, change := range changes {
		kinds[change.Kind] = true
	}
	if !kinds[MessageConfidenceChanged] {
		t.Fatalf("changes = %#v, want a confidence-only update for A", changes)
	}

	// Payload branch keeps AX before the analyst reconciles; no auto-flip.
	data := NewBranch("single", "", nil, '\n', "")
	_ = data.Choose(DirectionServerToClient, ByteRange{Offset: 1, Length: 1}, 4, "", "")
	oldView := data.View(before)
	for _, change := range CompareMessages(oldView.Messages, data.View(after).Messages, reassessment) {
		if change.Kind == MessageContentChanged {
			t.Fatal("a branch must not be auto-invalidated before explicit reconciliation")
		}
	}
	moves := data.Reconcile(after, "repeated corroboration overrules the 0x58 hypothesis")
	if len(moves) != 1 || !moves[0].Reconciled || moves[0].ToPacket != 3 {
		t.Fatalf("reconcile moves = %#v, want adoption of packet 3", moves)
	}
	invalidation := CompareMessages(oldView.Messages, data.View(after).Messages, reassessment)
	found := false
	for _, change := range invalidation {
		if change.Kind == MessageContentChanged && !change.Usable {
			found = true
		}
	}
	if !found {
		t.Fatalf("invalidation = %#v, want the AX-based conclusion marked unusable", invalidation)
	}
}

func TestCaseFileSaveLoadContinuesEitherBranch(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	packets := mustReadFrames(t, ambiguousDelimiterFrames(cISN, sISN, true))
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, packets[:5]); err != nil {
		t.Fatal(err)
	}
	delim := NewBranch("newline", "", nil, '\n', "analyst A: delimiter reading")
	data := NewBranch("single", "", nil, '\n', "analyst B: payload reading")
	contested := ByteRange{Offset: 1, Length: 1}
	_ = delim.Choose(DirectionServerToClient, contested, 3, "", "0x0A candidate")
	_ = data.Choose(DirectionServerToClient, contested, 4, "", "0x58 candidate")

	saved, err := SaveCaseFile(a, []Branch{delim, data})
	if err != nil {
		t.Fatal(err)
	}
	restored, branches, err := LoadCaseFile(saved)
	if err != nil {
		t.Fatal(err)
	}
	if len(branches) != 2 || branches[0].Choices[0].Reason == "" {
		t.Fatalf("branches after reload = %#v, want choices and rationale preserved", branches)
	}

	// Continue either fork after reopen with the reconciling evidence.
	if err := ingestAll(restored, packets[5:]); err != nil {
		t.Fatal(err)
	}
	result := restored.Sessions()[0].Result(DirectionServerToClient)
	for i := range branches {
		moves := branches[i].Reconcile(result, "reopened case: accept repeated corroboration")
		if i == 1 && (len(moves) != 1 || !moves[0].Reconciled) {
			t.Fatalf("payload branch moves after reopen = %#v", moves)
		}
	}
	if !Reconverged(branches[0].View(result), branches[1].View(result)) {
		t.Fatal("saved branches must reconverge after continuing from the reopened case file")
	}
}

func messageCites(msg Message, packet int) bool {
	for _, source := range msg.Sources {
		if source.Packet == packet {
			return true
		}
	}
	return false
}
