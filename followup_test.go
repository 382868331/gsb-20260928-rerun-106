package netforensics

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestPeerAckConfirmsGapWithoutFabricatingBytes(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("ABC"), 10),
		goldenFrame(zeroTime(4), true, cISN+10, sISN+1, 0x18, []byte("XYZ"), 11),
		goldenFrame(zeroTime(5), false, sISN+1, cISN+7, 0x10, nil, 12),
	)
	sess := ingestFrames(t, frames, DefaultLimits())
	result := sess.Result(DirectionClientToServer)

	if !bytes.Equal(result.Bytes, []byte("ABCXYZ")) {
		t.Fatalf("bytes = %q, want ABCXYZ with no invented gap bytes", result.Bytes)
	}
	if len(result.Gaps) != 1 || result.Gaps[0].Offset != 3 || result.Gaps[0].Length != 6 {
		t.Fatalf("gaps = %#v, want capture gap preserved", result.Gaps)
	}
	if !reflect.DeepEqual(result.PeerAckedRanges, []ByteRange{{Offset: 0, Length: 6}}) {
		t.Fatalf("peer acked ranges = %#v, want 0..6", result.PeerAckedRanges)
	}
	if !reflect.DeepEqual(result.PeerAckedMissing, []ByteRange{{Offset: 3, Length: 3}}) {
		t.Fatalf("peer acked missing = %#v, want the acked-but-uncaptured range 3..6", result.PeerAckedMissing)
	}
	var confirm *Evidence
	for i, ev := range sess.Evidence {
		if ev.Kind == EvidencePeerConfirm {
			confirm = &sess.Evidence[i]
		}
	}
	if confirm == nil {
		t.Fatal("missing peer_confirm evidence")
	}
	if confirm.Direction != DirectionClientToServer || confirm.Packet != 5 || confirm.Sequence != cISN+7 {
		t.Fatalf("peer_confirm evidence = %+v, want c2s confirmation from packet 5", *confirm)
	}
}

func TestResolveAnnotatesMessagesWithEvidenceAndUnresolved(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("A\n"), 10),
		goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("x\n"), 11),
	)
	result := ingestFrames(t, frames, DefaultLimits()).Result(DirectionServerToClient)

	first, err := result.Resolve(CandidateFirstObserved, '\n')
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Messages) != 1 || !bytes.Equal(first.Messages[0].Data, []byte("A")) {
		t.Fatalf("first rule messages = %#v, want A", first.Messages)
	}
	msg := first.Messages[0]
	if len(msg.Sources) != 2 {
		t.Fatalf("message sources = %#v, want both conflicting fragments as evidence", msg.Sources)
	}
	if !reflect.DeepEqual(msg.AssumedRanges, []ByteRange{{Offset: 0, Length: 1}}) {
		t.Fatalf("assumed ranges = %#v, want the resolved conflict byte", msg.AssumedRanges)
	}
	if len(first.UnresolvedRanges) != 0 {
		t.Fatalf("unresolved = %#v, want none", first.UnresolvedRanges)
	}

	last, err := result.Resolve(CandidateLastObserved, '\n')
	if err != nil {
		t.Fatal(err)
	}
	if len(last.Messages) != 1 || !bytes.Equal(last.Messages[0].Data, []byte("x")) {
		t.Fatalf("last rule messages = %#v, want x", last.Messages)
	}
	if _, err := result.Resolve("bogus", '\n'); err == nil {
		t.Fatal("expected error for unknown rule")
	}
}

func TestResolveReportsRemainingGap(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), true, cISN+1, sISN+1, 0x18, []byte("A\n"), 10),
		goldenFrame(zeroTime(4), true, cISN+6, sISN+1, 0x18, []byte("B\n"), 11),
	)
	result := ingestFrames(t, frames, DefaultLimits()).Result(DirectionClientToServer)
	resolved, err := result.Resolve(CandidateFirstObserved, '\n')
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved.Messages) != 2 {
		t.Fatalf("messages = %#v, want A and B on both sides of the gap", resolved.Messages)
	}
	if !reflect.DeepEqual(resolved.UnresolvedRanges, []ByteRange{{Offset: 2, Length: 3}}) {
		t.Fatalf("unresolved = %#v, want the capture gap", resolved.UnresolvedRanges)
	}
}

func TestSnapshotRestoreResumesAndKeepsFragments(t *testing.T) {
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
	if len(before.Gaps) != 1 {
		t.Fatalf("gaps = %#v, want one gap before resume", before.Gaps)
	}

	data, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	reopened := restored.Sessions()[0].Result(DirectionClientToServer)
	if !reflect.DeepEqual(reopened.Fragments, before.Fragments) {
		t.Fatalf("fragments changed across save/reopen: %#v vs %#v", reopened.Fragments, before.Fragments)
	}
	if !reflect.DeepEqual(reopened.Gaps, before.Gaps) || !bytes.Equal(reopened.Bytes, before.Bytes) {
		t.Fatalf("reopened result differs: %#v vs %#v", reopened, before)
	}

	fill := goldenFrame(zeroTime(5), true, cISN+3, sISN+1, 0x18, []byte("CD"), 12)
	if err := ingestAll(restored, mustReadFrames(t, []TCPFrameSpec{fill})); err != nil {
		t.Fatal(err)
	}
	filled := restored.Sessions()[0].Result(DirectionClientToServer)
	if !bytes.Equal(filled.Bytes, []byte("ABCDEF")) || len(filled.Gaps) != 0 {
		t.Fatalf("filled = %q gaps=%#v, want ABCDEF with no gaps", filled.Bytes, filled.Gaps)
	}
	for _, original := range before.Fragments {
		found := false
		for _, current := range filled.Fragments {
			if reflect.DeepEqual(original, current) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("original fragment %+v was rewritten by the late fill", original)
		}
	}

	changes := DiffStreamResults(reopened, filled)
	if len(changes) != 1 {
		t.Fatalf("changes = %#v, want exactly one strengthened range", changes)
	}
	change := changes[0]
	if change.Effect != EffectStrengthened || change.Before != StatusIncomplete || change.After != StatusDetermined {
		t.Fatalf("change = %+v, want incomplete -> determined strengthened", change)
	}
	if change.Range != (ByteRange{Offset: 2, Length: 2}) {
		t.Fatalf("changed range = %#v, want offset 2 length 2", change.Range)
	}
}

func TestSnapshotRestoreKeepsSessionGenerations(t *testing.T) {
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, GoldenFrames())); err != nil {
		t.Fatal(err)
	}
	data, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := ingestAll(restored, mustReadFrames(t, buildReusedSessionFrames())); err != nil {
		t.Fatal(err)
	}
	sessions := restored.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 distinct generations", len(sessions))
	}
	if sessions[0].ID == sessions[1].ID {
		t.Fatalf("reused address must keep distinct identities: %+v", sessions)
	}
	if got := sessions[1].Result(DirectionClientToServer).Bytes; !bytes.Equal(got, []byte("NEW")) {
		t.Fatalf("new generation bytes = %q, want NEW", got)
	}
	if got := sessions[0].Result(DirectionClientToServer).Bytes; !bytes.Equal(got, GoldenExpectedClient()) {
		t.Fatalf("old generation bytes = %q, want untouched golden payload", got)
	}
}

func TestDiffReportsInvalidatedConclusion(t *testing.T) {
	cISN := uint32(100)
	sISN := uint32(200)
	frames := append(handshakeFrames(cISN, sISN, 0),
		goldenFrame(zeroTime(3), false, sISN+1, cISN+1, 0x18, []byte("ABCDE"), 10),
	)
	a := NewAssembler(DefaultLimits())
	if err := ingestAll(a, mustReadFrames(t, frames)); err != nil {
		t.Fatal(err)
	}
	before := a.Sessions()[0].Result(DirectionServerToClient)

	conflict := goldenFrame(zeroTime(4), false, sISN+1, cISN+1, 0x18, []byte("AxCDE"), 11)
	if err := ingestAll(a, mustReadFrames(t, []TCPFrameSpec{conflict})); err != nil {
		t.Fatal(err)
	}
	after := a.Sessions()[0].Result(DirectionServerToClient)

	changes := DiffStreamResults(before, after)
	if len(changes) != 1 {
		t.Fatalf("changes = %#v, want one invalidated range", changes)
	}
	if changes[0].Effect != EffectInvalidated || changes[0].Before != StatusDetermined || changes[0].After != StatusConflict {
		t.Fatalf("change = %+v, want determined -> conflict invalidated", changes[0])
	}
	if changes[0].Range != (ByteRange{Offset: 1, Length: 1}) {
		t.Fatalf("changed range = %#v, want offset 1 length 1", changes[0].Range)
	}
}

func TestBudgetStopSurvivesSnapshotRestore(t *testing.T) {
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
	before := a.Sessions()[0].Result(DirectionClientToServer)

	data, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := RestoreSnapshot(data)
	if err != nil {
		t.Fatal(err)
	}
	reopened := restored.Sessions()[0].Result(DirectionClientToServer)
	if !reflect.DeepEqual(reopened.Fragments, before.Fragments) {
		t.Fatal("budget-stopped fragments changed across save/reopen")
	}
	if !reflect.DeepEqual(reopened.IncompleteRanges, before.IncompleteRanges) {
		t.Fatalf("incomplete ranges = %#v, want %#v", reopened.IncompleteRanges, before.IncompleteRanges)
	}
	if !bytes.Equal(reopened.Bytes, []byte("ABC")) {
		t.Fatalf("bytes = %q, want determined ABC only", reopened.Bytes)
	}
	if changes := DiffStreamResults(before, reopened); len(changes) != 0 {
		t.Fatalf("save/reopen must not change conclusions, got %#v", changes)
	}
}
