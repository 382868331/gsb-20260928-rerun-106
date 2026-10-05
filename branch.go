package netforensics

import (
	"encoding/json"
	"fmt"
	"sort"
)

// BranchChoice records one analyst decision at a contested range: which
// observed fragment is adopted as evidence, and why. The rationale is kept
// so a saved and reloaded branch still explains its past choices.
type BranchChoice struct {
	Range     ByteRange `json:"range"`
	Packet    int       `json:"packet"`
	Rationale string    `json:"rationale"`
}

// Branch is one line of interpretation. Choices made on a sibling branch
// never leak into this one: an assumption stays local to its branch.
type Branch struct {
	ID      string         `json:"id"`
	Parent  string         `json:"parent,omitempty"`
	Choices []BranchChoice `json:"choices,omitempty"`
}

func (b Branch) choiceFor(block Block) (BranchChoice, bool) {
	end := block.Offset + int64(block.Length)
	for i := len(b.Choices) - 1; i >= 0; i-- {
		choice := b.Choices[i]
		choiceEnd := choice.Range.Offset + int64(choice.Range.Length)
		if choice.Range.Offset <= block.Offset && choiceEnd >= end {
			return choice, true
		}
	}
	return BranchChoice{}, false
}

// BranchSet groups the competing interpretations of one stream direction.
// Confirmed (uncontested) content is shared by construction: every branch
// derives from the same StreamResult and only contested ranges diverge.
type BranchSet struct {
	SessionID string    `json:"session_id"`
	Direction Direction `json:"direction"`
	Branches  []Branch  `json:"branches"`
	Next      int       `json:"next"`
}

const BaseBranchID = "base"

func NewBranchSet(sessionID string, direction Direction) *BranchSet {
	return &BranchSet{
		SessionID: sessionID,
		Direction: direction,
		Branches:  []Branch{{ID: BaseBranchID}},
		Next:      1,
	}
}

func (s *BranchSet) Branch(id string) (Branch, bool) {
	for _, branch := range s.Branches {
		if branch.ID == id {
			return branch, true
		}
	}
	return Branch{}, false
}

// Fork creates a sibling branch that inherits the parent's choices and adds
// one new choice at a contested range. The parent branch is unchanged.
func (s *BranchSet) Fork(parentID string, choice BranchChoice) (string, error) {
	parent, ok := s.Branch(parentID)
	if !ok {
		return "", fmt.Errorf("unknown branch %q", parentID)
	}
	id := fmt.Sprintf("b%d", s.Next)
	s.Next++
	choices := append(append([]BranchChoice(nil), parent.Choices...), choice)
	s.Branches = append(s.Branches, Branch{ID: id, Parent: parentID, Choices: choices})
	return id, nil
}

// AddChoice records a new evidence-backed choice on an existing branch, for
// example when late bytes let two previously divergent branches converge on
// the same fragment.
func (s *BranchSet) AddChoice(branchID string, choice BranchChoice) error {
	for i := range s.Branches {
		if s.Branches[i].ID == branchID {
			s.Branches[i].Choices = append(s.Branches[i].Choices, choice)
			return nil
		}
	}
	return fmt.Errorf("unknown branch %q", branchID)
}

// Interpret resolves the stream under one branch. Shared confirmed blocks
// are identical across branches; contested blocks are resolved only where
// this branch recorded a choice, and stay unresolved otherwise.
func (s *BranchSet) Interpret(result StreamResult, branchID string) (Interpretation, error) {
	branch, ok := s.Branch(branchID)
	if !ok {
		return Interpretation{}, fmt.Errorf("unknown branch %q", branchID)
	}
	var blocks []Block
	var adopted []ByteRange
	unresolved := gapsToRanges(result.Gaps)
	for _, block := range result.Blocks {
		switch block.Kind {
		case BlockData:
			adopted = appendRange(adopted, block.Offset, block.Length)
			blocks = append(blocks, block)
		case BlockConflict:
			var source Fragment
			usable := false
			if choice, found := branch.choiceFor(block); found {
				source, usable = fragmentForPacket(block.Sources, choice.Packet)
			}
			if !usable {
				unresolved = appendRange(unresolved, block.Offset, block.Length)
				blocks = append(blocks, block)
				continue
			}
			data := fragmentBytes(source, block.Offset, block.Length)
			blocks = append(blocks, Block{
				Kind:    BlockData,
				Offset:  block.Offset,
				Length:  block.Length,
				Data:    data,
				Sources: []Fragment{source},
			})
			adopted = appendRange(adopted, block.Offset, block.Length)
		default:
			blocks = append(blocks, block)
		}
	}
	return Interpretation{
		Direction:        result.Direction,
		Rule:             "branch:" + branch.ID,
		Blocks:           blocks,
		Messages:         messagesFromBlocks(blocks, '\n'),
		AdoptedRanges:    adopted,
		UnresolvedRanges: mergeRanges(unresolved),
	}, nil
}

func fragmentForPacket(sources []Fragment, packet int) (Fragment, bool) {
	for _, source := range sources {
		if source.Packet == packet {
			return source, true
		}
	}
	return Fragment{}, false
}

// DifferenceKind classifies how two branch interpretations diverge.
type DifferenceKind string

const (
	// DifferenceContent: both sides adopt bytes for the range and the bytes
	// really differ.
	DifferenceContent DifferenceKind = "content_change"
	// DifferenceBoundary: adopted bytes are identical but message
	// segmentation differs.
	DifferenceBoundary DifferenceKind = "boundary_change"
	// DifferenceConfidence: bytes and boundaries agree, but the supporting
	// evidence differs (one side assumed, the other did not, or different
	// source fragments back the same bytes).
	DifferenceConfidence DifferenceKind = "confidence_change"
)

type BranchDifference struct {
	Kind   DifferenceKind `json:"kind"`
	Range  ByteRange      `json:"range"`
	Detail string         `json:"detail,omitempty"`
}

// CompareInterpretations diffs two branch interpretations side by side and
// separates real content changes from message-boundary changes and from
// confidence-basis changes.
func CompareInterpretations(a, b Interpretation) []BranchDifference {
	var diffs []BranchDifference
	aBytes := adoptedByteMap(a)
	bBytes := adoptedByteMap(b)
	marks := make(map[int64]bool, len(aBytes)+len(bBytes))
	for off := range aBytes {
		marks[off] = true
	}
	for off := range bBytes {
		marks[off] = true
	}
	sorted := make([]int64, 0, len(marks))
	for off := range marks {
		sorted = append(sorted, off)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	flush := func(kind DifferenceKind, start, end int64, detail string) {
		if start >= 0 && end > start {
			diffs = append(diffs, BranchDifference{Kind: kind, Range: ByteRange{Offset: start, Length: int(end - start)}, Detail: detail})
		}
	}
	var contentStart, confidenceStart int64 = -1, -1
	for _, off := range sorted {
		aValue, aOK := aBytes[off]
		bValue, bOK := bBytes[off]
		switch {
		case aOK && bOK && aValue != bValue:
			flush(DifferenceConfidence, confidenceStart, off, "")
			confidenceStart = -1
			if contentStart < 0 {
				contentStart = off
			}
		case aOK != bOK:
			flush(DifferenceContent, contentStart, off, "")
			contentStart = -1
			if confidenceStart < 0 {
				confidenceStart = off
			}
		default:
			flush(DifferenceContent, contentStart, off, "")
			flush(DifferenceConfidence, confidenceStart, off, "")
			contentStart, confidenceStart = -1, -1
		}
	}
	end := int64(0)
	if len(sorted) > 0 {
		end = sorted[len(sorted)-1] + 1
	}
	flush(DifferenceContent, contentStart, end, "")
	flush(DifferenceConfidence, confidenceStart, end, "only one branch adopts bytes here; the assumption is not shared")
	hasContent := false
	for _, diff := range diffs {
		if diff.Kind == DifferenceContent {
			hasContent = true
		}
	}
	if !hasContent {
		diffs = append(diffs, boundaryDifferences(a, b)...)
		diffs = append(diffs, confidenceDifferences(a, b)...)
	}
	return diffs
}

func adoptedByteMap(interp Interpretation) map[int64]byte {
	out := make(map[int64]byte)
	for _, block := range interp.Blocks {
		if block.Kind != BlockData {
			continue
		}
		for i, value := range block.Data {
			out[block.Offset+int64(i)] = value
		}
	}
	return out
}

func boundaryDifferences(a, b Interpretation) []BranchDifference {
	aBounds := messageBoundaries(a)
	bBounds := messageBoundaries(b)
	var diffs []BranchDifference
	for _, off := range aBounds {
		if !containsInt64(bBounds, off) {
			diffs = append(diffs, BranchDifference{Kind: DifferenceBoundary, Range: ByteRange{Offset: off}, Detail: "message boundary exists only in " + a.Rule})
		}
	}
	for _, off := range bBounds {
		if !containsInt64(aBounds, off) {
			diffs = append(diffs, BranchDifference{Kind: DifferenceBoundary, Range: ByteRange{Offset: off}, Detail: "message boundary exists only in " + b.Rule})
		}
	}
	return diffs
}

func messageBoundaries(interp Interpretation) []int64 {
	var out []int64
	for _, msg := range interp.Messages {
		if !containsInt64(out, msg.StartOffset) {
			out = append(out, msg.StartOffset)
		}
		if !containsInt64(out, msg.EndOffset) {
			out = append(out, msg.EndOffset)
		}
	}
	return out
}

func containsInt64(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func confidenceDifferences(a, b Interpretation) []BranchDifference {
	var diffs []BranchDifference
	for _, aMsg := range a.Messages {
		for _, bMsg := range b.Messages {
			if aMsg.StartOffset != bMsg.StartOffset || aMsg.EndOffset != bMsg.EndOffset || !bytesEqual(aMsg.Data, bMsg.Data) {
				continue
			}
			if !sameFragments(aMsg.Sources, bMsg.Sources) {
				diffs = append(diffs, BranchDifference{
					Kind:   DifferenceConfidence,
					Range:  ByteRange{Offset: aMsg.StartOffset, Length: int(aMsg.EndOffset - aMsg.StartOffset)},
					Detail: "identical message backed by different source fragments",
				})
			}
		}
	}
	return diffs
}

func sameFragments(a, b []Fragment) bool {
	if len(a) != len(b) {
		return false
	}
	for _, frag := range a {
		if !fragmentListed(b, frag) {
			return false
		}
	}
	return true
}

// MessageImpact states whether a previously exported message-level
// conclusion remains usable after new evidence arrived.
type MessageImpact struct {
	Message          Message                   `json:"message"`
	CurrentMessage   *Message                  `json:"current_message,omitempty"`
	ChangeKinds      []MessageChangeKind       `json:"change_kinds,omitempty"`
	Status           MessageConclusionStatus   `json:"status"`
	Reinterpret      bool                      `json:"reinterpret"`
	AdoptedSupport   []MessageFragmentEvidence `json:"adopted_support,omitempty"`
	AddedSupport     []MessageFragmentEvidence `json:"added_support,omitempty"`
	StillConflicting []MessageFragmentEvidence `json:"still_conflicting,omitempty"`
	PreviousSources  []Fragment                `json:"previous_sources,omitempty"`
	Reason           string                    `json:"reason,omitempty"`
}

type BranchReassessment struct {
	BranchID string          `json:"branch_id"`
	Changes  Reassessment    `json:"changes"`
	Messages []MessageImpact `json:"messages"`
}

type MessageChangeKind string

const (
	MessageChangeContent    MessageChangeKind = "content_change"
	MessageChangeBoundary   MessageChangeKind = "boundary_change"
	MessageChangeConfidence MessageChangeKind = "confidence_change"
)

type MessageConclusionStatus string

const (
	MessageConclusionCitable             MessageConclusionStatus = "citable"
	MessageConclusionAnnotationRequired  MessageConclusionStatus = "annotation_required"
	MessageConclusionReinterpretRequired MessageConclusionStatus = "reinterpret_required"
)

// MessageFragmentEvidence describes how one raw fragment supports the bytes
// of an exported message. Supports and Conflicts are byte ranges relative to
// the stream, so a fragment crossing a newline can corroborate one part while
// contesting a boundary or another local byte range.
type MessageFragmentEvidence struct {
	Fragment  Fragment    `json:"fragment"`
	Adopted   bool        `json:"adopted,omitempty"`
	New       bool        `json:"new,omitempty"`
	Supports  []ByteRange `json:"supports,omitempty"`
	Conflicts []ByteRange `json:"conflicts,omitempty"`
}

// Reassess compares the stream before and after late bytes or contradicting
// evidence, then maps the changed ranges onto the branch's previously
// exported messages. Only real content or segmentation changes force
// reinterpretation; newly added supporting evidence and still-contested
// local ranges (including conflicts that already existed before) only
// require annotation, so a pre-existing conflict never demotes every
// later change into a redo.
func (s *BranchSet) Reassess(branchID string, before, after StreamResult) (BranchReassessment, error) {
	beforeInterp, err := s.Interpret(before, branchID)
	if err != nil {
		return BranchReassessment{}, err
	}
	afterInterp, err := s.Interpret(after, branchID)
	if err != nil {
		return BranchReassessment{}, err
	}
	changes := CompareStreamResults(before, after)
	out := BranchReassessment{BranchID: branchID, Changes: changes}
	beforeBytes := adoptedByteMap(beforeInterp)
	afterBytes := adoptedByteMap(afterInterp)
	beforePackets := fragmentPacketSet(before.Fragments)
	for _, oldMsg := range beforeInterp.Messages {
		current, hasCurrent := messageStartingAt(afterInterp.Messages, oldMsg.StartOffset)
		impact := MessageImpact{
			Message:         oldMsg,
			PreviousSources: fragmentCopies(oldMsg.Sources),
			Status:          MessageConclusionCitable,
			Reason:          "unaffected by new evidence; exported conclusion remains citable",
		}
		if hasCurrent {
			impact.CurrentMessage = &current
		}

		contentRanges, boundaryRanges := adoptedMessageChanges(oldMsg, current, hasCurrent, beforeBytes, afterBytes)
		if len(contentRanges) > 0 {
			impact.ChangeKinds = appendMessageChange(impact.ChangeKinds, MessageChangeContent)
		}
		if len(boundaryRanges) > 0 {
			impact.ChangeKinds = appendMessageChange(impact.ChangeKinds, MessageChangeBoundary)
		}

		impact.AdoptedSupport, impact.AddedSupport, impact.StillConflicting = messageFragmentEvidence(oldMsg, current, hasCurrent, after, afterBytes, beforePackets)
		hasAddedSupport := len(impact.AddedSupport) > 0
		hasNewConflict := false
		for _, contested := range impact.StillConflicting {
			if contested.New {
				hasNewConflict = true
			}
		}
		if hasAddedSupport || hasNewConflict {
			impact.ChangeKinds = appendMessageChange(impact.ChangeKinds, MessageChangeConfidence)
		}

		switch {
		case len(contentRanges) > 0 || len(boundaryRanges) > 0:
			impact.Status = MessageConclusionReinterpretRequired
			impact.Reinterpret = true
			impact.Reason = "adopted content or message segmentation changed; exported conclusion must be reinterpreted"
		case hasAddedSupport && hasNewConflict:
			impact.Status = MessageConclusionAnnotationRequired
			impact.Reason = "adopted content and boundary are unchanged; annotate the added supporting fragments and the newly contested local ranges"
		case hasAddedSupport:
			impact.Status = MessageConclusionAnnotationRequired
			impact.Reason = "message content and adopted boundary are unchanged; annotate the added supporting raw fragments"
		case hasNewConflict:
			impact.Status = MessageConclusionAnnotationRequired
			impact.Reason = "adopted content is unchanged but new conflicting observations contest local ranges; annotate instead of reinterpreting"
		}
		out.Messages = append(out.Messages, impact)
	}
	return out, nil
}

func messageStartingAt(messages []Message, offset int64) (Message, bool) {
	for _, msg := range messages {
		if msg.StartOffset == offset {
			return msg, true
		}
	}
	return Message{}, false
}

func adoptedMessageChanges(old Message, current Message, hasCurrent bool, beforeBytes, afterBytes map[int64]byte) ([]ByteRange, []ByteRange) {
	var content []ByteRange
	var boundary []ByteRange
	contentStart := int64(-1)
	for off := old.StartOffset; off < old.EndOffset; off++ {
		beforeValue, beforeOK := beforeBytes[off]
		afterValue, afterOK := afterBytes[off]
		diff := !beforeOK || !afterOK || beforeValue != afterValue
		if diff && contentStart < 0 {
			contentStart = off
		}
		if (!diff || off == old.EndOffset-1) && contentStart >= 0 {
			end := off + 1
			if !diff {
				end = off
			}
			content = append(content, ByteRange{Offset: contentStart, Length: int(end - contentStart)})
			contentStart = -1
		}
	}
	if !hasCurrent || current.EndOffset != old.EndOffset {
		boundary = append(boundary, ByteRange{Offset: old.EndOffset, Length: 1})
	}
	return mergeRanges(content), mergeRanges(boundary)
}

// messageFragmentEvidence splits the raw fragments overlapping one
// exported message into three lists: fragments adopted by the branch,
// newly observed fragments that only corroborate the adopted bytes, and
// fragments (old or new) that still contest a local byte range. A
// fragment crossing a newline can appear with both support and conflict
// ranges; the adopted flag alone never hides that distinction.
func messageFragmentEvidence(old Message, current Message, hasCurrent bool, after StreamResult, adopted map[int64]byte, beforePackets map[int]bool) (adoptedEvidence, addedEvidence, stillConflicting []MessageFragmentEvidence) {
	adoptedPackets := make(map[int]bool)
	if hasCurrent {
		for _, frag := range current.Sources {
			adoptedPackets[frag.Packet] = true
		}
	}
	for _, frag := range after.Fragments {
		fragmentEnd := frag.Offset + int64(len(frag.Data))
		if fragmentEnd <= old.StartOffset || frag.Offset >= old.EndOffset {
			continue
		}
		var supports []ByteRange
		var conflicts []ByteRange
		supportStart := int64(-1)
		conflictStart := int64(-1)
		start := maxInt64(frag.Offset, old.StartOffset)
		end := minInt64(fragmentEnd, old.EndOffset)
		for off := start; off < end; off++ {
			fragValue := frag.Data[off-frag.Offset]
			adoptedValue, ok := adopted[off]
			supportsByte := ok && adoptedValue == fragValue
			supportStart, conflictStart = accumulateEvidenceRange(off, end, supportsByte, supportStart, conflictStart, &supports, &conflicts)
		}
		if len(supports) == 0 && len(conflicts) == 0 {
			continue
		}
		evidence := MessageFragmentEvidence{
			Fragment:  frag,
			Adopted:   adoptedPackets[frag.Packet],
			New:       !beforePackets[frag.Packet],
			Supports:  supports,
			Conflicts: conflicts,
		}
		if evidence.Adopted {
			adoptedEvidence = append(adoptedEvidence, evidence)
		}
		if len(conflicts) > 0 {
			stillConflicting = append(stillConflicting, evidence)
		} else if evidence.New {
			addedEvidence = append(addedEvidence, evidence)
		}
	}
	return adoptedEvidence, addedEvidence, stillConflicting
}

func accumulateEvidenceRange(off, end int64, supportsByte bool, supportStart, conflictStart int64, supports, conflicts *[]ByteRange) (int64, int64) {
	if supportsByte {
		if conflictStart >= 0 {
			*conflicts = append(*conflicts, ByteRange{Offset: conflictStart, Length: int(off - conflictStart)})
			conflictStart = -1
		}
		if supportStart < 0 {
			supportStart = off
		}
		if off == end-1 {
			*supports = append(*supports, ByteRange{Offset: supportStart, Length: int(end - supportStart)})
			supportStart = -1
		}
		return supportStart, conflictStart
	}
	if supportStart >= 0 {
		*supports = append(*supports, ByteRange{Offset: supportStart, Length: int(off - supportStart)})
		supportStart = -1
	}
	if conflictStart < 0 {
		conflictStart = off
	}
	if off == end-1 {
		*conflicts = append(*conflicts, ByteRange{Offset: conflictStart, Length: int(end - conflictStart)})
		conflictStart = -1
	}
	return supportStart, conflictStart
}

func appendMessageChange(kinds []MessageChangeKind, kind MessageChangeKind) []MessageChangeKind {
	for _, existing := range kinds {
		if existing == kind {
			return kinds
		}
	}
	return append(kinds, kind)
}

func fragmentPacketSet(fragments []Fragment) map[int]bool {
	out := make(map[int]bool, len(fragments))
	for _, frag := range fragments {
		out[frag.Packet] = true
	}
	return out
}

func fragmentCopies(fragments []Fragment) []Fragment {
	if len(fragments) == 0 {
		return nil
	}
	return append([]Fragment(nil), fragments...)
}

func changeRanges(changes []ConclusionChange) []ByteRange {
	var out []ByteRange
	for _, change := range changes {
		out = append(out, change.Range)
	}
	return out
}

func firstIntersection(msg Message, ranges []ByteRange) (ByteRange, bool) {
	for _, r := range ranges {
		if msg.StartOffset < r.Offset+int64(r.Length) && r.Offset < msg.EndOffset {
			return r, true
		}
	}
	return ByteRange{}, false
}

// SaveBranchSet serializes the branch set, including every choice rationale,
// so any branch can be resumed after a save/reload cycle.
func SaveBranchSet(set *BranchSet) ([]byte, error) {
	return json.Marshal(set)
}

func LoadBranchSet(data []byte) (*BranchSet, error) {
	var set BranchSet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, err
	}
	return &set, nil
}

func SaveBranchReassessment(reassessment BranchReassessment) ([]byte, error) {
	return json.Marshal(reassessment)
}

func LoadBranchReassessment(data []byte) (BranchReassessment, error) {
	var reassessment BranchReassessment
	if err := json.Unmarshal(data, &reassessment); err != nil {
		return BranchReassessment{}, err
	}
	return reassessment, nil
}
