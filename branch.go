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
	Message     Message `json:"message"`
	Reinterpret bool    `json:"reinterpret"`
	Reason      string  `json:"reason,omitempty"`
}

type BranchReassessment struct {
	BranchID string          `json:"branch_id"`
	Changes  Reassessment    `json:"changes"`
	Messages []MessageImpact `json:"messages"`
}

// Reassess compares the stream before and after late bytes or contradicting
// evidence, then maps the changed ranges onto the branch's previously
// exported messages: messages touching resolved, invalidated or newly
// uncertain ranges must be reinterpreted; messages only touched by
// strengthened confidence stay usable.
func (s *BranchSet) Reassess(branchID string, before, after StreamResult) (BranchReassessment, error) {
	interp, err := s.Interpret(before, branchID)
	if err != nil {
		return BranchReassessment{}, err
	}
	changes := CompareStreamResults(before, after)
	out := BranchReassessment{BranchID: branchID, Changes: changes}
	var reinterpret []ByteRange
	reinterpret = append(reinterpret, changeRanges(changes.Resolved)...)
	reinterpret = append(reinterpret, changeRanges(changes.Invalidated)...)
	reinterpret = append(reinterpret, changeRanges(changes.NewUncertain)...)
	strengthened := changeRanges(changes.Strengthened)
	for _, msg := range interp.Messages {
		impact := MessageImpact{Message: msg}
		if r, ok := firstIntersection(msg, reinterpret); ok {
			impact.Reinterpret = true
			impact.Reason = fmt.Sprintf("message overlaps changed range %d+%d; exported conclusion must be reinterpreted", r.Offset, r.Length)
		} else if r, ok := firstIntersection(msg, strengthened); ok {
			impact.Reason = fmt.Sprintf("confidence over range %d+%d strengthened; exported conclusion still usable", r.Offset, r.Length)
		} else {
			impact.Reason = "unaffected by new evidence; exported conclusion still usable"
		}
		out.Messages = append(out.Messages, impact)
	}
	return out, nil
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
