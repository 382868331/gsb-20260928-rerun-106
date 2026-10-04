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
	// Reassessments keeps the latest message-level reassessment per branch,
	// including the adopted and newly added raw fragments, so the basis for
	// every exported conclusion survives a save/reload cycle.
	Reassessments map[string]BranchReassessment `json:"reassessments,omitempty"`
}

const BaseBranchID = "base"

func NewBranchSet(sessionID string, direction Direction) *BranchSet {
	return &BranchSet{
		SessionID:     sessionID,
		Direction:     direction,
		Branches:      []Branch{{ID: BaseBranchID}},
		Next:          1,
		Reassessments: make(map[string]BranchReassessment),
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

// MessageChangeKind classifies what happened to one exported message after
// new raw packets were ingested.
type MessageChangeKind string

const (
	// MessageUnchanged: identical content, boundaries and supporting
	// fragments; the old exported conclusion is still directly citable.
	MessageUnchanged MessageChangeKind = "unchanged"
	// MessageContentChange: at least one adopted byte differs, or bytes that
	// backed the message became unresolved; the old conclusion must be
	// reinterpreted.
	MessageContentChange MessageChangeKind = "content_change"
	// MessageBoundaryChange: adopted bytes are the same but message
	// segmentation moved (split, merge or shift); the old conclusion must be
	// reinterpreted against the new boundaries.
	MessageBoundaryChange MessageChangeKind = "boundary_change"
	// MessageConfidenceChange: content and boundaries are unchanged but the
	// evidence set changed (additional corroboration, an ACK confirmation, or
	// a contradicting sibling-branch fragment); the old conclusion stays
	// citable but must carry an addendum noting the new basis.
	MessageConfidenceChange MessageChangeKind = "confidence_change"
)

// ConclusionUsability states how a previously exported conclusion relates
// to the reassessed evidence.
type ConclusionUsability string

const (
	// ConclusionCitable: the old conclusion can be quoted unchanged.
	ConclusionCitable ConclusionUsability = "citable"
	// ConclusionNeedsAddendum: the conclusion text still holds, but the
	// citation must note the changed confidence basis.
	ConclusionNeedsAddendum ConclusionUsability = "needs_addendum"
	// ConclusionMustReinterpret: content or boundaries moved; the old
	// conclusion text can no longer stand on its own.
	ConclusionMustReinterpret ConclusionUsability = "must_reinterpret"
)

// MessageImpact is the message-level result of a reassessment. It separates
// content, boundary and confidence changes and records, per conclusion, both
// the actually adopted raw fragments and the fragments newly added by the
// last evidence batch. A mere increase of evidence count is never recorded
// as another branch's fact: a contradicting fragment is listed as
// contradicting evidence and never adopted.
type MessageImpact struct {
	Message   Message             `json:"message"`
	Current   *Message            `json:"current,omitempty"`
	Change    MessageChangeKind   `json:"change"`
	Usability ConclusionUsability `json:"usability"`
	// AdoptedFragments are the raw fragments that actually support the
	// conclusion under this branch (before and after the reassessment).
	AdoptedFragments []Fragment `json:"adopted_fragments,omitempty"`
	// AddedSupportFragments are raw fragments newly observed that corroborate
	// the adopted bytes (identical content, including retransmissions).
	AddedSupportFragments []Fragment `json:"added_support_fragments,omitempty"`
	// ContradictingFragments are newly observed fragments carrying different
	// bytes for part of the message. They are evidence against the conclusion,
	// never silently adopted, regardless of how many arrive.
	ContradictingFragments []Fragment `json:"contradicting_fragments,omitempty"`
	// ChangedRanges are the underlying byte ranges driving the impact.
	ChangedRanges []ByteRange `json:"changed_ranges,omitempty"`
	Reinterpret   bool        `json:"reinterpret"`
	Reason        string      `json:"reason,omitempty"`
}

type BranchReassessment struct {
	BranchID     string          `json:"branch_id"`
	StreamBefore StreamResultRef `json:"stream_before_ref"`
	StreamAfter  StreamResultRef `json:"stream_after_ref"`
	Changes      Reassessment    `json:"changes"`
	Messages     []MessageImpact `json:"messages"`
	NewMessages  []Message       `json:"new_messages,omitempty"`
}

// StreamResultRef identifies the two evidence states a reassessment spans.
type StreamResultRef struct {
	Fragments []Fragment `json:"fragments,omitempty"`
}

// Reassess compares the stream before and after late raw packets (gap fills,
// retransmissions, sibling-branch corroboration or contradicting overlaps)
// and classifies each previously exported message as a content change, a
// boundary change, a confidence-only change, or unchanged.
//
// Content and boundary changes invalidate the old exported conclusion text
// (must_reinterpret). A confidence change keeps the conclusion citable but
// requires an addendum (needs_addendum). Every impact lists the fragments it
// actually adopts plus the newly added supporting fragments, split from new
// contradicting fragments. The result is stored on the BranchSet, so after a
// save/reload cycle the evidence basis is still available.
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
	newFragments := newObservedFragments(before.Fragments, after.Fragments)
	out := BranchReassessment{
		BranchID:     branchID,
		StreamBefore: StreamResultRef{Fragments: append([]Fragment(nil), before.Fragments...)},
		StreamAfter:  StreamResultRef{Fragments: append([]Fragment(nil), after.Fragments...)},
		Changes:      changes,
	}

	contentRanges := append(append(append([]ByteRange{}, changeRanges(changes.Invalidated)...), changeRanges(changes.NewUncertain)...), changeRanges(changes.Resolved)...)
	confidenceRanges := changeRanges(changes.Strengthened)

	matchedAfter := make(map[int]bool)
	for _, oldMsg := range beforeInterp.Messages {
		impact := MessageImpact{
			Message:          oldMsg,
			AdoptedFragments: matchingFragments(oldMsg, before.Fragments, beforeInterp.Blocks),
		}
		supporting, contradicting := classifyNewFragments(oldMsg, newFragments, afterInterp.Blocks)
		impact.AddedSupportFragments = supporting
		impact.ContradictingFragments = contradicting

		newMsg, matchIdx := matchMessage(oldMsg, afterInterp.Messages)
		if newMsg != nil {
			matchedAfter[matchIdx] = true
			impact.Current = newMsg
		}

		overlapsContent := intersectsAny(oldMsg, contentRanges)
		overlapsConfidence := intersectsAny(oldMsg, confidenceRanges) || len(supporting) > 0 || len(contradicting) > 0

		switch {
		case newMsg == nil:
			// No message with the same start: the segmentation moved or the
			// bytes became unresolved. Gap fills merge messages (boundary
			// change); invalidation or fresh uncertainty changes content.
			if len(contradicting) > 0 || intersectsAny(oldMsg, append(changeRanges(changes.Invalidated), changeRanges(changes.NewUncertain)...)) {
				impact.Change = MessageContentChange
				impact.Usability = ConclusionMustReinterpret
				impact.Reinterpret = true
				impact.ChangedRanges = append(impact.ChangedRanges, intersectingRanges(oldMsg, append(changeRanges(changes.Invalidated), changeRanges(changes.NewUncertain)...))...)
				impact.Reason = "adopted bytes changed or became unresolved across the message; exported conclusion must be reinterpreted"
			} else {
				impact.Change = MessageBoundaryChange
				impact.Usability = ConclusionMustReinterpret
				impact.Reinterpret = true
				impact.ChangedRanges = append(impact.ChangedRanges, intersectingRanges(oldMsg, contentRanges)...)
				impact.Reason = "message boundaries moved after new bytes arrived; exported conclusion must be reinterpreted against new segmentation"
			}
		case !bytesEqual(newMsg.Data, oldMsg.Data):
			impact.Change = MessageContentChange
			impact.Usability = ConclusionMustReinterpret
			impact.Reinterpret = true
			impact.ChangedRanges = append(impact.ChangedRanges, intersectingRanges(oldMsg, contentRanges)...)
			impact.Reason = "message content differs after reassessment; exported conclusion must be reinterpreted"
		case newMsg.EndOffset != oldMsg.EndOffset:
			impact.Change = MessageBoundaryChange
			impact.Usability = ConclusionMustReinterpret
			impact.Reinterpret = true
			impact.ChangedRanges = append(impact.ChangedRanges, intersectingRanges(oldMsg, contentRanges)...)
			impact.Reason = "message content is unchanged but boundaries moved; exported conclusion must be reinterpreted"
		case overlapsContent:
			// Same bytes and boundaries, yet an underlying range was
			// resolved (e.g. the gap sat inside the message but another
			// observation later covered it): still a confidence matter only
			// when bytes agree; corroboration is cited, not reinterpreted.
			impact.Change = MessageConfidenceChange
			impact.Usability = ConclusionNeedsAddendum
			impact.ChangedRanges = append(impact.ChangedRanges, intersectingRanges(oldMsg, contentRanges)...)
			impact.Reason = "content and boundaries unchanged; newly resolved range corroborates the message, addendum required"
		case overlapsConfidence:
			impact.Change = MessageConfidenceChange
			impact.Usability = ConclusionNeedsAddendum
			impact.ChangedRanges = append(impact.ChangedRanges, intersectingRanges(oldMsg, confidenceRanges)...)
			impact.Reason = "content and boundaries unchanged but the evidence set changed; conclusion stays citable with an addendum"
		default:
			impact.Change = MessageUnchanged
			impact.Usability = ConclusionCitable
			impact.Reason = "unaffected by new evidence; exported conclusion still citable"
		}
		out.Messages = append(out.Messages, impact)
	}
	for idx, msg := range afterInterp.Messages {
		if !matchedAfter[idx] {
			out.NewMessages = append(out.NewMessages, msg)
		}
	}
	if s.Reassessments == nil {
		s.Reassessments = make(map[string]BranchReassessment)
	}
	s.Reassessments[branchID] = out
	return out, nil
}

func changeRanges(changes []ConclusionChange) []ByteRange {
	var out []ByteRange
	for _, change := range changes {
		out = append(out, change.Range)
	}
	return out
}

// newObservedFragments returns fragments present after reassessment but not
// in the earlier evidence set. Packet indices restart at zero per pcap read,
// so identity is the triple (packet index, stream offset, payload); an exact
// duplicate is never counted twice.
func newObservedFragments(before, after []Fragment) []Fragment {
	type fragID struct {
		packet int
		offset int64
		data   string
	}
	known := make(map[fragID]bool, len(before))
	for _, frag := range before {
		known[fragID{frag.Packet, frag.Offset, string(frag.Data)}] = true
	}
	var out []Fragment
	for _, frag := range after {
		key := fragID{frag.Packet, frag.Offset, string(frag.Data)}
		if !known[key] {
			out = append(out, frag)
		}
	}
	return out
}

// matchMessage pairs an old message with the reassessed message sharing its
// start offset (messages are delimiter-terminated from a fixed start). It
// returns nil when segmentation moved away from that start.
func matchMessage(old Message, current []Message) (*Message, int) {
	for i := range current {
		if current[i].StartOffset == old.StartOffset {
			return &current[i], i
		}
	}
	return nil, -1
}

// classifyNewFragments separates newly observed fragments overlapping a
// message into supporting (identical to the bytes this branch adopts) and
// contradicting (different bytes). A supporting fragment increases
// confidence; a contradicting one is evidence for a sibling branch, never
// adopted here no matter how many copies arrive.
func classifyNewFragments(msg Message, newFragments []Fragment, blocks []Block) (supporting, contradicting []Fragment) {
	for _, frag := range newFragments {
		overlapStart := maxInt64(frag.Offset, msg.StartOffset)
		overlapEnd := minInt64(frag.Offset+int64(len(frag.Data)), msg.EndOffset)
		if overlapStart >= overlapEnd {
			continue
		}
		if adoptedRangeMatches(frag, overlapStart, overlapEnd, blocks) {
			supporting = append(supporting, frag)
		} else {
			contradicting = append(contradicting, frag)
		}
	}
	return supporting, contradicting
}

// matchingFragments lists observed fragments whose overlapping bytes with
// the message all equal the bytes this branch adopts. A fragment that
// disagrees at a single byte is excluded even where most of it agrees, so a
// sibling-branch observation is never listed as adopted evidence here.
func matchingFragments(msg Message, fragments []Fragment, blocks []Block) []Fragment {
	var out []Fragment
	for _, frag := range fragments {
		overlapStart := maxInt64(frag.Offset, msg.StartOffset)
		overlapEnd := minInt64(frag.Offset+int64(len(frag.Data)), msg.EndOffset)
		if overlapStart >= overlapEnd {
			continue
		}
		if adoptedRangeMatches(frag, overlapStart, overlapEnd, blocks) {
			out = append(out, frag)
		}
	}
	return out
}

// adoptedRangeMatches reports whether a fragment's bytes over [start,end)
// equal the bytes adopted by the branch's blocks. Gaps, conflicts and any
// missing coverage count as non-matching, so a fragment cannot "support"
// bytes the branch never adopted.
func adoptedRangeMatches(frag Fragment, start, end int64, blocks []Block) bool {
	for pos := start; pos < end; pos++ {
		var adopted byte
		covered := false
		for _, block := range blocks {
			if block.Kind != BlockData || pos < block.Offset || pos >= block.Offset+int64(block.Length) {
				continue
			}
			adopted = block.Data[pos-block.Offset]
			covered = true
			break
		}
		if !covered {
			return false
		}
		if adopted != frag.Data[pos-frag.Offset] {
			return false
		}
	}
	return true
}

func intersectsAny(msg Message, ranges []ByteRange) bool {
	_, ok := firstIntersection(msg, ranges)
	return ok
}

func intersectingRanges(msg Message, ranges []ByteRange) []ByteRange {
	var out []ByteRange
	for _, r := range ranges {
		if msg.StartOffset < r.Offset+int64(r.Length) && r.Offset < msg.EndOffset {
			out = append(out, r)
		}
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
