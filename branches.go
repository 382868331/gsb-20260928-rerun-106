package netforensics

import (
	"encoding/json"
	"fmt"
)

// MessageChangeKind classifies what happened to an upper-layer message when
// new bytes or opposite evidence arrives.
type MessageChangeKind string

const (
	// MessageContentChanged means the actual payload bytes the message maps to
	// changed; conclusions derived from the old message content are no longer
	// valid.
	MessageContentChanged MessageChangeKind = "content_changed"
	// MessageBoundaryChanged means the message payload is still present but its
	// start/end offsets shifted, so framing-derived conclusions must be
	// re-interpreted even though the content is unchanged.
	MessageBoundaryChanged MessageChangeKind = "boundary_changed"
	// MessageConfidenceChanged means neither content nor framing changed; only
	// the supporting evidence changed (strengthened, weakened or resolved).
	MessageConfidenceChanged MessageChangeKind = "confidence_changed"
	// MessageUnchanged means the message and its supporting evidence are stable.
	MessageUnchanged MessageChangeKind = "unchanged"
	// MessageNew is a message that did not exist in the previous interpretation.
	MessageNew MessageChangeKind = "new"
	// MessageWithdrawn is a previously exported message that can no longer be
	// parsed (for example a gap opened up inside it).
	MessageWithdrawn MessageChangeKind = "withdrawn"
)

// MessageChange pairs a previous and current message and records why an
// upper-layer conclusion must be revisited.
type MessageChange struct {
	Kind        MessageChangeKind  `json:"kind"`
	Before      *Message           `json:"before,omitempty"`
	After       *Message           `json:"after,omitempty"`
	Reasons     []ConclusionChange `json:"reason,omitempty"`
	Usable      bool               `json:"usable"`
	Explanation string             `json:"explanation,omitempty"`
}

// Choice records which raw fragment a branch adopted for one contested range,
// together with the human-supplied rationale. Packet 0 means a rule-based
// choice (first_observed / last_observed) rather than a specific fragment.
type Choice struct {
	Direction Direction `json:"direction"`
	Range     ByteRange `json:"range"`
	Rule      string    `json:"rule,omitempty"`
	Packet    int       `json:"packet,omitempty"`
	Reason    string    `json:"reason"`
}

// Branch is one interpretation fork. Confirmed content outside contested
// ranges is shared between branches because it comes from the same stream;
// only the choices and conclusions derived after them are branch-local.
type Branch struct {
	ID        string   `json:"id"`
	ParentID  string   `json:"parent_id,omitempty"`
	CreatedAt string   `json:"created_at,omitempty"`
	Choices   []Choice `json:"choices"`
	Delimiter byte     `json:"delimiter"`
	Notes     string   `json:"notes,omitempty"`
}

// BranchView is the resolved state of a branch against one snapshot of the
// streams: adopted blocks, parsed messages and the ranges that are still
// contested or missing.
type BranchView struct {
	Direction        Direction   `json:"direction"`
	Blocks           []Block     `json:"blocks"`
	Messages         []Message   `json:"messages"`
	AdoptedRanges    []ByteRange `json:"adopted_ranges"`
	UnresolvedRanges []ByteRange `json:"unresolved_ranges"`
	ContestedRanges  []ByteRange `json:"contested_ranges"`
	MissingRanges    []ByteRange `json:"missing_ranges"`
	StaleChoices     []Choice    `json:"stale_choices,omitempty"`
}

// CaseFile ties the assembler snapshot to named interpretation branches so an
// investigation can be saved, reopened and continued on either fork.
type CaseFile struct {
	Snapshot Snapshot `json:"snapshot"`
	Branches []Branch `json:"branches"`
}

// NewBranch creates a fork. Choices are copied so later edits on one branch
// never leak into the other: a hypothesis is not a fact in the sibling fork.
func NewBranch(id, parent string, choices []Choice, delim byte, reason string) Branch {
	return Branch{
		ID:        id,
		ParentID:  parent,
		Choices:   append([]Choice(nil), choices...),
		Delimiter: delim,
		Notes:     reason,
	}
}

// Choose records or replaces the adopted evidence for one contested range in
// this branch. The choice is branch-local and never mutates the shared stream.
func (b *Branch) Choose(direction Direction, rng ByteRange, packet int, rule, reason string) error {
	if packet == 0 && rule != CandidateFirstObserved && rule != CandidateLastObserved {
		return fmt.Errorf("choice for %d:%d must name a packet or %q/%q", rng.Offset, rng.Length, CandidateFirstObserved, CandidateLastObserved)
	}
	for i := range b.Choices {
		if b.Choices[i].Direction == direction && b.Choices[i].Range == rng {
			b.Choices[i].Packet = packet
			b.Choices[i].Rule = rule
			b.Choices[i].Reason = reason
			return nil
		}
	}
	b.Choices = append(b.Choices, Choice{Direction: direction, Range: rng, Packet: packet, Rule: rule, Reason: reason})
	return nil
}

func (b Branch) choice(direction Direction, rng ByteRange) (Choice, bool) {
	for _, choice := range b.Choices {
		if choice.Direction == direction && choice.Range == rng {
			return choice, true
		}
	}
	return Choice{}, false
}

// ReconcileResult reports whether later evidence strongly favours a reading
// of a conflict block that differs from the branch's adopted fragment. It
// requires the alternative reading to be repeated by at least two independent
// fragments beyond the adopted one, so a single retransmission can never
// silently flip a branch hypothesis.
type ReconcileResult struct {
	Direction  Direction `json:"direction"`
	Range      ByteRange `json:"range"`
	FromPacket int       `json:"from_packet"`
	ToPacket   int       `json:"to_packet"`
	Witnesses  []int     `json:"witnesses"`
	Reconciled bool      `json:"reconciled"`
}

// Reconcile examines every conflict block in the stream result and, where one
// reading now has at least two more independent witnesses than the branch's
// adopted reading, updates this branch's choice to the majority reading. The
// analyst-supplied reason is stored on the replacement choice so the move is
// auditable; the sibling branch is never touched.
//
// It returns one result per contested range (Reconciled indicates whether the
// choice actually moved). Reconcile never invents bytes: it only selects among
// fragments that are already present in the stream result.
func (b *Branch) Reconcile(result StreamResult, reason string) []ReconcileResult {
	var out []ReconcileResult
	for _, block := range result.Blocks {
		if block.Kind != BlockConflict {
			continue
		}
		rng := ByteRange{Offset: block.Offset, Length: block.Length}
		choice, hadChoice := b.choice(result.Direction, rng)
		adopted, _ := fragmentForChoice(block, choice)
		adoptedValue := []byte(nil)
		if hadChoice {
			adoptedValue = fragmentBytes(adopted, block.Offset, block.Length)
		}
		type tally struct {
			value    []byte
			packets  []int
			fragment Fragment
		}
		var tallies []tally
		for _, source := range block.Sources {
			value := fragmentBytes(source, block.Offset, block.Length)
			found := -1
			for i := range tallies {
				if bytesEqual(tallies[i].value, value) {
					found = i
					break
				}
			}
			if found < 0 {
				tallies = append(tallies, tally{value: value, packets: []int{source.Packet}, fragment: source})
			} else {
				tallies[found].packets = append(tallies[found].packets, source.Packet)
			}
		}
		var best tally
		for _, candidate := range tallies {
			if len(candidate.packets) > len(best.packets) {
				best = candidate
			}
		}
		adoptedCount := 0
		for _, candidate := range tallies {
			if bytesEqual(candidate.value, adoptedValue) {
				adoptedCount = len(candidate.packets)
			}
		}
		rr := ReconcileResult{Direction: result.Direction, Range: rng, FromPacket: choice.Packet, ToPacket: best.fragment.Packet, Witnesses: append([]int(nil), best.packets...)}
		if !bytesEqual(best.value, adoptedValue) && len(best.packets) >= adoptedCount+2 {
			_ = b.Choose(result.Direction, rng, best.fragment.Packet, "", reason)
			rr.Reconciled = true
		}
		out = append(out, rr)
	}
	return out
}

// View resolves the branch against one stream result, applying its adopted
// fragments to conflict blocks and leaving gaps explicit. Messages parse over
// the adopted bytes but never across unresolved ranges.
func (b Branch) View(result StreamResult) BranchView {
	delim := b.Delimiter
	if delim == 0 {
		delim = '\n'
	}
	blocks := make([]Block, len(result.Blocks))
	var adopted, contested, missing []ByteRange
	var stale []Choice
	for i, block := range result.Blocks {
		switch block.Kind {
		case BlockData:
			blocks[i] = block
			adopted = appendRange(adopted, block.Offset, block.Length)
		case BlockGap:
			blocks[i] = block
			missing = appendRange(missing, block.Offset, block.Length)
		case BlockConflict:
			rng := ByteRange{Offset: block.Offset, Length: block.Length}
			choice, ok := b.choice(result.Direction, rng)
			if !ok {
				blocks[i] = block
				contested = appendRange(contested, block.Offset, block.Length)
				continue
			}
			source, ok := fragmentForChoice(block, choice)
			if !ok {
				stale = append(stale, choice)
				blocks[i] = block
				contested = appendRange(contested, block.Offset, block.Length)
				continue
			}
			blocks[i] = Block{Kind: BlockData, Offset: block.Offset, Length: block.Length, Data: fragmentBytes(source, block.Offset, block.Length), Sources: []Fragment{source}}
			adopted = appendRange(adopted, block.Offset, block.Length)
		}
	}
	unresolved := append(append([]ByteRange(nil), contested...), missing...)
	return BranchView{
		Direction:        result.Direction,
		Blocks:           blocks,
		Messages:         messagesFromBlocks(blocks, delim),
		AdoptedRanges:    mergeRanges(adopted),
		UnresolvedRanges: mergeRanges(unresolved),
		ContestedRanges:  mergeRanges(contested),
		MissingRanges:    mergeRanges(missing),
		StaleChoices:     stale,
	}
}

func fragmentForChoice(block Block, choice Choice) (Fragment, bool) {
	if choice.Packet != 0 {
		for _, source := range block.Sources {
			end := block.Offset + int64(block.Length)
			if source.Packet == choice.Packet && source.Offset <= block.Offset && source.Offset+int64(len(source.Data)) >= end {
				return source, true
			}
		}
		return Fragment{}, false
	}
	if len(block.Sources) == 0 {
		return Fragment{}, false
	}
	selected := block.Sources[0]
	for _, source := range block.Sources[1:] {
		if choice.Rule == CandidateFirstObserved && source.Packet < selected.Packet {
			selected = source
		}
		if choice.Rule == CandidateLastObserved && source.Packet > selected.Packet {
			selected = source
		}
	}
	return selected, true
}

// CompareMessages explains which upper-layer messages must be reinterpreted
// when the underlying stream changes, distinguishing real content changes from
// pure boundary shifts and confidence-only updates. Messages are paired by
// stream offset; a withdrawn/new pair that covers the same area is reported as
// a content or boundary change rather than as two unrelated events.
func CompareMessages(before, after []Message, reassessment Reassessment) []MessageChange {
	var changes []MessageChange
	afterByStart := make(map[int64]Message, len(after))
	for _, msg := range after {
		afterByStart[msg.StartOffset] = msg
	}
	consumed := make(map[int64]bool, len(after))
	for _, old := range before {
		if current, ok := afterByStart[old.StartOffset]; ok {
			consumed[old.StartOffset] = true
			if change, ok := pairMessageChange(&old, &current, reassessment); ok {
				changes = append(changes, change)
			}
			continue
		}
		if current, ok := overlappingMessage(after, old, consumed); ok {
			consumed[current.StartOffset] = true
			if change, ok := pairMessageChange(&old, &current, reassessment); ok {
				changes = append(changes, change)
			}
			continue
		}
		changes = append(changes, MessageChange{
			Kind:        MessageWithdrawn,
			Before:      &old,
			Usable:      false,
			Explanation: "message no longer parses after new evidence; previously exported conclusions are withdrawn",
		})
	}
	for _, current := range after {
		if !consumed[current.StartOffset] {
			changes = append(changes, MessageChange{Kind: MessageNew, After: &current, Usable: true})
		}
	}
	return changes
}

func overlappingMessage(after []Message, old Message, consumed map[int64]bool) (Message, bool) {
	for _, current := range after {
		if consumed[current.StartOffset] {
			continue
		}
		if current.StartOffset < old.EndOffset && old.StartOffset < current.EndOffset {
			return current, true
		}
	}
	return Message{}, false
}

func pairMessageChange(before, after *Message, reassessment Reassessment) (MessageChange, bool) {
	reasons := reasonsCovering(reassessment, before.StartOffset, before.EndOffset)
	sameContent := bytesEqual(before.Data, after.Data)
	sameBoundary := before.StartOffset == after.StartOffset && before.EndOffset == after.EndOffset
	change := MessageChange{Before: before, After: after, Reasons: reasons}
	switch {
	case !sameContent:
		change.Kind = MessageContentChanged
		change.Usable = false
		change.Explanation = "payload bytes changed; conclusions derived from the old content are invalidated"
	case !sameBoundary:
		change.Kind = MessageBoundaryChanged
		change.Usable = true
		change.Explanation = "content is unchanged but message boundaries shifted; framing conclusions must be re-interpreted"
	case hasInvalidating(reasons):
		change.Kind = MessageContentChanged
		change.Usable = false
		change.Explanation = "underlying bytes were invalidated by conflicting evidence"
	case len(reasons) > 0:
		change.Kind = MessageConfidenceChanged
		change.Usable = true
		change.Explanation = "content and framing unchanged; only supporting evidence confidence changed"
	default:
		return MessageChange{}, false
	}
	return change, true
}

func reasonsCovering(reassessment Reassessment, start, end int64) []ConclusionChange {
	groups := [][]ConclusionChange{reassessment.Strengthened, reassessment.Invalidated, reassessment.Resolved, reassessment.StillUnresolved, reassessment.NewUncertain}
	var out []ConclusionChange
	for _, group := range groups {
		for _, change := range group {
			if change.Range.Offset < end && change.Range.Offset+int64(change.Range.Length) > start {
				out = append(out, change)
			}
		}
	}
	return out
}

func hasInvalidating(reasons []ConclusionChange) bool {
	for _, reason := range reasons {
		if reason.Status == ConclusionInvalidated {
			return true
		}
	}
	return false
}

// Reconverged reports whether two branch views now agree on their upper-layer
// Conflict-driven forks reconverge once the contested ranges are resolved
// and both readings yield the same parsed messages (content and offsets). The
// raw conflict block may remain explicit in the stream, but the exported
// interpretation is identical, which is what forensic conclusions depend on.
func Reconverged(left, right BranchView) bool {
	if left.Direction != right.Direction || len(left.Messages) != len(right.Messages) {
		return false
	}
	for i := range left.Messages {
		lm, rm := left.Messages[i], right.Messages[i]
		if lm.StartOffset != rm.StartOffset || lm.EndOffset != rm.EndOffset || !bytesEqual(lm.Data, rm.Data) {
			return false
		}
	}
	return true
}

// SaveCaseFile persists the assembler state together with all branches,
// including each branch's adopted evidence and stated rationale.
func SaveCaseFile(a *Assembler, branches []Branch) ([]byte, error) {
	return json.Marshal(CaseFile{Snapshot: a.Snapshot(), Branches: branches})
}

// LoadCaseFile restores a saved investigation so either fork can continue.
func LoadCaseFile(data []byte) (*Assembler, []Branch, error) {
	var file CaseFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, nil, err
	}
	a := NewAssemblerFromSnapshot(file.Snapshot)
	return a, append([]Branch(nil), file.Branches...), nil
}
