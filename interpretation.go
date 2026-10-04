package netforensics

import "fmt"

type ConclusionStatus string

const (
	ConclusionStrengthened    ConclusionStatus = "strengthened"
	ConclusionInvalidated     ConclusionStatus = "invalidated"
	ConclusionResolved        ConclusionStatus = "resolved"
	ConclusionStillUnresolved ConclusionStatus = "still_unresolved"
	ConclusionNewUncertain    ConclusionStatus = "new_uncertain"
)

type ConclusionChange struct {
	Direction Direction        `json:"direction"`
	Range     ByteRange        `json:"range"`
	Status    ConclusionStatus `json:"status"`
	Detail    string           `json:"detail,omitempty"`
}

type Reassessment struct {
	Strengthened    []ConclusionChange `json:"strengthened"`
	Invalidated     []ConclusionChange `json:"invalidated"`
	Resolved        []ConclusionChange `json:"resolved"`
	StillUnresolved []ConclusionChange `json:"still_unresolved"`
	NewUncertain    []ConclusionChange `json:"new_uncertain"`
}

func (r StreamResult) Interpret(rule string) (Interpretation, error) {
	candidate, ok := r.Candidate(rule)
	if !ok {
		return Interpretation{}, fmt.Errorf("unknown stream interpretation %q", rule)
	}
	var adopted []ByteRange
	var contested []ByteRange
	for _, block := range r.Blocks {
		switch block.Kind {
		case BlockData:
			adopted = appendRange(adopted, block.Offset, block.Length)
		case BlockConflict:
			contested = appendRange(contested, block.Offset, block.Length)
			adopted = appendRange(adopted, block.Offset, block.Length)
		}
	}
	unresolved := gapsToRanges(r.Gaps)
	for _, rng := range contested {
		unresolved = appendRange(unresolved, rng.Offset, rng.Length)
	}
	messages := messagesFromBlocks(candidate.Blocks, '\n')
	return Interpretation{
		Direction:        r.Direction,
		Rule:             rule,
		Blocks:           append([]Block(nil), candidate.Blocks...),
		Messages:         messages,
		AdoptedRanges:    adopted,
		UnresolvedRanges: unresolved,
	}, nil
}

func messagesFromBlocks(blocks []Block, delim byte) []Message {
	var messages []Message
	var run []byte
	runStart := int64(-1)
	var sources []Fragment
	discard := func() {
		run = nil
		runStart = -1
		sources = nil
	}
	for _, block := range blocks {
		if block.Kind != BlockData {
			discard()
			continue
		}
		for i, value := range block.Data {
			position := block.Offset + int64(i)
			if value == delim {
				if runStart >= 0 {
					messages = append(messages, Message{
						Data:        append([]byte(nil), run...),
						StartOffset: runStart,
						EndOffset:   position + 1,
						Sources:     append([]Fragment(nil), sources...),
					})
				}
				discard()
				continue
			}
			if runStart >= 0 && position != runStart+int64(len(run)) {
				discard()
			}
			if runStart < 0 {
				runStart = position
			}
			for _, source := range block.Sources {
				if fragmentCovers(source, position) && !fragmentListed(sources, source) {
					sources = append(sources, source)
				}
			}
			run = append(run, value)
		}
	}
	return messages
}

func fragmentCovers(frag Fragment, offset int64) bool {
	return frag.Offset <= offset && frag.Offset+int64(len(frag.Data)) > offset
}

func fragmentListed(fragments []Fragment, want Fragment) bool {
	for _, frag := range fragments {
		if frag.Packet == want.Packet && frag.Offset == want.Offset {
			return true
		}
	}
	return false
}

func CompareStreamResults(before, after StreamResult) Reassessment {
	var result Reassessment
	beforeGaps := rangeSet(before.Gaps)
	afterGaps := rangeSet(after.Gaps)
	beforeConflicts := conflictRanges(before.Blocks)
	afterConflicts := conflictRanges(after.Blocks)
	beforeData := dataRanges(before.Blocks)
	afterData := dataRanges(after.Blocks)
	for _, gap := range before.Gaps {
		r := ByteRange{Offset: gap.Offset, Length: gap.Length}
		if afterGaps[r] {
			for _, next := range after.Gaps {
				if next.Offset == gap.Offset && next.Length == gap.Length && !gap.Acknowledged && next.Acknowledged {
					result.Strengthened = append(result.Strengthened, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionStrengthened, Detail: "gap is acknowledged from the opposite direction"})
				} else {
					result.StillUnresolved = append(result.StillUnresolved, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionStillUnresolved})
				}
			}
			continue
		}
		if rangesContain(afterData, r) {
			result.Resolved = append(result.Resolved, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionResolved, Detail: "late segment supplied previously missing bytes"})
		}
	}
	for _, r := range beforeConflicts {
		if containsRange(afterConflicts, r) {
			if afterBlock := blockAt(after.Blocks, r.Offset); afterBlock != nil {
				if beforeBlock := blockAt(before.Blocks, r.Offset); beforeBlock != nil && corroboratesPrimary(beforeBlock, afterBlock) {
					result.Strengthened = append(result.Strengthened, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionStrengthened, Detail: "a new fragment corroborates one reading of the contested bytes; the conflict stays explicit until adopted"})
					continue
				}
			}
			result.StillUnresolved = append(result.StillUnresolved, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionStillUnresolved, Detail: "conflicting observations remain"})
			continue
		}
		if rangesContain(afterData, r) {
			result.Resolved = append(result.Resolved, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionResolved})
		}
	}
	for _, gap := range after.Gaps {
		r := ByteRange{Offset: gap.Offset, Length: gap.Length}
		if !beforeGaps[r] {
			result.NewUncertain = append(result.NewUncertain, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionNewUncertain})
		}
	}
	for _, r := range afterConflicts {
		if !containsRange(beforeConflicts, r) {
			result.NewUncertain = append(result.NewUncertain, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionNewUncertain})
		}
	}
	for _, r := range beforeData {
		if containsRange(afterConflicts, r) {
			result.Invalidated = append(result.Invalidated, ConclusionChange{Direction: after.Direction, Range: r, Status: ConclusionInvalidated, Detail: "a later observation conflicts with previously unique bytes"})
		}
	}
	return result
}

func blockAt(blocks []Block, offset int64) *Block {
	for i := range blocks {
		if blocks[i].Offset == offset {
			return &blocks[i]
		}
	}
	return nil
}

// corroboratesPrimary reports whether the after conflict block gained new
// witnesses that agree with the first-observed (primary) reading, i.e. the
// branch adopting that reading now has stronger evidence behind it.
func corroboratesPrimary(before, after *Block) bool {
	want := fragmentBytes(after.Sources[0], after.Offset, after.Length)
	beforeAgree, afterAgree := 0, 0
	for _, source := range before.Sources {
		if bytesEqual(fragmentBytes(source, before.Offset, before.Length), want) {
			beforeAgree++
		}
	}
	for _, source := range after.Sources {
		if bytesEqual(fragmentBytes(source, after.Offset, after.Length), want) {
			afterAgree++
		}
	}
	return afterAgree > beforeAgree
}

func rangeSet(gaps []Gap) map[ByteRange]bool {
	out := make(map[ByteRange]bool, len(gaps))
	for _, gap := range gaps {
		out[ByteRange{Offset: gap.Offset, Length: gap.Length}] = true
	}
	return out
}

func conflictRanges(blocks []Block) []ByteRange {
	var ranges []ByteRange
	for _, block := range blocks {
		if block.Kind == BlockConflict {
			ranges = appendRange(ranges, block.Offset, block.Length)
		}
	}
	return ranges
}

func dataRanges(blocks []Block) []ByteRange {
	var ranges []ByteRange
	for _, block := range blocks {
		if block.Kind == BlockData {
			ranges = appendRange(ranges, block.Offset, block.Length)
		}
	}
	return ranges
}

func containsRange(ranges []ByteRange, want ByteRange) bool {
	for _, r := range ranges {
		if r == want {
			return true
		}
	}
	return false
}

func rangesContain(ranges []ByteRange, want ByteRange) bool {
	end := want.Offset + int64(want.Length)
	for _, r := range ranges {
		if r.Offset <= want.Offset && r.Offset+int64(r.Length) >= end {
			return true
		}
	}
	return false
}
