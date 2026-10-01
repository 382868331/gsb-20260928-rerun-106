package netforensics

import "sort"

// RangeStatus describes how certain the reconstruction is for a byte range.
type RangeStatus string

const (
	StatusUnknown    RangeStatus = "unknown"
	StatusGap        RangeStatus = "gap"
	StatusIncomplete RangeStatus = "incomplete"
	StatusDetermined RangeStatus = "determined"
	StatusConflict   RangeStatus = "conflict"
)

// ChangeEffect classifies how a conclusion changed between two reviews.
type ChangeEffect string

const (
	// EffectStrengthened means a range that was missing or ambiguous is now
	// uniquely determined (for example an out-of-order segment filled a gap).
	EffectStrengthened ChangeEffect = "strengthened"
	// EffectInvalidated means a range that was uniquely determined is now
	// contested by a conflicting observation.
	EffectInvalidated ChangeEffect = "invalidated"
	// EffectAdded means bytes appear that had no prior conclusion at all.
	EffectAdded ChangeEffect = "added"
)

// ConclusionChange describes one range whose interpretation changed between
// two stream results. Ranges that did not change are not reported.
type ConclusionChange struct {
	Range  ByteRange    `json:"range"`
	Before RangeStatus  `json:"before"`
	After  RangeStatus  `json:"after"`
	Effect ChangeEffect `json:"effect"`
	Detail string       `json:"detail"`
}

// DiffStreamResults compares an earlier stream result with a later one (for
// example before and after out-of-order segments arrived, a budget stopped
// ingestion, or a snapshot was restored and capture resumed) and reports
// which conclusions were strengthened, invalidated, or added. Raw fragments
// are never rewritten, so a determined range can only become conflict (new
// conflicting observation), never silently different bytes.
func DiffStreamResults(before, after StreamResult) []ConclusionChange {
	beforeRanges := statusRanges(before)
	afterRanges := statusRanges(after)
	var boundaries []int64
	for _, r := range append(beforeRanges, afterRanges...) {
		boundaries = append(boundaries, r.Offset, r.Offset+int64(r.Length))
	}
	boundaries = uniqueSortedOffsets(boundaries)
	var changes []ConclusionChange
	for i := 0; i+1 < len(boundaries); i++ {
		start, end := boundaries[i], boundaries[i+1]
		if end <= start {
			continue
		}
		b := statusAt(beforeRanges, start)
		af := statusAt(afterRanges, start)
		if b == af {
			continue
		}
		effect, detail := classifyChange(b, af)
		changes = append(changes, ConclusionChange{
			Range:  ByteRange{Offset: start, Length: int(end - start)},
			Before: b,
			After:  af,
			Effect: effect,
			Detail: detail,
		})
	}
	return changes
}

type rangedStatus struct {
	Offset int64
	Length int
	Status RangeStatus
}

func statusRanges(result StreamResult) []rangedStatus {
	var out []rangedStatus
	for _, block := range result.Blocks {
		status := StatusDetermined
		switch block.Kind {
		case BlockGap:
			status = StatusGap
		case BlockConflict:
			status = StatusConflict
		}
		out = append(out, rangedStatus{Offset: block.Offset, Length: block.Length, Status: status})
	}
	for _, r := range result.IncompleteRanges {
		out = append(out, rangedStatus{Offset: r.Offset, Length: r.Length, Status: StatusIncomplete})
	}
	// Incomplete ranges overlap gap blocks; let the more specific status win.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Offset != out[j].Offset {
			return out[i].Offset < out[j].Offset
		}
		return statusRank(out[i].Status) > statusRank(out[j].Status)
	})
	return out
}

func statusRank(status RangeStatus) int {
	switch status {
	case StatusConflict:
		return 4
	case StatusDetermined:
		return 3
	case StatusIncomplete:
		return 2
	case StatusGap:
		return 1
	}
	return 0
}

func statusAt(ranges []rangedStatus, offset int64) RangeStatus {
	best := StatusUnknown
	for _, r := range ranges {
		if offset >= r.Offset && offset < r.Offset+int64(r.Length) && statusRank(r.Status) > statusRank(best) {
			best = r.Status
		}
	}
	return best
}

func classifyChange(before, after RangeStatus) (ChangeEffect, string) {
	switch after {
	case StatusDetermined:
		switch before {
		case StatusGap:
			return EffectStrengthened, "capture gap filled by later or reordered segments"
		case StatusIncomplete:
			return EffectStrengthened, "previously incomplete range now fully observed"
		case StatusConflict:
			return EffectStrengthened, "conflicting observations resolved to unique bytes"
		default:
			return EffectAdded, "new bytes observed"
		}
	case StatusConflict:
		if before == StatusDetermined {
			return EffectInvalidated, "previously unique bytes now contested by a conflicting observation"
		}
		return EffectAdded, "new conflicting observations"
	case StatusGap, StatusIncomplete:
		if before == StatusDetermined || before == StatusConflict {
			return EffectInvalidated, "previously determined bytes no longer covered"
		}
		return EffectAdded, "range now known to be missing"
	default:
		return EffectAdded, "conclusion changed"
	}
}
