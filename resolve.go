package netforensics

import "fmt"

// ResolvedMessage is an application message parsed under one user-selected
// interpretation rule. It records the evidence (fragments) backing the
// chosen bytes and the ranges where the rule was applied to resolve
// ambiguity.
type ResolvedMessage struct {
	Data          []byte      `json:"data"`
	StartOffset   int64       `json:"start_offset"`
	EndOffset     int64       `json:"end_offset"`
	Sources       []Fragment  `json:"sources,omitempty"`
	AssumedRanges []ByteRange `json:"assumed_ranges,omitempty"`
}

// ResolvedStream is the result of applying one candidate rule to a stream:
// the parsed messages plus the ranges that remain unresolved regardless of
// the chosen rule (capture gaps and budget-stopped ranges).
type ResolvedStream struct {
	Rule             string            `json:"rule"`
	Messages         []ResolvedMessage `json:"messages"`
	UnresolvedRanges []ByteRange       `json:"unresolved_ranges"`
}

// Resolve applies a user-selected candidate rule (for example
// CandidateFirstObserved or CandidateLastObserved) and parses application
// messages from that interpretation. Messages still stop at gaps: bytes
// that were never captured are never invented, no matter which rule is
// chosen.
func (s StreamResult) Resolve(rule string, delim byte) (ResolvedStream, error) {
	candidate, ok := s.Candidate(rule)
	if !ok {
		return ResolvedStream{}, fmt.Errorf("unknown candidate rule %q", rule)
	}
	resolved := ResolvedStream{
		Rule:             rule,
		UnresolvedRanges: mergeRanges(append(gapsToRanges(s.Gaps), s.IncompleteRanges...)),
	}
	for _, message := range parseMessages(candidate.Blocks, delim) {
		resolved.Messages = append(resolved.Messages, ResolvedMessage{
			Data:          message.Data,
			StartOffset:   message.StartOffset,
			EndOffset:     message.EndOffset,
			Sources:       sourcesForSpan(candidate.Blocks, message.StartOffset, message.EndOffset),
			AssumedRanges: intersectRanges(s.UncertainRanges, []ByteRange{{Offset: message.StartOffset, Length: int(message.EndOffset - message.StartOffset)}}),
		})
	}
	return resolved, nil
}

// sourcesForSpan collects the distinct fragments that back the chosen bytes
// inside [start, end).
func sourcesForSpan(blocks []Block, start, end int64) []Fragment {
	var out []Fragment
	seen := make(map[[2]int64]bool)
	for _, block := range blocks {
		if block.Kind == BlockGap || block.Offset+int64(block.Length) <= start || block.Offset >= end {
			continue
		}
		for _, source := range block.Sources {
			key := [2]int64{int64(source.Packet), source.Offset}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, source)
		}
	}
	return out
}
