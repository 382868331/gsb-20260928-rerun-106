package session

import "sort"

// fragment is a held payload fragment in relative coordinates where
// relative 0 is the SYN and the first data byte is 1.
type fragment struct {
	start uint64
	data  []byte
}

func (f fragment) end() uint64 { return f.start + uint64(len(f.data)) }

type direction struct {
	isn    uint32
	isnSet bool
	finSeq uint64
	finSet bool

	base         uint64 // always 1 once ISN is set
	deliveredEnd uint64 // one past the contiguous in-order prefix
	data         []byte
	pending      []fragment
}

func (d *direction) setISN(isn uint32) {
	if d.isnSet {
		return
	}
	d.isn = isn
	d.isnSet = true
	d.base = 1
	d.deliveredEnd = 1
}

// rel maps an absolute TCP sequence number to relative coordinates.
func (d *direction) rel(seq uint32) uint64 {
	return uint64(int64(seq) - int64(d.isn))
}

// byteAt returns the first-seen byte at a relative coordinate.
func (d *direction) byteAt(pos uint64) (byte, bool) {
	if pos >= d.base && pos < d.deliveredEnd {
		return d.data[pos-d.base], true
	}
	for _, p := range d.pending {
		if pos >= p.start && pos < p.end() {
			return p.data[pos-p.start], true
		}
	}
	return 0, false
}

// compareOverlap checks new payload against bytes already seen. It yields
// one overwrite record (first disagreement, which dominates) or one
// retransmit record when the overlap is byte-identical.
func (d *direction) compareOverlap(relStart uint64, payload []byte, frameIdx, dir int) []Conflict {
	haveOverlap := false
	overlapStart := uint64(0)
	for i, b := range payload {
		pos := relStart + uint64(i)
		ex, ok := d.byteAt(pos)
		if !ok {
			continue
		}
		if !haveOverlap {
			haveOverlap = true
			overlapStart = pos
		}
		if ex != b {
			return []Conflict{{
				Dir: dir, FrameIndex: frameIdx,
				Start: relStart, End: relStart + uint64(len(payload)),
				OverlapAt: pos, Existing: ex, New: b,
				Kind: KindOverwrite, Resolution: "kept-first",
			}}
		}
	}
	if haveOverlap {
		return []Conflict{{
			Dir: dir, FrameIndex: frameIdx,
			Start: relStart, End: relStart + uint64(len(payload)),
			OverlapAt: overlapStart, Kind: KindRetransmit, Resolution: "kept-first",
		}}
	}
	return nil
}

// PlaceResult tells the caller how a fragment interacted with coverage.
type PlaceResult int

const (
	PlaceDuplicate     PlaceResult = iota // only already-known coordinates
	PlaceAccepted                         // new bytes stored/coverage grew
	PlaceBudgetBlocked                    // new bytes rejected by the budget
)

// place stores a payload fragment, returning a three-way result and overlap
// evidence. budgetLeft receives the projected total buffered size.
func (d *direction) place(relStart uint64, payload []byte, frameIdx, dir int, budgetLeft func(int) bool) (PlaceResult, []Conflict) {
	if len(payload) == 0 {
		return PlaceDuplicate, nil
	}
	var headEvidence []Conflict
	if relStart < d.base && d.base-relStart < uint64(len(payload)) {
		headEvidence = d.compareOverlap(relStart, payload[:d.base-relStart], frameIdx, dir)
		payload = payload[d.base-relStart:]
		relStart = d.base
	} else if relStart < d.base {
		return PlaceDuplicate, d.compareOverlap(relStart, payload, frameIdx, dir)
	}
	var conflicts []Conflict
	conflicts = append(conflicts, headEvidence...)
	conflicts = append(conflicts, d.compareOverlap(relStart, payload, frameIdx, dir)...)
	oldCoverage := d.coverage()

	// Project coverage after merging without mutating state yet, so the
	// budget can reject a fragment that would introduce new bytes.
	projected := append(append([]fragment(nil), d.pending...),
		fragment{start: relStart, data: append([]byte(nil), payload...)})
	if mergedTotal, newCoverage := mergeTotal(d, projected); newCoverage > oldCoverage {
		totalCoverage := uint64(len(d.data)) + uint64(mergedTotal)
		if !budgetLeft(int(totalCoverage)) {
			return PlaceBudgetBlocked, conflicts
		}
	}

	merged := append(append([]fragment(nil), d.pending...),
		fragment{start: relStart, data: append([]byte(nil), payload...)})
	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].start != merged[j].start {
			return merged[i].start < merged[j].start
		}
		return len(merged[i].data) > len(merged[j].data)
	})
	var unique []fragment
	for _, fr := range merged {
		if len(unique) == 0 || fr.start > unique[len(unique)-1].end() {
			unique = append(unique, fragment{start: fr.start, data: append([]byte(nil), fr.data...)})
			continue
		}
		last := &unique[len(unique)-1]
		if fr.end() <= last.end() {
			continue
		}
		last.data = append(last.data, fr.data[last.end()-fr.start:]...)
	}

	d.pending = unique
	d.drain()
	if d.coverage() > oldCoverage {
		return PlaceAccepted, conflicts
	}
	return PlaceDuplicate, conflicts
}

// mergeTotal simulates merging in an extra fragment set and returns the
// total pending byte count and the resulting coverage, without mutating d.
func mergeTotal(d *direction, frags []fragment) (pendingBytes int, coverage uint64) {
	sort.SliceStable(frags, func(i, j int) bool {
		if frags[i].start != frags[j].start {
			return frags[i].start < frags[j].start
		}
		return len(frags[i].data) > len(frags[j].data)
	})
	var unique []fragment
	for _, fr := range frags {
		if len(unique) == 0 || fr.start > unique[len(unique)-1].end() {
			unique = append(unique, fragment{start: fr.start, data: append([]byte(nil), fr.data...)})
			continue
		}
		last := &unique[len(unique)-1]
		if fr.end() <= last.end() {
			continue
		}
		last.data = append(last.data, fr.data[last.end()-fr.start:]...)
	}
	cov := uint64(len(d.data))
	for _, p := range unique {
		pendingBytes += len(p.data)
		s := p.start
		if s < d.deliveredEnd {
			s = d.deliveredEnd
		}
		if p.end() > s {
			cov += p.end() - s
		}
	}
	return pendingBytes, cov
}

// coverage counts unique sequence positions represented right now.
func (d *direction) coverage() uint64 {
	cov := uint64(len(d.data))
	for _, p := range d.pending {
		s := p.start
		if s < d.deliveredEnd {
			s = d.deliveredEnd
		}
		if p.end() > s {
			cov += p.end() - s
		}
	}
	return cov
}

// drain moves contiguous pending fragments into the delivered prefix.
func (d *direction) drain() {
	for {
		idx := -1
		for i, p := range d.pending {
			if p.start <= d.deliveredEnd && p.end() > d.deliveredEnd {
				idx = i
				break
			}
		}
		if idx < 0 {
			return
		}
		p := d.pending[idx]
		p.data = p.data[d.deliveredEnd-p.start:]
		d.data = append(d.data, p.data...)
		d.deliveredEnd += uint64(len(p.data))
		d.pending = append(d.pending[:idx], d.pending[idx+1:]...)
	}
}

// highWater returns the furthest relative coordinate observed, including FIN.
func (d *direction) highWater() uint64 {
	high := d.deliveredEnd
	for _, p := range d.pending {
		if p.end() > high {
			high = p.end()
		}
	}
	if d.finSet && d.finSeq > high {
		high = d.finSeq
	}
	return high
}

// gaps reports missing ranges from the first data byte through high water.
func (d *direction) gaps() []Gap {
	if !d.isnSet {
		return nil
	}
	high := d.highWater()
	if high <= d.base {
		return nil
	}
	pend := append([]fragment(nil), d.pending...)
	sort.Slice(pend, func(i, j int) bool { return pend[i].start < pend[j].start })
	var gaps []Gap
	cursor := d.deliveredEnd
	for _, p := range pend {
		s := p.start
		if s < cursor {
			s = cursor
		}
		if s > cursor {
			gaps = append(gaps, Gap{Start: cursor, End: s})
		}
		if p.end() > cursor {
			cursor = p.end()
		}
	}
	if cursor < high {
		gaps = append(gaps, Gap{Start: cursor, End: high})
	}
	return gaps
}

// spans renders delivered and out-of-order data with gaps between them.
// Gap spans carry no bytes: callers render placeholders themselves.
func (d *direction) spans() []Span {
	if !d.isnSet {
		return nil
	}
	var spans []Span
	if len(d.data) > 0 {
		spans = append(spans, Span{Data: d.data, Start: d.base, End: d.deliveredEnd})
	}
	cursor := d.deliveredEnd
	pend := append([]fragment(nil), d.pending...)
	sort.Slice(pend, func(i, j int) bool { return pend[i].start < pend[j].start })
	for _, p := range pend {
		s := p.start
		if s < cursor {
			s = cursor
		}
		if p.end() <= s {
			continue
		}
		if s > cursor {
			spans = append(spans, Span{Gap: true, Start: cursor, End: s})
		}
		spans = append(spans, Span{Data: p.data[s-p.start:], Start: s, End: p.end()})
		cursor = p.end()
	}
	if d.finSet && d.finSeq > cursor {
		spans = append(spans, Span{Gap: true, Start: cursor, End: d.finSeq})
	}
	return spans
}
