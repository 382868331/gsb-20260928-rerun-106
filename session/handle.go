package session

import "tcprecon/pcapio"

func (s *Session) ensureDir(dir int) *direction {
	if s.dirs[dir] == nil {
		s.dirs[dir] = &direction{}
	}
	return s.dirs[dir]
}

func (s *Session) record(seg *pcapio.Segment, dir int, from, to Endpoint, disposition string, accepted bool, note string) {
	s.frames = append(s.frames, FrameEvidence{
		FrameIndex: seg.Frame.Index, Dir: dir, From: from, To: to,
		Seq: seg.Seq, Ack: seg.Ack, SYN: seg.SYN, FIN: seg.FIN, RST: seg.RST,
		PayloadLen: len(seg.Data), Accepted: accepted,
		Disposition: disposition, Note: note,
	})
}

// handle processes one segment attributed to this session.
func (s *Session) handle(seg *pcapio.Segment, dir int, from, to Endpoint, e *Engine) {
	d := s.ensureDir(dir)

	if seg.RST {
		s.record(seg, dir, from, to, "reset", false, "")
		s.markClosed(seg.Frame.Index, "rst")
		return
	}

	if s.closed {
		note := "segment after session close"
		if len(seg.Data) > 0 {
			note = "payload after session close; not spliced"
		}
		s.record(seg, dir, from, to, "late-after-close", false, note)
		e.stats.LateSegments++
		return
	}

	// Without the peer ISN coordinates are unknowable. Keep evidence but do
	// not fabricate alignment.
	if !d.isnSet {
		s.record(seg, dir, from, to, "control", false, "peer ISN not observed; payload not aligned")
		s.maybeCloseOnFin(seg, dir)
		return
	}

	// A peer ACK can acknowledge the other direction's FIN before this segment
	// carries any data; process teardown bookkeeping first.
	s.observeAck(seg, dir)

	if len(seg.Data) == 0 {
		s.record(seg, dir, from, to, "control", false, "")
		s.maybeCloseOnFin(seg, dir)
		return
	}

	rs := d.rel(seg.Seq)
	res, conflicts := d.place(rs, seg.Data, seg.Frame.Index, dir, func(total int) bool {
		return e.budgetAllowDir(total)
	})
	s.conflicts = append(s.conflicts, conflicts...)
	overwrite := false
	for _, c := range conflicts {
		if c.Kind == KindOverwrite {
			overwrite = true
		}
	}

	disposition := "assembled"
	accepted := res == PlaceAccepted
	note := ""
	switch {
	case res == PlaceBudgetBlocked:
		disposition, accepted = "dropped", false
		note = "byte budget exhausted; fragment withheld"
		s.drops = append(s.drops, DropEvent{FrameIndex: seg.Frame.Index, Dir: dir, Reason: note})
		e.recordDrop(seg.Frame.Index, dir, note)
	case res == PlaceDuplicate:
		if overwrite {
			disposition = "conflict"
		} else {
			disposition = "retransmit"
			note = "identical retransmit; original bytes kept"
		}
	default:
		switch {
		case overwrite:
			disposition = "conflict"
		case rs > d.deliveredEnd:
			disposition = "buffered"
		}
	}
	s.record(seg, dir, from, to, disposition, accepted, note)
	s.maybeCloseOnFin(seg, dir)
}

// observeAck marks the opposite direction FIN acknowledged when the peer's
// ACK number equals finSeq+1 (relative), accounting for sequence wrap.
func (s *Session) observeAck(seg *pcapio.Segment, dir int) {
	if !seg.ACK {
		return
	}
	peer := s.ensureDir(1 - dir)
	if !peer.isnSet || !peer.finSet || s.finAcked[1-dir] {
		return
	}
	want := peer.finSeq + 1
	got := peer.rel(seg.Ack)
	if got == want {
		s.finAcked[1-dir] = true
	}
}

// maybeCloseOnFin records FIN state and closes when both directions have
// FINed (a RST on either side closes immediately in handle).
func (s *Session) maybeCloseOnFin(seg *pcapio.Segment, dir int) {
	d := s.ensureDir(dir)
	if seg.FIN && d.isnSet {
		finRel := d.rel(seg.Seq)
		if len(seg.Data) > 0 {
			finRel = d.rel(seg.Seq) + uint64(len(seg.Data))
		}
		d.finSet = true
		d.finSeq = finRel // FIN occupies the byte after the last data byte
	}
	if s.dirs[C2S] != nil && s.dirs[C2S].finSet &&
		s.dirs[S2C] != nil && s.dirs[S2C].finSet {
		s.tryFinClose(seg.Frame.Index)
	}
}

func (s *Session) tryFinClose(frameIdx int) {
	if s.finAcked[C2S] && s.finAcked[S2C] {
		s.markClosed(frameIdx, "fin-ack fin-ack")
	}
}

func (s *Session) markClosed(frameIdx int, why string) {
	if s.closed {
		return
	}
	s.closed = true
	s.closeWhy = why
	s.closedFrame = frameIdx
}

// Payload returns the contiguous in-order reassembled bytes for a direction.
func (s *Session) Payload(dir int) []byte {
	if s.dirs[dir] == nil || !s.dirs[dir].isnSet {
		return nil
	}
	return append([]byte(nil), s.dirs[dir].data...)
}

// Spans returns data spans interleaved with explicit gap spans.
func (s *Session) Spans(dir int) []Span {
	if s.dirs[dir] == nil {
		return nil
	}
	return s.dirs[dir].spans()
}

// Gaps returns never-recovered ranges for a direction.
func (s *Session) Gaps(dir int) []Gap {
	if s.dirs[dir] == nil {
		return nil
	}
	gs := s.dirs[dir].gaps()
	for i := range gs {
		gs[i].Dir = dir
	}
	return gs
}
