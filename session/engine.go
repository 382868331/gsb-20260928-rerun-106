package session

import (
	"fmt"

	"tcprecon/pcapio"
)

// Budget caps reassembly resource use. Zero means unlimited.
type Budget struct {
	MaxSessions    int
	MaxFrames      int // total evidence frames accepted
	MaxBytesPerDir int // delivered + buffered bytes in any one direction
	MaxTotalBytes  int // across every session direction
}

// Stats summarizes engine-level counters.
type Stats struct {
	Frames        int
	TCPSegments   int
	NonTCP        int
	Sessions      int
	LateSegments  int
	Orphans       int
	DroppedFrames int
	Exhausted     bool
	ExhaustReason string
}

// Engine holds configuration and output of one capture analysis.
type Engine struct {
	budget   Budget
	sessions []*Session
	// incarnations indexed by tuple key in connection order
	byKey     map[string][]*Session
	drops     []DropEvent
	stats     Stats
	usedBytes int
}

// NewEngine constructs an engine with the given budget.
func NewEngine(b Budget) *Engine {
	return &Engine{budget: b, byKey: map[string][]*Session{}}
}

// Sessions returns reconstructed sessions in open order.
func (e *Engine) Sessions() []*Session { return e.sessions }

// Drops returns engine-level drops (budget exhaustion etc.).
func (e *Engine) Drops() []DropEvent { return e.drops }

// Stats returns counters after processing.
func (e *Engine) Stats() Stats { return e.stats }

func (e *Engine) budgetAllowDir(additional int) bool {
	if e.budget.MaxBytesPerDir > 0 && additional > e.budget.MaxBytesPerDir {
		return false
	}
	if e.budget.MaxTotalBytes > 0 {
		cur := 0
		for _, s := range e.sessions {
			for _, d := range s.dirs {
				if d != nil {
					cur += int(d.coverage())
				}
			}
		}
		if cur+additional > e.budget.MaxTotalBytes {
			return false
		}
	}
	return true
}

// Process ingests frames in capture order.
func (e *Engine) Process(frames []*pcapio.Frame, link pcapio.LinkType) error {
	for _, f := range frames {
		e.stats.Frames++
		if e.budget.MaxFrames > 0 && e.stats.Frames > e.budget.MaxFrames {
			e.recordDrop(f.Index, -1, "max-frames exceeded")
			continue
		}
		seg, err := pcapio.DecodeFrame(f, link)
		if err != nil {
			return fmt.Errorf("frame %d: %w", f.Index, err)
		}
		if seg == nil {
			e.stats.NonTCP++
			continue
		}
		e.stats.TCPSegments++
		e.dispatch(seg)
	}
	return nil
}

func (e *Engine) recordDrop(frameIdx, dir int, reason string) {
	e.stats.DroppedFrames++
	if !e.stats.Exhausted {
		e.stats.Exhausted = true
		e.stats.ExhaustReason = reason
	}
	e.drops = append(e.drops, DropEvent{FrameIndex: frameIdx, Dir: dir, Reason: reason})
}

func (e *Engine) dispatch(seg *pcapio.Segment) {
	from := Endpoint{IP: seg.SrcIP, Port: seg.SrcPort}
	to := Endpoint{IP: seg.DstIP, Port: seg.DstPort}
	key := tupleKey(from, to)
	candidates := e.byKey[key]

	if seg.SYN && !seg.ACK {
		e.openSession(key, from, to, seg)
		return
	}

	// SYN-ACK: attach ISN to the most recent matching open session.
	if seg.SYN && seg.ACK {
		if s := e.pickForHandshake(candidates, from, to); s != nil {
			d := s.ensureDir(S2C)
			d.setISN(seg.Seq)
			s.record(seg, S2C, from, to, "syn", true, "")
			return
		}
		// SYN-ACK without our SYN: treat as orphan evidence
		e.stats.Orphans++
		return
	}

	// Pure data/control segment: find the best incarnation.
	s, dir := e.pickSession(candidates, seg, from, to)
	if s == nil {
		e.stats.Orphans++
		return
	}
	s.handle(seg, dir, from, to, e)
}

func (e *Engine) openSession(key string, client, server Endpoint, seg *pcapio.Segment) {
	if e.budget.MaxSessions > 0 && len(e.sessions) >= e.budget.MaxSessions {
		e.recordDrop(seg.Frame.Index, C2S, "max-sessions exceeded")
		return
	}
	inc := len(e.byKey[key])
	s := &Session{
		ID: len(e.sessions), Client: client, Server: server, Key: key,
		Incarnation: inc, openedFrame: seg.Frame.Index,
	}
	s.dirs[C2S] = &direction{}
	s.dirs[C2S].setISN(seg.Seq)
	s.dirs[S2C] = &direction{}
	if seg.FIN {
		s.dirs[C2S].finSet = true
		s.dirs[C2S].finSeq = s.dirs[C2S].rel(seg.Seq)
	}
	s.record(seg, C2S, client, server, "syn", true, "")
	e.byKey[key] = append(e.byKey[key], s)
	e.sessions = append(e.sessions, s)
	e.stats.Sessions++
}

func (e *Engine) pickForHandshake(cand []*Session, from, to Endpoint) *Session {
	// latest incarnation whose client/server match and which lacks peer ISN
	for i := len(cand) - 1; i >= 0; i-- {
		s := cand[i]
		if s.Client.equal(to) && s.Server.equal(from) && !s.otherInitSeen() {
			return s
		}
	}
	for i := len(cand) - 1; i >= 0; i-- {
		s := cand[i]
		if s.Client.equal(to) && s.Server.equal(from) {
			return s
		}
	}
	return nil
}

// pickSession chooses an incarnation. Open sessions always win over closed
// ones; if every incarnation is closed the traffic is late (recorded on the
// closest one) rather than leaking into a future reused connection.
func (e *Engine) pickSession(cand []*Session, seg *pcapio.Segment, from, to Endpoint) (*Session, int) {
	dir := -1
	matchDir := func(s *Session) int {
		switch {
		case s.Client.equal(from) && s.Server.equal(to):
			return C2S
		case s.Client.equal(to) && s.Server.equal(from):
			return S2C
		}
		return -1
	}
	var openMatch []*Session
	for i := len(cand) - 1; i >= 0; i-- {
		s := cand[i]
		d := matchDir(s)
		if d < 0 {
			continue
		}
		dir = d
		if !s.closed {
			openMatch = append(openMatch, s)
		}
	}
	if len(openMatch) > 0 {
		return scorePick(openMatch, seg, dir), dir
	}
	if len(cand) > 0 {
		// all closed: score across all candidates for late attribution
		var matched []*Session
		for _, s := range cand {
			if matchDir(s) >= 0 {
				matched = append(matched, s)
			}
		}
		dir2 := -1
		if len(matched) > 0 {
			dir2 = matchDir(matched[0])
		}
		if len(matched) > 0 {
			return scorePick(matched, seg, dir2), dir2
		}
	}
	_ = dir
	return nil, -1
}

// scorePick chooses the incarnation whose expected receive window best fits.
func scorePick(set []*Session, seg *pcapio.Segment, dir int) *Session {
	best := set[0]
	bestScore := seqScore(best, seg, dir)
	for _, s := range set[1:] {
		sc := seqScore(s, seg, dir)
		if sc < bestScore {
			bestScore, best = sc, s
		}
	}
	return best
}

func seqScore(s *Session, seg *pcapio.Segment, dir int) uint64 {
	d := s.dirs[dir]
	if d == nil || !d.isnSet {
		return 1<<63 - 1
	}
	r := d.rel(seg.Seq)
	ref := d.deliveredEnd
	if r > ref {
		return r - ref
	}
	return ref - r
}
