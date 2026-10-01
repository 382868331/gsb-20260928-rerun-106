package netforensics

import "encoding/json"

type Snapshot struct {
	Limits   Limits         `json:"limits"`
	Stats    Stats          `json:"stats"`
	Sessions []sessionState `json:"sessions"`
}

type sessionState struct {
	Session Session     `json:"session"`
	Client  streamState `json:"client"`
	Server  streamState `json:"server"`
}

type streamState struct {
	ISN          uint32           `json:"isn"`
	ISNSet       bool             `json:"isn_set"`
	Next         uint32           `json:"next"`
	FINSeq       uint32           `json:"fin_seq"`
	ClosedByFIN  bool             `json:"closed_by_fin"`
	Pending      []segment        `json:"pending"`
	Chunks       map[int64][]byte `json:"chunks"`
	Observations []Fragment       `json:"observations"`
	Gaps         []Gap            `json:"gaps"`
	Incomplete   []ByteRange      `json:"incomplete"`
	MaxOffset    int64            `json:"max_offset"`
	Received     int              `json:"received"`
}

func (a *Assembler) Snapshot() Snapshot {
	var states []sessionState
	for _, sess := range a.Sessions() {
		states = append(states, sessionState{
			Session: *sess,
			Client:  sess.Client.state(),
			Server:  sess.Server.state(),
		})
	}
	return Snapshot{Limits: a.limits, Stats: a.Stats(), Sessions: states}
}

func (a *Assembler) SaveSnapshot() ([]byte, error) {
	return json.Marshal(a.Snapshot())
}

func NewAssemblerFromSnapshot(snap Snapshot) *Assembler {
	a := NewAssembler(snap.Limits)
	var pending int64
	for i := range snap.Sessions {
		entry := &snap.Sessions[i]
		sess := &entry.Session
		sess.Client = newStream(entry.Client.ISN, a)
		sess.Server = newStream(entry.Server.ISN, a)
		entry.Client.restore(sess.Client)
		entry.Server.restore(sess.Server)
		pending += pendingBytes(sess.Client.pending)
		pending += pendingBytes(sess.Server.pending)
		a.sessions[sess.Key] = append(a.sessions[sess.Key], sess)
		if sess.State != StateClosed && sess.State != StateReset {
			a.lookup[sess.Key] = sess
			a.lookup[sess.Key.reversed()] = sess
		} else {
			a.closed[sess.Key] = a.sessions[sess.Key]
		}
	}
	stats := snap.Stats
	stats.PendingBytes = pending
	a.stats = stats
	return a
}

func pendingBytes(segments []segment) int64 {
	var total int64
	for _, seg := range segments {
		total += int64(len(seg.Data))
	}
	return total
}

func LoadAssemblerSnapshot(data []byte) (*Assembler, error) {
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	return NewAssemblerFromSnapshot(snap), nil
}

func (s *stream) state() streamState {
	return streamState{
		ISN:          s.isn,
		ISNSet:       s.isnSet,
		Next:         s.next,
		FINSeq:       s.finSeq,
		ClosedByFIN:  s.closedByFIN,
		Pending:      append([]segment(nil), s.pending...),
		Chunks:       cloneChunks(s.chunks),
		Observations: append([]Fragment(nil), s.observations...),
		Gaps:         append([]Gap(nil), s.gaps...),
		Incomplete:   append([]ByteRange(nil), s.incomplete...),
		MaxOffset:    s.maxOffset,
		Received:     s.received,
	}
}

func (state streamState) restore(s *stream) {
	s.isn = state.ISN
	s.isnSet = state.ISNSet
	s.next = state.Next
	s.finSeq = state.FINSeq
	s.closedByFIN = state.ClosedByFIN
	s.pending = append([]segment(nil), state.Pending...)
	if state.Chunks != nil {
		s.chunks = cloneChunks(state.Chunks)
	}
	s.observations = append([]Fragment(nil), state.Observations...)
	s.gaps = append([]Gap(nil), state.Gaps...)
	s.incomplete = append([]ByteRange(nil), state.Incomplete...)
	s.maxOffset = state.MaxOffset
	s.received = state.Received
}

func cloneChunks(chunks map[int64][]byte) map[int64][]byte {
	out := make(map[int64][]byte, len(chunks))
	for offset, data := range chunks {
		out[offset] = append([]byte(nil), data...)
	}
	return out
}
