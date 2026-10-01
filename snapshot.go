package netforensics

import (
	"encoding/json"
	"time"
)

// Snapshot is a JSON-serializable copy of the full assembler state. Raw
// fragments, pending out-of-order segments, evidence and uncertainty
// bookkeeping are preserved verbatim so analysis can be saved and resumed
// later without rewriting any captured bytes.
type Snapshot struct {
	Limits   Limits            `json:"limits"`
	Stats    Stats             `json:"stats"`
	Sessions []SessionSnapshot `json:"sessions"`
}

type SessionSnapshot struct {
	ID        string         `json:"id"`
	Key       SessionKey     `json:"key"`
	ClientISN uint32         `json:"client_isn"`
	ServerISN uint32         `json:"server_isn"`
	State     SessionState   `json:"state"`
	Start     time.Time      `json:"start"`
	End       time.Time      `json:"end"`
	Client    StreamSnapshot `json:"client"`
	Server    StreamSnapshot `json:"server"`
	Raw       []RawPacket    `json:"raw"`
	Packets   []int          `json:"packets"`
	Evidence  []Evidence     `json:"evidence"`
}

type StreamSnapshot struct {
	ISN          uint32            `json:"isn"`
	ISNSet       bool              `json:"isn_set"`
	Next         uint32            `json:"next"`
	FinSeq       uint32            `json:"fin_seq"`
	ClosedByFIN  bool              `json:"closed_by_fin"`
	Pending      []SegmentSnapshot `json:"pending,omitempty"`
	Chunks       []ChunkSnapshot   `json:"chunks,omitempty"`
	Observations []Fragment        `json:"observations,omitempty"`
	Incomplete   []ByteRange       `json:"incomplete,omitempty"`
	MaxOffset    int64             `json:"max_offset"`
	Received     int               `json:"received"`
	PeerAcked    int64             `json:"peer_acked"`
}

type SegmentSnapshot struct {
	Seq    uint32 `json:"seq"`
	Data   []byte `json:"data"`
	Packet int    `json:"packet"`
	Offset int64  `json:"offset"`
}

type ChunkSnapshot struct {
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
}

// Snapshot serializes the assembler, including every open and closed
// session, so capture can resume after a save/restart cycle.
func (a *Assembler) Snapshot() ([]byte, error) {
	snap := Snapshot{
		Limits: a.limits,
		Stats:  a.Stats(),
	}
	for _, sess := range a.Sessions() {
		snap.Sessions = append(snap.Sessions, SessionSnapshot{
			ID:        sess.ID,
			Key:       sess.Key,
			ClientISN: sess.ClientISN,
			ServerISN: sess.ServerISN,
			State:     sess.State,
			Start:     sess.Start,
			End:       sess.End,
			Client:    snapshotStream(sess.Client),
			Server:    snapshotStream(sess.Server),
			Raw:       append([]RawPacket(nil), sess.Raw...),
			Packets:   append([]int(nil), sess.Packets...),
			Evidence:  append([]Evidence(nil), sess.Evidence...),
		})
	}
	return json.Marshal(snap)
}

func snapshotStream(s *stream) StreamSnapshot {
	snap := StreamSnapshot{
		ISN:          s.isn,
		ISNSet:       s.isnSet,
		Next:         s.next,
		FinSeq:       s.finSeq,
		ClosedByFIN:  s.closedByFIN,
		Observations: append([]Fragment(nil), s.observations...),
		Incomplete:   append([]ByteRange(nil), s.incomplete...),
		MaxOffset:    s.maxOffset,
		Received:     s.received,
		PeerAcked:    s.peerAcked,
	}
	for _, seg := range s.pending {
		snap.Pending = append(snap.Pending, SegmentSnapshot{Seq: seg.seq, Data: append([]byte(nil), seg.data...), Packet: seg.packet, Offset: seg.offset})
	}
	for offset, data := range s.chunks {
		snap.Chunks = append(snap.Chunks, ChunkSnapshot{Offset: offset, Data: append([]byte(nil), data...)})
	}
	return snap
}

// RestoreSnapshot rebuilds an assembler from a snapshot. Session lookup
// tables are reconstructed so ingestion continues exactly where it stopped,
// and address/port reuse still starts a new session generation.
func RestoreSnapshot(data []byte) (*Assembler, error) {
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, err
	}
	a := NewAssembler(snap.Limits)
	a.stats = snap.Stats
	for _, ss := range snap.Sessions {
		sess := &Session{
			ID:        ss.ID,
			Key:       ss.Key,
			ClientISN: ss.ClientISN,
			ServerISN: ss.ServerISN,
			State:     ss.State,
			Start:     ss.Start,
			End:       ss.End,
			Raw:       ss.Raw,
			Packets:   ss.Packets,
			Evidence:  ss.Evidence,
		}
		sess.Client = restoreStream(ss.Client, a)
		sess.Server = restoreStream(ss.Server, a)
		a.sessions[sess.Key] = append(a.sessions[sess.Key], sess)
		if sess.State == StateClosed || sess.State == StateReset {
			a.closed[sess.Key] = a.sessions[sess.Key]
		} else {
			a.lookup[sess.Key] = sess
			a.lookup[sess.Key.reversed()] = sess
		}
	}
	return a, nil
}

func restoreStream(snap StreamSnapshot, a *Assembler) *stream {
	s := &stream{
		isn:           snap.ISN,
		isnSet:        snap.ISNSet,
		next:          snap.Next,
		finSeq:        snap.FinSeq,
		closedByFIN:   snap.ClosedByFIN,
		chunks:        make(map[int64][]byte),
		observations:  snap.Observations,
		incomplete:    snap.Incomplete,
		evidenceCount: make(map[EvidenceKind]int),
		maxOffset:     snap.MaxOffset,
		received:      snap.Received,
		peerAcked:     snap.PeerAcked,
		a:             a,
	}
	for _, seg := range snap.Pending {
		s.pending = append(s.pending, segment{seq: seg.Seq, data: seg.Data, packet: seg.Packet, offset: seg.Offset})
	}
	for _, chunk := range snap.Chunks {
		s.chunks[chunk.Offset] = chunk.Data
	}
	return s
}
