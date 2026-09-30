package netforensics

import (
	"encoding/json"
	"time"
)

type assemblerSnapshot struct {
	Limits   Limits            `json:"limits"`
	Stats    Stats             `json:"stats"`
	Sessions []sessionSnapshot `json:"sessions"`
}

type sessionSnapshot struct {
	ID        string         `json:"id"`
	Key       SessionKey     `json:"key"`
	ClientISN uint32         `json:"client_isn"`
	ServerISN uint32         `json:"server_isn"`
	State     SessionState   `json:"state"`
	Start     time.Time      `json:"start"`
	End       time.Time      `json:"end"`
	Client    streamSnapshot `json:"client"`
	Server    streamSnapshot `json:"server"`
	Raw       []RawPacket    `json:"raw"`
	Packets   []int          `json:"packets"`
	Evidence  []Evidence     `json:"evidence"`
}

type streamSnapshot struct {
	ISN         uint32             `json:"isn"`
	ISNSet      bool               `json:"isn_set"`
	Next        uint32             `json:"next"`
	FINSeq      uint32             `json:"fin_seq"`
	ClosedByFIN bool               `json:"closed_by_fin"`
	Pending     []segmentSnapshot  `json:"pending"`
	Fragments   []fragmentSnapshot `json:"fragments"`
	Gaps        []Gap              `json:"gaps"`
	MaxOffset   int64              `json:"max_offset"`
	Received    int                `json:"received"`
}

type segmentSnapshot struct {
	Seq    uint32 `json:"seq"`
	Data   []byte `json:"data"`
	Packet int    `json:"packet"`
	Offset int64  `json:"offset"`
}

type fragmentSnapshot struct {
	Seq    uint32 `json:"seq"`
	Data   []byte `json:"data"`
	Packet int    `json:"packet"`
	Offset int64  `json:"offset"`
}

func (a *Assembler) Export() ([]byte, error) {
	snap := assemblerSnapshot{Limits: a.limits, Stats: a.stats, Sessions: make([]sessionSnapshot, 0, len(a.Sessions()))}
	for _, sess := range a.Sessions() {
		snap.Sessions = append(snap.Sessions, sessionSnapshot{
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

func snapshotStream(st *stream) streamSnapshot {
	out := streamSnapshot{
		ISN:         st.isn,
		ISNSet:      st.isnSet,
		Next:        st.next,
		FINSeq:      st.finSeq,
		ClosedByFIN: st.closedByFIN,
		Gaps:        append([]Gap(nil), st.gaps...),
		MaxOffset:   st.maxOffset,
		Received:    st.received,
	}
	for _, seg := range st.pending {
		out.Pending = append(out.Pending, segmentSnapshot{Seq: seg.seq, Data: append([]byte(nil), seg.data...), Packet: seg.packet, Offset: seg.offset})
	}
	for _, frag := range st.fragments {
		out.Fragments = append(out.Fragments, fragmentSnapshot{Seq: frag.seq, Data: append([]byte(nil), frag.data...), Packet: frag.packet, Offset: frag.offset})
	}
	return out
}

func ImportAssembler(data []byte) (*Assembler, error) {
	var snap assemblerSnapshot
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
			Raw:       append([]RawPacket(nil), ss.Raw...),
			Packets:   append([]int(nil), ss.Packets...),
			Evidence:  append([]Evidence(nil), ss.Evidence...),
		}
		sess.Client = restoreStream(ss.Client, a)
		sess.Server = restoreStream(ss.Server, a)
		a.sessions[sess.Key] = append(a.sessions[sess.Key], sess)
		if sess.State != StateClosed && sess.State != StateReset {
			a.lookup[sess.Key] = sess
			a.lookup[sess.Key.reversed()] = sess
		} else {
			a.closed[sess.Key] = append(a.closed[sess.Key], sess)
		}
	}
	return a, nil
}

func restoreStream(ss streamSnapshot, a *Assembler) *stream {
	st := &stream{
		isn:           ss.ISN,
		isnSet:        ss.ISNSet,
		next:          ss.Next,
		finSeq:        ss.FINSeq,
		closedByFIN:   ss.ClosedByFIN,
		gaps:          append([]Gap(nil), ss.Gaps...),
		maxOffset:     ss.MaxOffset,
		received:      ss.Received,
		evidenceCount: make(map[EvidenceKind]int),
		a:             a,
	}
	for _, seg := range ss.Pending {
		st.pending = append(st.pending, segment{seq: seg.Seq, data: append([]byte(nil), seg.Data...), packet: seg.Packet, offset: seg.Offset})
	}
	for _, frag := range ss.Fragments {
		st.fragments = append(st.fragments, fragment{seq: frag.Seq, data: append([]byte(nil), frag.Data...), packet: frag.Packet, offset: frag.Offset})
	}
	return st
}
