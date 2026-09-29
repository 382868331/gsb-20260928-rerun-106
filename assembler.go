package netforensics

import (
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
)

var (
	ErrPacketBudgetExhausted  = errors.New("packet budget exhausted")
	ErrSessionBudgetExhausted = errors.New("session budget exhausted")
	ErrStreamBudgetExhausted  = errors.New("stream byte budget exhausted")
	ErrPendingBudgetExhausted = errors.New("pending segment budget exhausted")
)

type Limits struct {
	MaxPackets      int
	MaxSessions     int
	MaxStreamBytes  int64
	MaxPendingBytes int64
}

func DefaultLimits() Limits {
	return Limits{
		MaxPackets:      1_000_000,
		MaxSessions:     10_000,
		MaxStreamBytes:  256 << 20,
		MaxPendingBytes: 16 << 20,
	}
}

type Stats struct {
	Packets       int64
	Sessions      int64
	AcceptedBytes int64
	PendingBytes  int64
	BudgetStops   int64
}

type Assembler struct {
	limits   Limits
	stats    Stats
	sessions map[SessionKey][]*Session
	lookup   map[SessionKey]*Session
	closed   map[SessionKey][]*Session
}

func NewAssembler(limits Limits) *Assembler {
	return &Assembler{
		limits:   limits,
		sessions: make(map[SessionKey][]*Session),
		lookup:   make(map[SessionKey]*Session),
		closed:   make(map[SessionKey][]*Session),
	}
}

func (a *Assembler) Stats() Stats {
	return Stats{
		Packets:       atomic.LoadInt64(&a.stats.Packets),
		Sessions:      atomic.LoadInt64(&a.stats.Sessions),
		AcceptedBytes: atomic.LoadInt64(&a.stats.AcceptedBytes),
		PendingBytes:  atomic.LoadInt64(&a.stats.PendingBytes),
		BudgetStops:   atomic.LoadInt64(&a.stats.BudgetStops),
	}
}

func (a *Assembler) Sessions() []*Session {
	var out []*Session
	for _, group := range a.sessions {
		out = append(out, group...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (a *Assembler) Ingest(p RawPacket) error {
	if a.limits.MaxPackets > 0 && int(atomic.AddInt64(&a.stats.Packets, 1)) > a.limits.MaxPackets {
		atomic.AddInt64(&a.stats.BudgetStops, 1)
		return ErrPacketBudgetExhausted
	}
	if p.Flags.SYN && !p.Flags.ACK {
		return a.startSession(p)
	}
	sess := a.lookup[p.directKey()]
	if sess == nil {
		sess = a.lookup[p.reverseKey()]
	}
	if sess == nil || sess.State == StateClosed || sess.State == StateReset {
		a.recordOrphanLate(p, sess)
		return nil
	}

	if p.Flags.SYN && p.Flags.ACK {
		sess.State = StateEstablished
		sess.ServerISN = p.Seq
		sess.addEvidence(Evidence{Kind: EvidenceHandshake, Packet: p.Index, Direction: sess.direction(p), Sequence: p.Seq, Detail: "SYN-ACK"})
	} else if p.Flags.ACK && sess.State == StateNew && p.SrcIP == sess.Key.Client.IP {
		sess.State = StateEstablished
	}
	if p.Flags.RST {
		sess.State = StateReset
		sess.End = p.Timestamp
		a.closeKey(sess.Key)
		sess.addEvidence(Evidence{Kind: EvidenceConnectionClose, Packet: p.Index, Direction: sess.direction(p), Sequence: p.Seq, Detail: "RST"})
		return nil
	}
	sess.Raw = append(sess.Raw, cloneRawPacket(p))

	var st *stream
	var direction Direction
	if p.SrcIP == sess.Key.Client.IP && p.SrcPort == sess.Key.Client.Port &&
		p.DstIP == sess.Key.Server.IP && p.DstPort == sess.Key.Server.Port {
		st, direction = sess.Client, DirectionClientToServer
	} else {
		st, direction = sess.Server, DirectionServerToClient
	}
	if err := st.ingest(p, direction, sess); err != nil {
		sess.addEvidence(Evidence{Kind: EvidenceBudgetExhausted, Packet: p.Index, Direction: direction, Sequence: p.Seq, Detail: err.Error()})
		atomic.AddInt64(&a.stats.BudgetStops, 1)
		return err
	}
	sess.Packets = append(sess.Packets, p.Index)
	if p.Flags.FIN {
		st.markFIN(p, direction, sess)
		if sess.Client.closedByFIN && sess.Server.closedByFIN {
			sess.State = StateClosed
			sess.End = p.Timestamp
			a.closeKey(sess.Key)
		}
	}
	return nil
}

func (a *Assembler) startSession(p RawPacket) error {
	key := SessionKey{
		Client: Endpoint{IP: p.SrcIP, Port: p.SrcPort},
		Server: Endpoint{IP: p.DstIP, Port: p.DstPort},
	}
	if current := a.lookup[key]; current != nil && current.State != StateClosed && current.State != StateReset {
		return nil
	}
	if a.limits.MaxSessions > 0 && int(atomic.AddInt64(&a.stats.Sessions, 1)) > a.limits.MaxSessions {
		atomic.AddInt64(&a.stats.Sessions, -1)
		atomic.AddInt64(&a.stats.BudgetStops, 1)
		return ErrSessionBudgetExhausted
	}
	sess := &Session{
		ID:        fmt.Sprintf("tcp-%06d", atomic.LoadInt64(&a.stats.Sessions)),
		Key:       key,
		ClientISN: p.Seq,
		State:     StateNew,
		Start:     p.Timestamp,
		Client:    newStream(p.Seq, a),
		Server:    newStream(0, a),
	}
	sess.Raw = append(sess.Raw, cloneRawPacket(p))
	sess.addEvidence(Evidence{Kind: EvidenceHandshake, Packet: p.Index, Direction: DirectionClientToServer, Sequence: p.Seq, Detail: "SYN"})
	a.sessions[key] = append(a.sessions[key], sess)
	a.lookup[key] = sess
	a.lookup[key.reversed()] = sess
	return nil
}

func (a *Assembler) recordOrphanLate(p RawPacket, previous *Session) {
	if len(p.Payload) == 0 && !p.Flags.SYN && !p.Flags.RST && !p.Flags.FIN {
		return
	}
	if previous == nil {
		previous = a.findClosed(p)
	}
	if previous == nil || (previous.State != StateClosed && previous.State != StateReset) {
		return
	}
	previous.addEvidence(Evidence{Kind: EvidenceLateSegment, Packet: p.Index, Direction: previous.direction(p), Sequence: p.Seq, Length: len(p.Payload), Detail: "segment after closed connection is not attached to a reused address"})
}

func (a *Assembler) findClosed(p RawPacket) *Session {
	for _, key := range []SessionKey{p.directKey(), p.reverseKey()} {
		if group := a.closed[key]; len(group) > 0 {
			return group[len(group)-1]
		}
	}
	return nil
}

func (a *Assembler) closeKey(key SessionKey) {
	delete(a.lookup, key)
	delete(a.lookup, key.reversed())
	a.closed[key] = a.sessions[key]
}

func (a *Assembler) pendingDelta(n int64) {
	atomic.AddInt64(&a.stats.PendingBytes, n)
}

func (p RawPacket) directKey() SessionKey {
	return SessionKey{Client: Endpoint{IP: p.SrcIP, Port: p.SrcPort}, Server: Endpoint{IP: p.DstIP, Port: p.DstPort}}
}

func (p RawPacket) reverseKey() SessionKey {
	return SessionKey{Client: Endpoint{IP: p.DstIP, Port: p.DstPort}, Server: Endpoint{IP: p.SrcIP, Port: p.SrcPort}}
}

func (k SessionKey) reversed() SessionKey {
	return SessionKey{Client: k.Server, Server: k.Client}
}

func (s *Session) direction(p RawPacket) Direction {
	if p.SrcIP == s.Key.Client.IP && p.SrcPort == s.Key.Client.Port {
		return DirectionClientToServer
	}
	return DirectionServerToClient
}

func (s *Session) addEvidence(e Evidence) {
	s.Evidence = append(s.Evidence, e)
}

type segment struct {
	seq    uint32
	data   []byte
	packet int
	offset int64
}

type stream struct {
	isn           uint32
	isnSet        bool
	next          uint32
	finSeq        uint32
	closedByFIN   bool
	pending       []segment
	chunks        map[int64][]byte
	gaps          []Gap
	evidenceCount map[EvidenceKind]int
	maxOffset     int64
	received      int
	a             *Assembler
}

func newStream(isn uint32, a *Assembler) *stream {
	return &stream{isn: isn, isnSet: isn != 0, next: isn + 1, chunks: make(map[int64][]byte), evidenceCount: make(map[EvidenceKind]int), a: a}
}

func (s *stream) setISN(seq uint32) {
	if !s.isnSet {
		s.isn = seq
		s.next = seq + 1
		s.isnSet = true
	}
}

func (s *stream) ingest(p RawPacket, direction Direction, sess *Session) error {
	if p.Flags.SYN && p.Flags.ACK && direction == DirectionServerToClient {
		s.setISN(p.Seq)
	}
	data := p.Payload
	if len(data) == 0 {
		return nil
	}
	if !s.isnSet {
		return nil
	}
	start := p.Seq
	end := addSeq(start, uint32(len(data)))
	relStart := rel32(s.isn+1, start)
	relEnd := int64(relStart) + int64(len(data))
	if relStart < 0 {
		cut := int(-relStart)
		if cut >= len(data) {
			return nil
		}
		start = addSeq(start, uint32(cut))
		data = data[cut:]
		relStart = 0
	}
	if seqBefore(end, s.next) || end == s.next {
		s.evidenceOverlap(sess, p, direction, data, relStart, false)
		return nil
	}
	if seqBefore(start, s.next) {
		cut := int(rel32(s.next, start))
		overlapData := data
		start = s.next
		data = data[cut:]
		relStart = int64(rel32(s.isn+1, start))
		s.evidenceOverlap(sess, p, direction, overlapData, relStart, true)
		if len(data) == 0 {
			return nil
		}
		if start != s.next {
			return nil
		}
		if err := s.acceptInOrder(sess, p, direction, start, data, relStart); err != nil {
			return err
		}
		return s.drainPending(sess, direction)
	}
	if start != s.next {
		suspension := rel32(s.next, start)
		if suspension > 0 {
			gap := Gap{Direction: direction, StartSeq: s.next, Length: int(suspension), Offset: int64(rel32(s.isn+1, s.next))}
			sess.addEvidence(Evidence{Kind: EvidenceGap, Packet: p.Index, Direction: direction, Sequence: s.next, Length: gap.Length, Offset: gap.Offset, Detail: fmt.Sprintf("missing %d bytes before sequence %d", gap.Length, start)})
		}
		if idx := s.findPending(start); idx >= 0 {
			existing := s.pending[idx].data
			detail := "duplicate out-of-order segment"
			kind := EvidenceRetransmission
			if len(existing) != len(data) || !bytesEqual(existing, data) {
				detail = "conflicting out-of-order overlap; first observed bytes retained"
				kind = EvidenceOverlapConflict
			}
			sess.addEvidence(Evidence{Kind: kind, Packet: p.Index, Direction: direction, Sequence: start, Length: len(data), Offset: relStart, Detail: detail})
			return nil
		}
		if s.a.limits.MaxPendingBytes > 0 && atomic.LoadInt64(&s.a.stats.PendingBytes)+int64(len(data)) > s.a.limits.MaxPendingBytes {
			atomic.AddInt64(&s.a.stats.BudgetStops, 1)
			return ErrPendingBudgetExhausted
		}
		s.pending = append(s.pending, segment{seq: start, data: append([]byte(nil), data...), packet: p.Index, offset: relStart})
		s.a.pendingDelta(int64(len(data)))
		sess.addEvidence(Evidence{Kind: EvidenceOutOfOrder, Packet: p.Index, Direction: direction, Sequence: start, Length: len(data), Offset: relStart})
		if relEnd > s.maxOffset {
			s.maxOffset = relEnd
		}
		return nil
	}
	if err := s.acceptInOrder(sess, p, direction, start, data, relStart); err != nil {
		return err
	}
	return s.drainPending(sess, direction)
}

func (s *stream) acceptInOrder(sess *Session, p RawPacket, direction Direction, start uint32, data []byte, relStart int64) error {
	if s.a.limits.MaxStreamBytes > 0 && int64(s.received+len(data)) > s.a.limits.MaxStreamBytes {
		atomic.AddInt64(&s.a.stats.BudgetStops, 1)
		return ErrStreamBudgetExhausted
	}
	s.chunks[relStart] = append([]byte(nil), data...)
	s.received += len(data)
	atomic.AddInt64(&s.a.stats.AcceptedBytes, int64(len(data)))
	s.next = addSeq(start, uint32(len(data)))
	if relStart+int64(len(data)) > s.maxOffset {
		s.maxOffset = relStart + int64(len(data))
	}
	return nil
}

func (s *stream) drainPending(sess *Session, direction Direction) error {
	for {
		idx := s.findPending(s.next)
		if idx < 0 {
			return nil
		}
		seg := s.pending[idx]
		s.pending = append(s.pending[:idx], s.pending[idx+1:]...)
		s.a.pendingDelta(-int64(len(seg.data)))
		relStart := int64(rel32(s.isn+1, seg.seq))
		if err := s.acceptInOrder(sess, RawPacket{Index: seg.packet, Seq: seg.seq}, direction, seg.seq, seg.data, relStart); err != nil {
			return err
		}
	}
}

func (s *stream) findPending(seq uint32) int {
	for i, seg := range s.pending {
		if seg.seq == seq {
			return i
		}
	}
	return -1
}

func (s *stream) evidenceOverlap(sess *Session, p RawPacket, direction Direction, data []byte, relStart int64, trimmed bool) {
	kind := EvidenceRetransmission
	detail := "identical retransmission"
	if trimmed {
		detail = "overlapping segment extends accepted data; suffix retained when reachable"
	}
	off := int64(rel32(s.isn+1, p.Seq))
	overlapEnd := s.next
	if seqBefore(addSeq(p.Seq, uint32(len(p.Payload))), overlapEnd) {
		overlapEnd = addSeq(p.Seq, uint32(len(p.Payload)))
	}
	overlapLen := int(rel32(p.Seq, overlapEnd))
	if overlapLen > 0 {
		old := s.bytesAt(int64(rel32(s.isn+1, p.Seq)), overlapLen)
		if old != nil && !bytesEqual(old, p.Payload[:overlapLen]) {
			kind = EvidenceOverlapConflict
			detail = "overlapping bytes differ; first observed bytes retained"
		}
	}
	sess.addEvidence(Evidence{Kind: kind, Packet: p.Index, Direction: direction, Sequence: p.Seq, Length: len(p.Payload), Offset: off, Detail: detail})
}

func cloneRawPacket(p RawPacket) RawPacket {
	clone := p
	if p.Payload != nil {
		clone.Payload = append([]byte(nil), p.Payload...)
	}
	if p.Frame != nil {
		clone.Frame = append([]byte(nil), p.Frame...)
	}
	return clone
}

func (s *stream) bytesAt(offset int64, length int) []byte {
	if offset < 0 || length <= 0 {
		return nil
	}
	out := make([]byte, 0, length)
	var offsets []int64
	for off := range s.chunks {
		offsets = append(offsets, off)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	for _, start := range offsets {
		chunk := s.chunks[start]
		if start+int64(len(chunk)) <= offset || start >= offset+int64(length) {
			continue
		}
		begin := int(offset - start)
		if begin < 0 {
			begin = 0
		}
		end := int(offset + int64(length) - start)
		if end > len(chunk) {
			end = len(chunk)
		}
		if int64(start)+int64(begin) != offset+int64(len(out)) {
			return nil
		}
		out = append(out, chunk[begin:end]...)
	}
	if len(out) != length {
		return nil
	}
	return out
}

func (s *stream) markFIN(p RawPacket, direction Direction, sess *Session) {
	s.closedByFIN = true
	s.finSeq = addSeq(p.Seq, uint32(len(p.Payload)))
	sess.addEvidence(Evidence{Kind: EvidenceConnectionClose, Packet: p.Index, Direction: direction, Sequence: p.Seq, Detail: "FIN"})
}

func (s *stream) result(direction Direction) StreamResult {
	blocks, data := s.materialize(direction)
	return StreamResult{
		Direction: direction,
		ISN:       s.isn,
		NextSeq:   s.next,
		FINSeq:    s.finSeq,
		Closed:    s.closedByFIN,
		Bytes:     data,
		Blocks:    blocks,
		Gaps:      append([]Gap(nil), s.gaps...),
		Received:  s.received,
	}
}

func (s *stream) materialize(direction Direction) ([]Block, []byte) {
	var offsets []int64
	available := make(map[int64][]byte, len(s.chunks)+len(s.pending))
	for off := range s.chunks {
		offsets = append(offsets, off)
		available[off] = s.chunks[off]
	}
	for _, seg := range s.pending {
		if _, exists := available[seg.offset]; !exists {
			offsets = append(offsets, seg.offset)
			available[seg.offset] = seg.data
		}
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	coverageEnd := int64(0)
	var blocks []Block
	var data []byte
	for _, off := range offsets {
		chunk := available[off]
		if off < coverageEnd {
			skip := int(coverageEnd - off)
			if skip >= len(chunk) {
				continue
			}
			chunk = chunk[skip:]
			off = coverageEnd
		}
		if off > coverageEnd {
			length := int(off - coverageEnd)
			blocks = append(blocks, Block{Kind: BlockGap, Length: length})
			addGapResult(&s.gaps, Gap{Direction: direction, StartSeq: addSeq(s.isn+1, uint32(coverageEnd)), Length: length, Offset: coverageEnd})
		}
		blocks = append(blocks, Block{Kind: BlockData, Data: append([]byte(nil), chunk...), Length: len(chunk)})
		data = append(data, chunk...)
		coverageEnd = off + int64(len(chunk))
	}
	if s.closedByFIN {
		finOffset := int64(rel32(s.isn+1, s.finSeq))
		if finOffset > coverageEnd {
			length := int(finOffset - coverageEnd)
			blocks = append(blocks, Block{Kind: BlockGap, Length: length})
			addGapResult(&s.gaps, Gap{Direction: direction, StartSeq: addSeq(s.isn+1, uint32(coverageEnd)), Length: length, Offset: coverageEnd})
		}
	}
	return blocks, data
}

func addSeq(a, b uint32) uint32 { return a + b }

func rel32(base, value uint32) int64 {
	delta := int32(value - base)
	return int64(delta)
}

func seqBefore(a, b uint32) bool { return int32(a-b) < 0 }

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func appendGap(gaps []Gap, gap Gap) []Gap {
	for _, existing := range gaps {
		if existing.StartSeq == gap.StartSeq && existing.Length == gap.Length {
			return gaps
		}
	}
	return append(gaps, gap)
}

func addGapResult(gaps *[]Gap, gap Gap) {
	for _, existing := range *gaps {
		if existing.Offset == gap.Offset && existing.Length == gap.Length {
			return
		}
	}
	*gaps = append(*gaps, gap)
}
