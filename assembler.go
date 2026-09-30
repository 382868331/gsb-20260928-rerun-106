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
	fragments     []fragment
	gaps          []Gap
	evidenceCount map[EvidenceKind]int
	maxOffset     int64
	received      int
	a             *Assembler
}

func newStream(isn uint32, a *Assembler) *stream {
	return &stream{isn: isn, isnSet: isn != 0, next: isn + 1, evidenceCount: make(map[EvidenceKind]int), a: a}
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
	if relStart < 0 {
		cut := int(-relStart)
		if cut >= len(data) {
			return nil
		}
		start = addSeq(start, uint32(cut))
		data = data[cut:]
		relStart = 0
	}
	s.addFragment(p.Index, start, data, relStart)
	if seqBefore(end, s.next) || end == s.next {
		s.evidenceOverlap(sess, p, direction, relStart, false)
		return nil
	}
	if seqBefore(start, s.next) {
		cut := len(data)
		if overlapLen := int(rel32(start, s.next)); overlapLen < cut {
			cut = overlapLen
		}
		start = s.next
		data = data[cut:]
		relStart = int64(rel32(s.isn+1, start))
		s.evidenceOverlap(sess, p, direction, relStart-int64(cut), true)
		if len(data) == 0 {
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
		uncovered := s.uncoveredPending(sess, p, direction, start, data, relStart)
		if len(uncovered) == 0 {
			return nil
		}
		addedPending := 0
		for _, piece := range uncovered {
			addedPending += len(piece.data)
		}
		if s.a.limits.MaxPendingBytes > 0 && atomic.LoadInt64(&s.a.stats.PendingBytes)+int64(addedPending) > s.a.limits.MaxPendingBytes {
			atomic.AddInt64(&s.a.stats.BudgetStops, 1)
			return ErrPendingBudgetExhausted
		}
		for _, piece := range uncovered {
			s.pending = append(s.pending, piece)
			s.a.pendingDelta(int64(len(piece.data)))
			sess.addEvidence(Evidence{Kind: EvidenceOutOfOrder, Packet: p.Index, Direction: direction, Sequence: piece.seq, Length: len(piece.data), Offset: piece.offset})
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
	s.received += len(data)
	atomic.AddInt64(&s.a.stats.AcceptedBytes, int64(len(data)))
	s.next = addSeq(start, uint32(len(data)))
	if relStart+int64(len(data)) > s.maxOffset {
		s.maxOffset = relStart + int64(len(data))
	}
	return nil
}

type fragment struct {
	seq    uint32
	data   []byte
	packet int
	offset int64
}

func (s *stream) addFragment(packet int, seq uint32, data []byte, offset int64) {
	if len(data) == 0 || offset < 0 {
		return
	}
	s.fragments = append(s.fragments, fragment{
		seq:    seq,
		data:   append([]byte(nil), data...),
		packet: packet,
		offset: offset,
	})
	end := offset + int64(len(data))
	if end > s.maxOffset {
		s.maxOffset = end
	}
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

func (s *stream) uncoveredPending(sess *Session, p RawPacket, direction Direction, start uint32, data []byte, relStart int64) []segment {
	pieces := []segment{{seq: start, data: append([]byte(nil), data...), packet: p.Index, offset: relStart}}
	for _, existing := range s.pending {
		var next []segment
		for _, piece := range pieces {
			pieceStart := piece.offset
			pieceEnd := piece.offset + int64(len(piece.data))
			existingStart := existing.offset
			existingEnd := existing.offset + int64(len(existing.data))
			overlapStart := pieceStart
			if existingStart > overlapStart {
				overlapStart = existingStart
			}
			overlapEnd := pieceEnd
			if existingEnd < overlapEnd {
				overlapEnd = existingEnd
			}
			if overlapStart >= overlapEnd {
				next = append(next, piece)
				continue
			}
			overlapLen := int(overlapEnd - overlapStart)
			newPart := piece.data[overlapStart-pieceStart : overlapStart-pieceStart+int64(overlapLen)]
			oldPart := existing.data[overlapStart-existingStart : overlapStart-existingStart+int64(overlapLen)]
			kind := EvidenceRetransmission
			detail := "duplicate out-of-order segment"
			if !bytesEqual(oldPart, newPart) {
				kind = EvidenceOverlapConflict
				detail = "conflicting out-of-order overlap; all observed fragments retained"
			}
			sess.addEvidence(Evidence{Kind: kind, Packet: p.Index, Direction: direction, Sequence: addSeq(piece.seq, uint32(overlapStart-pieceStart)), Length: overlapLen, Offset: overlapStart, Detail: detail})
			if overlapStart > pieceStart {
				next = append(next, segment{seq: piece.seq, data: piece.data[:overlapStart-pieceStart], packet: piece.packet, offset: pieceStart})
			}
			if overlapEnd < pieceEnd {
				skip := int(overlapEnd - pieceStart)
				next = append(next, segment{seq: addSeq(piece.seq, uint32(skip)), data: piece.data[skip:], packet: piece.packet, offset: overlapEnd})
			}
		}
		pieces = next
	}
	return pieces
}

func (s *stream) evidenceOverlap(sess *Session, p RawPacket, direction Direction, _ int64, trimmed bool) {
	kind := EvidenceRetransmission
	detail := "identical retransmission"
	if trimmed {
		detail = "overlapping segment extends accepted data; suffix retained when reachable"
	}
	overlapEnd := s.next
	if seqBefore(addSeq(p.Seq, uint32(len(p.Payload))), overlapEnd) {
		overlapEnd = addSeq(p.Seq, uint32(len(p.Payload)))
	}
	overlapLen := int(rel32(p.Seq, overlapEnd))
	pOffset := int64(rel32(s.isn+1, p.Seq))
	overlapOffset := pOffset
	candidateSkip := 0
	if overlapOffset < 0 {
		candidateSkip = int(-overlapOffset)
		overlapLen -= candidateSkip
		overlapOffset = 0
	}
	if overlapLen > 0 {
		candidate := p.Payload[candidateSkip : candidateSkip+overlapLen]
		if !s.rangeMatchesAccepted(overlapOffset, overlapLen, candidate) {
			kind = EvidenceOverlapConflict
			detail = "overlapping bytes differ; all observed fragments retained as candidates"
		}
	}
	sess.addEvidence(Evidence{Kind: kind, Packet: p.Index, Direction: direction, Sequence: addSeq(p.Seq, uint32(candidateSkip)), Length: overlapLen, Offset: overlapOffset, Detail: detail})
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

func (s *stream) rangeMatchesAccepted(offset int64, length int, want []byte) bool {
	if offset < 0 || length <= 0 || len(want) < length {
		return false
	}
	for pos := offset; pos < offset+int64(length); pos++ {
		first, _, ok := s.acceptedByteAt(pos)
		if !ok {
			return true
		}
		if first != want[int(pos-offset)] {
			return false
		}
	}
	return true
}

func (s *stream) acceptedByteAt(offset int64) (byte, fragment, bool) {
	var zero fragment
	if offset < 0 || offset >= int64(s.received) {
		return 0, zero, false
	}
	var found fragment
	acceptedEnd := int64(rel32(s.isn+1, s.next))
	for _, frag := range s.fragments {
		if frag.offset < acceptedEnd && offset >= frag.offset && offset < frag.offset+int64(len(frag.data)) {
			found = frag
			break
		}
	}
	if found.data == nil {
		return 0, zero, false
	}
	return found.data[offset-found.offset], found, true
}

func (s *stream) firstByteAt(offset int64) (byte, fragment, bool) {
	var zero fragment
	var found fragment
	have := false
	for _, frag := range s.fragments {
		if offset >= frag.offset && offset < frag.offset+int64(len(frag.data)) {
			if !have {
				found = frag
				have = true
			}
		}
	}
	if !have {
		return 0, zero, false
	}
	return found.data[offset-found.offset], found, true
}

func (s *stream) lastByteAt(offset int64) (byte, fragment, bool) {
	var zero fragment
	var found fragment
	have := false
	for i := len(s.fragments) - 1; i >= 0; i-- {
		frag := s.fragments[i]
		if offset >= frag.offset && offset < frag.offset+int64(len(frag.data)) {
			found = frag
			have = true
			break
		}
	}
	if !have {
		return 0, zero, false
	}
	return found.data[offset-found.offset], found, true
}

func (s *stream) markFIN(p RawPacket, direction Direction, sess *Session) {
	s.closedByFIN = true
	s.finSeq = addSeq(p.Seq, uint32(len(p.Payload)))
	sess.addEvidence(Evidence{Kind: EvidenceConnectionClose, Packet: p.Index, Direction: direction, Sequence: p.Seq, Detail: "FIN"})
}

func (s *stream) result(direction Direction) StreamResult {
	blocks, data, gaps, uncertain := s.materialize(direction)
	first := s.candidate(CandidateFirstObserved)
	last := s.candidate(CandidateLastObserved)
	incomplete := append([]IncompleteRange(nil), gapsAsIncomplete(gaps)...)
	return StreamResult{
		Direction:        direction,
		ISN:              s.isn,
		NextSeq:          s.next,
		FINSeq:           s.finSeq,
		Closed:           s.closedByFIN,
		Bytes:            data,
		Blocks:           blocks,
		Gaps:             gaps,
		Received:         s.received,
		Candidates:       []CandidateStream{first, last},
		UncertainRanges:  uncertain,
		IncompleteRanges: incomplete,
	}
}

func (s *stream) materialize(direction Direction) ([]Block, []byte, []Gap, []ByteRange) {
	end := s.maxOffset
	if s.closedByFIN {
		finOffset := int64(rel32(s.isn+1, s.finSeq))
		if finOffset > end {
			end = finOffset
		}
	}
	var blocks []Block
	var data []byte
	var gaps []Gap
	var uncertain []ByteRange
	appendRun := func(kind BlockKind, start, stop int, value byte, packet int) {
		length := stop - start
		if length <= 0 {
			return
		}
		off := int64(start)
		block := Block{Kind: kind, Length: length, StartOffset: off, Packet: packet}
		if kind != BlockGap {
			block.Data = bytesRepeat(value, length)
			data = append(data, block.Data...)
		}
		if len(blocks) > 0 {
			last := &blocks[len(blocks)-1]
			if last.Kind == kind && (kind == BlockGap || last.Packet == packet) && last.StartOffset+int64(last.Length) == off {
				last.Length += length
				if kind != BlockGap {
					last.Data = append(last.Data, block.Data...)
				}
				return
			}
		}
		blocks = append(blocks, block)
	}
	appendRange := func(ranges *[]ByteRange, start, stop int) {
		if start >= stop {
			return
		}
		if n := len(*ranges); n > 0 && (*ranges)[n-1].End == int64(start) {
			(*ranges)[n-1].End = int64(stop)
			return
		}
		*ranges = append(*ranges, ByteRange{Start: int64(start), End: int64(stop)})
	}
	for pos := int64(0); pos < end; pos++ {
		first, firstFrag, ok := s.firstByteAt(pos)
		if !ok {
			if n := len(blocks); n > 0 && blocks[n-1].Kind == BlockGap && blocks[n-1].StartOffset+int64(blocks[n-1].Length) == pos {
				blocks[n-1].Length++
			} else {
				blocks = append(blocks, Block{Kind: BlockGap, Length: 1, StartOffset: pos, Packet: -1})
			}
			if n := len(gaps); n > 0 && gaps[n-1].Offset+int64(gaps[n-1].Length) == pos {
				gaps[n-1].Length++
			} else {
				gaps = append(gaps, Gap{StartSeq: addSeq(s.isn+1, uint32(pos)), Length: 1, Offset: pos})
			}
			continue
		}
		last, _, _ := s.lastByteAt(pos)
		if first == last && s.uniqueAt(pos) {
			appendRun(BlockData, int(pos), int(pos)+1, first, firstFrag.packet)
		} else {
			appendRun(BlockAmbiguous, int(pos), int(pos)+1, first, firstFrag.packet)
			appendRange(&uncertain, int(pos), int(pos)+1)
		}
	}
	for i := range gaps {
		gaps[i].Direction = direction
	}
	return blocks, data, gaps, uncertain
}

func (s *stream) uniqueAt(offset int64) bool {
	var value byte
	have := false
	for _, frag := range s.fragments {
		if offset < frag.offset || offset >= frag.offset+int64(len(frag.data)) {
			continue
		}
		b := frag.data[offset-frag.offset]
		if !have {
			value = b
		} else if b != value {
			return false
		}
		have = true
	}
	return have
}

func gapsAsIncomplete(gaps []Gap) []IncompleteRange {
	out := make([]IncompleteRange, 0, len(gaps))
	for _, gap := range gaps {
		out = append(out, IncompleteRange{Start: gap.Offset, End: gap.Offset + int64(gap.Length), Reason: "missing data"})
	}
	return out
}

func (s *stream) candidate(rule CandidateRule) CandidateStream {
	end := s.maxOffset
	if s.closedByFIN {
		finOffset := int64(rel32(s.isn+1, s.finSeq))
		if finOffset > end {
			end = finOffset
		}
	}
	out := CandidateStream{Rule: rule}
	var data []byte
	for pos := int64(0); pos < end; pos++ {
		var b byte
		var frag fragment
		var ok bool
		if rule == CandidateFirstObserved {
			b, frag, ok = s.firstByteAt(pos)
		} else {
			b, frag, ok = s.lastByteAt(pos)
		}
		if !ok {
			if n := len(out.Blocks); n > 0 && out.Blocks[n-1].Kind == BlockGap && out.Blocks[n-1].StartOffset+int64(out.Blocks[n-1].Length) == pos {
				out.Blocks[n-1].Length++
			} else {
				out.Blocks = append(out.Blocks, Block{Kind: BlockGap, Length: 1, StartOffset: pos, Packet: -1})
			}
			continue
		}
		data = append(data, b)
		if n := len(out.Blocks); n > 0 && out.Blocks[n-1].Kind == BlockData && out.Blocks[n-1].Packet == frag.packet && out.Blocks[n-1].StartOffset+int64(out.Blocks[n-1].Length) == pos {
			out.Blocks[n-1].Length++
			out.Blocks[n-1].Data = append(out.Blocks[n-1].Data, b)
		} else {
			out.Blocks = append(out.Blocks, Block{Kind: BlockData, Length: 1, StartOffset: pos, Packet: frag.packet, Data: []byte{b}})
		}
	}
	out.Bytes = data
	return out
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
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
