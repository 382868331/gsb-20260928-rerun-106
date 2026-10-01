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
	sess.recordACK(p)

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
		ID:         fmt.Sprintf("tcp-%06d-gen-%02d", atomic.LoadInt64(&a.stats.Sessions), len(a.sessions[key])+1),
		Key:        key,
		Generation: len(a.sessions[key]) + 1,
		ClientISN:  p.Seq,
		State:      StateNew,
		Start:      p.Timestamp,
		Client:     newStream(p.Seq, a),
		Server:     newStream(0, a),
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

func (s *Session) recordACK(p RawPacket) {
	if !p.Flags.ACK {
		return
	}
	if p.SrcIP == s.Key.Client.IP && p.SrcPort == s.Key.Client.Port {
		s.Server.markACK(s, p, DirectionServerToClient, DirectionClientToServer)
		return
	}
	s.Client.markACK(s, p, DirectionClientToServer, DirectionServerToClient)
}

type segment struct {
	Seq    uint32 `json:"seq"`
	Data   []byte `json:"data"`
	Packet int    `json:"packet"`
	Offset int64  `json:"offset"`
}

type stream struct {
	isn           uint32
	isnSet        bool
	next          uint32
	finSeq        uint32
	closedByFIN   bool
	pending       []segment
	chunks        map[int64][]byte
	observations  []Fragment
	gaps          []Gap
	incomplete    []ByteRange
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
		s.observations = append(s.observations, Fragment{Packet: p.Index, Seq: start, Offset: relStart, Data: append([]byte(nil), data...)})
		s.evidenceOverlap(sess, p, direction, data, relStart, false)
		return nil
	}
	if seqBefore(start, s.next) {
		cut := int(rel32(start, s.next))
		overlapData := data
		overlapSeq := start
		overlapOffset := int64(rel32(s.isn+1, start))
		start = s.next
		data = data[cut:]
		relStart = int64(rel32(s.isn+1, start))
		if len(data) == 0 {
			s.observations = append(s.observations, Fragment{Packet: p.Index, Seq: overlapSeq, Offset: overlapOffset, Data: append([]byte(nil), overlapData...)})
			s.evidenceOverlap(sess, p, direction, overlapData, relStart, true)
			return nil
		}
		if s.a.limits.MaxStreamBytes > 0 && int64(s.received+len(data)) > s.a.limits.MaxStreamBytes {
			atomic.AddInt64(&s.a.stats.BudgetStops, 1)
			s.incomplete = appendRange(s.incomplete, relStart, len(data))
			return ErrStreamBudgetExhausted
		}
		s.observations = append(s.observations, Fragment{Packet: p.Index, Seq: overlapSeq, Offset: overlapOffset, Data: append([]byte(nil), overlapData...)})
		s.evidenceOverlap(sess, p, direction, overlapData, relStart, true)
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
			s.gaps = addGapResultList(s.gaps, gap)
			sess.addEvidence(Evidence{Kind: EvidenceGap, Packet: p.Index, Direction: direction, Sequence: s.next, Length: gap.Length, Offset: gap.Offset, Detail: fmt.Sprintf("missing %d bytes before sequence %d", gap.Length, start)})
		}
		if idx := s.findPendingOverlap(start, end); idx >= 0 {
			existing := s.pending[idx]
			overlapStart := maxRel(relStart, existing.Offset)
			overlapEnd := minRel(relStart+int64(len(data)), existing.Offset+int64(len(existing.Data)))
			overlapLength := int(overlapEnd - overlapStart)
			newPart := data[overlapStart-relStart:]
			existingPart := existing.Data[overlapStart-existing.Offset:]
			detail := "duplicate out-of-order segment"
			kind := EvidenceRetransmission
			if !bytesEqual(existingPart[:overlapLength], newPart[:overlapLength]) {
				detail = "conflicting out-of-order overlap; all observed bytes retained as candidates"
				kind = EvidenceOverlapConflict
			}
			sess.addEvidence(Evidence{Kind: kind, Packet: p.Index, Direction: direction, Sequence: start, Length: len(data), Offset: relStart, Detail: detail})
			s.observations = append(s.observations, Fragment{Packet: p.Index, Seq: start, Offset: relStart, Data: append([]byte(nil), data...)})
			return nil
		}
		if s.a.limits.MaxPendingBytes > 0 && atomic.LoadInt64(&s.a.stats.PendingBytes)+int64(len(data)) > s.a.limits.MaxPendingBytes {
			atomic.AddInt64(&s.a.stats.BudgetStops, 1)
			s.incomplete = appendRange(s.incomplete, relStart, len(data))
			return ErrPendingBudgetExhausted
		}
		s.observations = append(s.observations, Fragment{Packet: p.Index, Seq: start, Offset: relStart, Data: append([]byte(nil), data...)})
		s.pending = append(s.pending, segment{Seq: start, Data: append([]byte(nil), data...), Packet: p.Index, Offset: relStart})
		s.a.pendingDelta(int64(len(data)))
		sess.addEvidence(Evidence{Kind: EvidenceOutOfOrder, Packet: p.Index, Direction: direction, Sequence: start, Length: len(data), Offset: relStart})
		if relEnd > s.maxOffset {
			s.maxOffset = relEnd
		}
		return nil
	}
	if s.a.limits.MaxStreamBytes > 0 && int64(s.received+len(data)) > s.a.limits.MaxStreamBytes {
		atomic.AddInt64(&s.a.stats.BudgetStops, 1)
		s.incomplete = appendRange(s.incomplete, relStart, len(data))
		return ErrStreamBudgetExhausted
	}
	s.observations = append(s.observations, Fragment{Packet: p.Index, Seq: start, Offset: relStart, Data: append([]byte(nil), data...)})
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
	filled := ByteRange{Offset: relStart, Length: len(data)}
	s.gaps = subtractGapRanges(s.gaps, filled)
	s.received += len(data)
	atomic.AddInt64(&s.a.stats.AcceptedBytes, int64(len(data)))
	s.next = addSeq(start, uint32(len(data)))
	if relStart+int64(len(data)) > s.maxOffset {
		s.maxOffset = relStart + int64(len(data))
	}
	return nil
}

func (s *stream) markACK(sess *Session, p RawPacket, target, acknowledging Direction) {
	if !s.isnSet {
		return
	}
	ackedLength := rel32(s.isn+1, p.Ack)
	if ackedLength <= 0 {
		return
	}
	changed := false
	for i := range s.gaps {
		gap := &s.gaps[i]
		end := gap.Offset + int64(gap.Length)
		if !gap.Acknowledged && end <= ackedLength {
			gap.Acknowledged = true
			gap.ConfirmingPacket = p.Index
			changed = true
		}
	}
	if changed {
		sess.addEvidence(Evidence{Kind: EvidenceAckConfirmation, Packet: p.Index, Direction: target, AcknowledgingDirection: acknowledging, Sequence: p.Ack, Length: int(ackedLength), Detail: "opposite direction acknowledges bytes across a captured gap"})
	}
}

func (s *stream) drainPending(sess *Session, direction Direction) error {
	for {
		idx := s.findPendingStartingAtOrBefore(s.next)
		if idx < 0 {
			return nil
		}
		seg := s.pending[idx]
		cut := 0
		if seqBefore(seg.Seq, s.next) {
			cut = int(rel32(seg.Seq, s.next))
			prefix := seg.Data[:cut]
			s.evidenceOverlap(sess, RawPacket{Index: seg.Packet, Seq: seg.Seq, Payload: prefix}, direction, prefix, seg.Offset, cut < len(seg.Data))
			seg.Seq = s.next
			seg.Offset = int64(rel32(s.isn+1, s.next))
			seg.Data = seg.Data[cut:]
			s.pending[idx] = seg
		}
		if len(seg.Data) == 0 {
			s.pending = append(s.pending[:idx], s.pending[idx+1:]...)
			s.a.pendingDelta(-int64(cut))
			continue
		}
		s.pending = append(s.pending[:idx], s.pending[idx+1:]...)
		s.a.pendingDelta(-int64(len(seg.Data) + cut))
		if err := s.acceptInOrder(sess, RawPacket{Index: seg.Packet, Seq: seg.Seq}, direction, seg.Seq, seg.Data, seg.Offset); err != nil {
			return err
		}
	}
}

func (s *stream) findPending(seq uint32) int {
	for i, seg := range s.pending {
		if seg.Seq == seq {
			return i
		}
	}
	return -1
}

func (s *stream) findPendingOverlap(start, end uint32) int {
	for i, seg := range s.pending {
		segEnd := addSeq(seg.Seq, uint32(len(seg.Data)))
		if start == seg.Seq || (seqBefore(start, segEnd) && seqBefore(seg.Seq, end)) {
			return i
		}
	}
	return -1
}

func maxRel(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minRel(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (s *stream) findPendingStartingAtOrBefore(seq uint32) int {
	for i, seg := range s.pending {
		end := addSeq(seg.Seq, uint32(len(seg.Data)))
		if seg.Seq == seq || (seqBefore(seg.Seq, seq) && seqBefore(seq, end)) {
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
	blocks, candidates, gaps, available, uncertain, incomplete := s.materialize(direction)
	data := blocksToBytes(blocks)
	fragments := append([]Fragment(nil), s.observations...)
	sort.Slice(fragments, func(i, j int) bool {
		if fragments[i].Offset != fragments[j].Offset {
			return fragments[i].Offset < fragments[j].Offset
		}
		return fragments[i].Packet < fragments[j].Packet
	})
	return StreamResult{
		Direction:        direction,
		ISN:              s.isn,
		NextSeq:          s.next,
		FINSeq:           s.finSeq,
		Closed:           s.closedByFIN,
		Bytes:            data,
		Blocks:           blocks,
		Gaps:             gaps,
		IncompleteRanges: incomplete,
		UncertainRanges:  uncertain,
		AvailableRanges:  available,
		Fragments:        fragments,
		Candidates:       candidates,
		Received:         s.received,
	}
}

func (s *stream) materialize(direction Direction) ([]Block, []StreamCandidate, []Gap, []ByteRange, []ByteRange, []ByteRange) {
	var boundaries []int64
	for _, frag := range s.observations {
		boundaries = append(boundaries, frag.Offset, frag.Offset+int64(len(frag.Data)))
	}
	boundaries = appendDifferenceBoundaries(boundaries, s.observations)
	observedEnd := int64(0)
	declaredEnd := int64(-1)
	for _, frag := range s.observations {
		if end := frag.Offset + int64(len(frag.Data)); end > observedEnd {
			observedEnd = end
		}
	}
	for _, extra := range s.incomplete {
		boundaries = append(boundaries, extra.Offset, extra.Offset+int64(extra.Length))
		if end := extra.Offset + int64(extra.Length); end > observedEnd {
			observedEnd = end
		}
	}
	if s.closedByFIN {
		finOffset := int64(rel32(s.isn+1, s.finSeq))
		declaredEnd = finOffset
		boundaries = append(boundaries, finOffset)
	}
	boundaries = append(boundaries, 0)
	boundaries = uniqueSortedOffsets(boundaries)

	var primary []Block
	var firstBlocks, lastBlocks []Block
	gaps := append([]Gap(nil), s.gaps...)
	var covered []ByteRange
	var uncertain []ByteRange
	for i := 0; i+1 < len(boundaries); i++ {
		start, end := boundaries[i], boundaries[i+1]
		length := int(end - start)
		if length <= 0 || start < 0 || end > observedEnd {
			continue
		}
		active := fragmentsAt(s.observations, start, end)
		if len(active) == 0 && (end <= observedEnd || (declaredEnd >= 0 && end <= declaredEnd)) {
			block := Block{Kind: BlockGap, Offset: start, Length: length}
			primary = append(primary, block)
			firstBlocks = append(firstBlocks, block)
			lastBlocks = append(lastBlocks, block)
			gap := Gap{Direction: direction, StartSeq: addSeq(s.isn+1, uint32(start)), Length: length, Offset: start}
			gaps = addGapResultList(gaps, gap)
			uncertain = appendRange(uncertain, start, length)
			continue
		}
		first, last := active[0], active[0]
		for _, frag := range active[1:] {
			if frag.Packet < first.Packet {
				first = frag
			}
			if frag.Packet > last.Packet {
				last = frag
			}
		}
		firstBytes := fragmentBytes(first, start, length)
		lastBytes := fragmentBytes(last, start, length)
		firstBlocks = append(firstBlocks, Block{Kind: BlockData, Offset: start, Data: firstBytes, Length: length, Sources: []Fragment{first}})
		lastBlocks = append(lastBlocks, Block{Kind: BlockData, Offset: start, Data: lastBytes, Length: length, Sources: []Fragment{last}})
		covered = appendRange(covered, start, length)
		if bytesEqual(firstBytes, lastBytes) && allSame(active, start, length, firstBytes) {
			primary = append(primary, Block{Kind: BlockData, Offset: start, Data: append([]byte(nil), firstBytes...), Length: length, Sources: append([]Fragment(nil), active...)})
		} else {
			values := distinctValues(active, start, length)
			primary = append(primary, Block{Kind: BlockConflict, Offset: start, Data: append([]byte(nil), firstBytes...), Length: length, Alternatives: values, Sources: append([]Fragment(nil), active...)})
			uncertain = appendRange(uncertain, start, length)
		}
	}
	candidates := []StreamCandidate{
		{Rule: CandidateFirstObserved, Bytes: blocksToBytes(firstBlocks), Blocks: firstBlocks},
		{Rule: CandidateLastObserved, Bytes: blocksToBytes(lastBlocks), Blocks: lastBlocks},
	}
	incomplete := append(append([]ByteRange(nil), gapsToRanges(gaps)...), s.incomplete...)
	return primary, candidates, gaps, mergeRanges(covered), mergeRanges(uncertain), mergeRanges(incomplete)
}

func uniqueSortedOffsets(values []int64) []int64 {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func appendDifferenceBoundaries(boundaries []int64, fragments []Fragment) []int64 {
	for i := 0; i < len(fragments); i++ {
		for j := i + 1; j < len(fragments); j++ {
			left, right := fragments[i], fragments[j]
			start := maxInt64(left.Offset, right.Offset)
			end := minInt64(left.Offset+int64(len(left.Data)), right.Offset+int64(len(right.Data)))
			different := false
			for pos := start; pos < end; pos++ {
				valueDifferent := left.Data[pos-left.Offset] != right.Data[pos-right.Offset]
				if valueDifferent != different {
					boundaries = append(boundaries, pos)
					if different {
						boundaries = append(boundaries, pos)
					}
					different = valueDifferent
				}
			}
			if different {
				boundaries = append(boundaries, end)
			}
		}
	}
	return boundaries
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func fragmentsAt(fragments []Fragment, start, end int64) []Fragment {
	var out []Fragment
	for _, frag := range fragments {
		if frag.Offset <= start && frag.Offset+int64(len(frag.Data)) >= end {
			out = append(out, frag)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packet < out[j].Packet })
	return out
}

func fragmentBytes(frag Fragment, start int64, length int) []byte {
	begin := int(start - frag.Offset)
	return append([]byte(nil), frag.Data[begin:begin+length]...)
}

func allSame(fragments []Fragment, start int64, length int, want []byte) bool {
	for _, frag := range fragments {
		if !bytesEqual(fragmentBytes(frag, start, length), want) {
			return false
		}
	}
	return true
}

func distinctValues(fragments []Fragment, start int64, length int) [][]byte {
	var values [][]byte
	for _, frag := range fragments {
		value := fragmentBytes(frag, start, length)
		found := false
		for _, existing := range values {
			if bytesEqual(existing, value) {
				found = true
				break
			}
		}
		if !found {
			values = append(values, value)
		}
	}
	return values
}

func appendRange(ranges []ByteRange, start int64, length int) []ByteRange {
	return mergeRanges(append(ranges, ByteRange{Offset: start, Length: length}))
}

func mergeRanges(ranges []ByteRange) []ByteRange {
	if len(ranges) < 2 {
		return ranges
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].Offset < ranges[j].Offset })
	out := []ByteRange{ranges[0]}
	for _, current := range ranges[1:] {
		last := &out[len(out)-1]
		if current.Offset <= last.Offset+int64(last.Length) {
			if end := current.Offset + int64(current.Length); end > last.Offset+int64(last.Length) {
				last.Length = int(end - last.Offset)
			}
			continue
		}
		out = append(out, current)
	}
	return out
}

func gapsToRanges(gaps []Gap) []ByteRange {
	var ranges []ByteRange
	for _, gap := range gaps {
		ranges = append(ranges, ByteRange{Offset: gap.Offset, Length: gap.Length})
	}
	return mergeRanges(ranges)
}

func blocksToBytes(blocks []Block) []byte {
	var data []byte
	for _, block := range blocks {
		if block.Kind != BlockGap {
			data = append(data, block.Data...)
		}
	}
	return data
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

func addGapResultList(gaps []Gap, gap Gap) []Gap {
	for _, existing := range gaps {
		if existing.Offset == gap.Offset && existing.Length == gap.Length {
			return gaps
		}
	}
	return append(gaps, gap)
}

func subtractGapRanges(gaps []Gap, filled ByteRange) []Gap {
	var out []Gap
	fillEnd := filled.Offset + int64(filled.Length)
	for _, gap := range gaps {
		end := gap.Offset + int64(gap.Length)
		if end <= filled.Offset || gap.Offset >= fillEnd {
			out = append(out, gap)
			continue
		}
		if filled.Offset <= gap.Offset && fillEnd >= end {
			continue
		}
		if gap.Offset < filled.Offset {
			out = append(out, Gap{Direction: gap.Direction, StartSeq: gap.StartSeq, Length: int(filled.Offset - gap.Offset), Offset: gap.Offset, Acknowledged: gap.Acknowledged, ConfirmingPacket: gap.ConfirmingPacket})
		}
		if end > fillEnd {
			out = append(out, Gap{Direction: gap.Direction, StartSeq: addSeq(gap.StartSeq, uint32(fillEnd-gap.Offset)), Length: int(end - fillEnd), Offset: fillEnd, Acknowledged: gap.Acknowledged, ConfirmingPacket: gap.ConfirmingPacket})
		}
	}
	return out
}

func addGapResult(gaps *[]Gap, gap Gap) {
	for _, existing := range *gaps {
		if existing.Offset == gap.Offset && existing.Length == gap.Length {
			return
		}
	}
	*gaps = append(*gaps, gap)
}
