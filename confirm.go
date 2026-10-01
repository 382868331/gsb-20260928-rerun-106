package netforensics

import "fmt"

// confirmAck records that the peer (the sender of packet p) acknowledged
// bytes of this stream. The acknowledgement is evidence that the peer
// received those bytes; it never fabricates bytes that were not captured.
func (s *stream) confirmAck(sess *Session, p RawPacket, direction Direction) {
	if !p.Flags.ACK || !s.isnSet {
		return
	}
	rel := rel32(s.isn+1, p.Ack)
	if rel <= s.peerAcked {
		return
	}
	s.peerAcked = rel
	sess.addEvidence(Evidence{
		Kind:      EvidencePeerConfirm,
		Packet:    p.Index,
		Direction: direction,
		Sequence:  p.Ack,
		Offset:    rel,
		Detail:    fmt.Sprintf("peer acknowledges %d bytes of this direction; confirms receipt even where capture has gaps", rel),
	})
}

// peerAckedRanges returns the byte range the peer has acknowledged.
func (s *stream) peerAckedRanges() []ByteRange {
	if s.peerAcked <= 0 {
		return nil
	}
	return []ByteRange{{Offset: 0, Length: int(s.peerAcked)}}
}

// intersectRanges returns the overlap between two range lists, merged into
// disjoint ranges.
func intersectRanges(a, b []ByteRange) []ByteRange {
	var out []ByteRange
	for _, left := range a {
		for _, right := range b {
			start := maxInt64(left.Offset, right.Offset)
			end := minInt64(left.Offset+int64(left.Length), right.Offset+int64(right.Length))
			if end > start {
				out = appendRange(out, start, int(end-start))
			}
		}
	}
	return out
}
