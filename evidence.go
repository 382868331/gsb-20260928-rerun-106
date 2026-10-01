package netforensics

import "time"

type Direction string

const (
	DirectionClientToServer Direction = "c2s"
	DirectionServerToClient Direction = "s2c"
)

type EvidenceKind string

const (
	EvidenceOutOfOrder      EvidenceKind = "out_of_order"
	EvidenceRetransmission  EvidenceKind = "retransmission"
	EvidenceOverlapConflict EvidenceKind = "overlap_conflict"
	EvidenceLateSegment     EvidenceKind = "late_segment"
	EvidenceGap             EvidenceKind = "gap"
	EvidenceAckConfirmation EvidenceKind = "ack_confirmation"
	EvidenceBudgetExhausted EvidenceKind = "budget_exhausted"
	EvidenceHandshake       EvidenceKind = "handshake"
	EvidenceConnectionClose EvidenceKind = "connection_close"
)

type RawPacket struct {
	Index       int
	Timestamp   time.Time
	CaptureLen  int
	OriginalLen int
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	Seq         uint32
	Ack         uint32
	Flags       TCPFlags
	IPID        uint16
	TTL         uint8
	Window      uint16
	Payload     []byte
	Frame       []byte
}

type TCPFlags struct {
	FIN bool
	SYN bool
	RST bool
	PSH bool
	ACK bool
	URG bool
}

func (f TCPFlags) String() string {
	var b [6]byte
	i := 0
	if f.URG {
		b[i] = 'U'
		i++
	}
	if f.ACK {
		b[i] = 'A'
		i++
	}
	if f.PSH {
		b[i] = 'P'
		i++
	}
	if f.RST {
		b[i] = 'R'
		i++
	}
	if f.SYN {
		b[i] = 'S'
		i++
	}
	if f.FIN {
		b[i] = 'F'
		i++
	}
	return string(b[:i])
}

type Evidence struct {
	Kind                   EvidenceKind `json:"kind"`
	Packet                 int          `json:"packet"`
	Direction              Direction    `json:"direction"`
	AcknowledgingDirection Direction    `json:"acknowledging_direction,omitempty"`
	Sequence               uint32       `json:"sequence"`
	Offset                 int64        `json:"offset"`
	Length                 int          `json:"length"`
	Detail                 string       `json:"detail,omitempty"`
}

type Endpoint struct {
	IP   string
	Port uint16
}

func (e Endpoint) String() string {
	return joinHostPort(e.IP, e.Port)
}

type SessionKey struct {
	Client Endpoint
	Server Endpoint
}

func (k SessionKey) String() string {
	return k.Client.String() + " -> " + k.Server.String()
}

type Gap struct {
	Direction        Direction `json:"direction"`
	StartSeq         uint32    `json:"start_seq"`
	Length           int       `json:"length"`
	Offset           int64     `json:"offset"`
	Acknowledged     bool      `json:"acknowledged,omitempty"`
	ConfirmingPacket int       `json:"confirming_packet,omitempty"`
}

type ByteRange struct {
	Offset int64 `json:"offset"`
	Length int   `json:"length"`
}

type Fragment struct {
	Packet int    `json:"packet"`
	Seq    uint32 `json:"seq"`
	Offset int64  `json:"offset"`
	Data   []byte `json:"data"`
}

type BlockKind int

const (
	BlockData BlockKind = iota
	BlockGap
	BlockConflict
)

type Block struct {
	Kind         BlockKind  `json:"kind"`
	Data         []byte     `json:"data,omitempty"`
	Length       int        `json:"length"`
	Offset       int64      `json:"offset"`
	Alternatives [][]byte   `json:"alternatives,omitempty"`
	Sources      []Fragment `json:"sources,omitempty"`
}

const (
	CandidateFirstObserved = "first_observed"
	CandidateLastObserved  = "last_observed"
)

type StreamCandidate struct {
	Rule   string  `json:"rule"`
	Bytes  []byte  `json:"bytes"`
	Blocks []Block `json:"blocks"`
}

type Message struct {
	Data             []byte      `json:"data"`
	StartOffset      int64       `json:"start_offset"`
	EndOffset        int64       `json:"end_offset"`
	Sources          []Fragment  `json:"sources,omitempty"`
	UnresolvedRanges []ByteRange `json:"unresolved_ranges,omitempty"`
}

type Interpretation struct {
	Direction        Direction   `json:"direction"`
	Rule             string      `json:"rule"`
	Blocks           []Block     `json:"blocks"`
	Messages         []Message   `json:"messages"`
	AdoptedRanges    []ByteRange `json:"adopted_ranges"`
	UnresolvedRanges []ByteRange `json:"unresolved_ranges"`
}

type StreamResult struct {
	Direction        Direction         `json:"direction"`
	ISN              uint32            `json:"isn"`
	NextSeq          uint32            `json:"next_seq"`
	FINSeq           uint32            `json:"fin_seq"`
	Closed           bool              `json:"closed"`
	Bytes            []byte            `json:"bytes"`
	Blocks           []Block           `json:"blocks"`
	Gaps             []Gap             `json:"gaps"`
	IncompleteRanges []ByteRange       `json:"incomplete_ranges"`
	UncertainRanges  []ByteRange       `json:"uncertain_ranges"`
	AvailableRanges  []ByteRange       `json:"available_ranges"`
	Fragments        []Fragment        `json:"fragments"`
	Candidates       []StreamCandidate `json:"candidates"`
	Received         int               `json:"received"`
}

func (s StreamResult) Complete() bool {
	return s.Closed && len(s.Gaps) == 0 && len(s.UncertainRanges) == 0
}

func (s StreamResult) Candidate(rule string) (StreamCandidate, bool) {
	for _, candidate := range s.Candidates {
		if candidate.Rule == rule {
			return candidate, true
		}
	}
	return StreamCandidate{}, false
}

func (s StreamResult) Messages(delim byte) []Message {
	blocks := append([]Block(nil), s.Blocks...)
	for i := range blocks {
		if blocks[i].Kind == BlockData && len(blocks[i].Sources) == 0 {
			blocks[i].Sources = fragmentsCovering(s.Fragments, blocks[i].Offset, blocks[i].Length)
		}
	}
	return messagesFromBlocks(blocks, delim)
}

func fragmentsCovering(fragments []Fragment, start int64, length int) []Fragment {
	var out []Fragment
	end := start + int64(length)
	for _, frag := range fragments {
		if frag.Offset <= start && frag.Offset+int64(len(frag.Data)) >= end {
			out = append(out, frag)
		}
	}
	return out
}

type SessionState string

const (
	StateNew         SessionState = "new"
	StateEstablished SessionState = "established"
	StateClosed      SessionState = "closed"
	StateReset       SessionState = "reset"
)

type Session struct {
	ID         string       `json:"id"`
	Key        SessionKey   `json:"key"`
	Generation int          `json:"generation"`
	ClientISN  uint32       `json:"client_isn"`
	ServerISN  uint32       `json:"server_isn"`
	State      SessionState `json:"state"`
	Start      time.Time    `json:"start"`
	End        time.Time    `json:"end"`
	Client     *stream      `json:"-"`
	Server     *stream      `json:"-"`
	Raw        []RawPacket  `json:"raw_packets"`
	Packets    []int        `json:"packets"`
	Evidence   []Evidence   `json:"evidence"`
}

func (s *Session) Result(direction Direction) StreamResult {
	if direction == DirectionClientToServer {
		return s.Client.result(direction)
	}
	return s.Server.result(direction)
}
