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
	EvidenceBudgetExhausted EvidenceKind = "budget_exhausted"
	EvidencePeerConfirm     EvidenceKind = "peer_confirm"
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
	Kind      EvidenceKind
	Packet    int
	Direction Direction
	Sequence  uint32
	Offset    int64
	Length    int
	Detail    string
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
	Direction Direction
	StartSeq  uint32
	Length    int
	Offset    int64
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
	Data        []byte `json:"data"`
	StartOffset int64  `json:"start_offset"`
	EndOffset   int64  `json:"end_offset"`
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
	PeerAckedRanges  []ByteRange       `json:"peer_acked_ranges,omitempty"`
	PeerAckedMissing []ByteRange       `json:"peer_acked_missing,omitempty"`
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
	return parseMessages(s.Blocks, delim)
}

func parseMessages(blocks []Block, delim byte) []Message {
	var messages []Message
	var run []byte
	runStart := int64(-1)
	flush := func() {
		start := int64(-1)
		for i, b := range run {
			position := runStart + int64(i)
			if b != delim {
				if start < 0 {
					start = position
				}
				continue
			}
			if start < 0 {
				if runStart != 0 {
					continue
				}
				start = position
			}
			messages = append(messages, Message{
				Data:        append([]byte(nil), run[start-runStart:i]...),
				StartOffset: start,
				EndOffset:   position + 1,
			})
			start = -1
		}
		run = nil
		runStart = -1
	}
	for _, block := range blocks {
		if block.Kind == BlockData {
			if runStart < 0 {
				runStart = block.Offset
			}
			if block.Offset == runStart+int64(len(run)) {
				run = append(run, block.Data...)
				continue
			}
		}
		flush()
	}
	flush()
	return messages
}

type SessionState string

const (
	StateNew         SessionState = "new"
	StateEstablished SessionState = "established"
	StateClosed      SessionState = "closed"
	StateReset       SessionState = "reset"
)

type Session struct {
	ID        string
	Key       SessionKey
	ClientISN uint32
	ServerISN uint32
	State     SessionState
	Start     time.Time
	End       time.Time
	Client    *stream
	Server    *stream
	Raw       []RawPacket
	Packets   []int
	Evidence  []Evidence
}

func (s *Session) Result(direction Direction) StreamResult {
	if direction == DirectionClientToServer {
		return s.Client.result(direction)
	}
	return s.Server.result(direction)
}
