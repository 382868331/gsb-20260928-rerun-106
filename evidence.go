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

type BlockKind int

const (
	BlockData BlockKind = iota
	BlockGap
	BlockAmbiguous
)

type Block struct {
	Kind        BlockKind
	Data        []byte
	Length      int
	StartOffset int64
	Packet      int
}

type StreamResult struct {
	Direction        Direction
	ISN              uint32
	NextSeq          uint32
	FINSeq           uint32
	Closed           bool
	Bytes            []byte
	Blocks           []Block
	Gaps             []Gap
	Received         int
	Candidates       []CandidateStream
	UncertainRanges  []ByteRange
	IncompleteRanges []IncompleteRange
}

type CandidateRule string

const (
	CandidateFirstObserved CandidateRule = "first_observed"
	CandidateLastObserved  CandidateRule = "last_observed"
)

type CandidateStream struct {
	Rule   CandidateRule
	Bytes  []byte
	Blocks []Block
}

type ByteRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"`
}

type IncompleteRange struct {
	Start  int64  `json:"start"`
	End    int64  `json:"end"`
	Reason string `json:"reason"`
}

type ApplicationMessage struct {
	Data         []byte           `json:"data"`
	StartOffset  int64            `json:"start_offset"`
	EndOffset    int64            `json:"end_offset"`
	Complete     bool             `json:"complete"`
	BlockedRange *IncompleteRange `json:"blocked_range,omitempty"`
}

func (s StreamResult) Complete() bool {
	return s.Closed && len(s.Gaps) == 0
}

func (s StreamResult) Candidate(rule CandidateRule) (CandidateStream, bool) {
	for _, candidate := range s.Candidates {
		if candidate.Rule == rule {
			return candidate, true
		}
	}
	return CandidateStream{}, false
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
