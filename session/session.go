// Package session turns an ordered stream of captured TCP segments into
// bidirectional conversation objects with full forensic evidence.
//
// It never invents data: missing sequence ranges are reported as explicit
// gaps instead of being zero-filled, and segments arriving after a
// connection has closed are recorded as late evidence instead of being
// spliced into a later connection that reuses the same addresses.
package session

import (
	"fmt"
	"net"
)

// Endpoint is one TCP endpoint.
type Endpoint struct {
	IP   net.IP
	Port uint16
}

func (ep Endpoint) String() string {
	return fmt.Sprintf("%s:%d", ep.IP, ep.Port)
}

// Direction constants.
const (
	C2S = 0 // client (connection initiator) -> server
	S2C = 1 // server -> client
)

// DirName returns "c2s" or "s2c".
func DirName(dir int) string {
	if dir == C2S {
		return "c2s"
	}
	return "s2c"
}

// ConflictKind distinguishes retransmits from disagreeing overlaps.
type ConflictKind int

const (
	KindRetransmit ConflictKind = iota // identical bytes seen again
	KindOverwrite                      // overlapping bytes disagree
)

// Conflict is evidence of an overlapping sequence range.
type Conflict struct {
	Dir           int
	FrameIndex    int
	Start, End    uint64 // relative sequence coordinates
	OverlapAt     uint64
	Existing, New byte
	Kind          ConflictKind
	Resolution    string // "kept-first" or "kept-original"
}

// DropEvent records a frame rejected by the resource budget or state rules.
type DropEvent struct {
	FrameIndex int
	Dir        int
	Reason     string
}

// Gap is a missing, never-recovered sequence range.
type Gap struct {
	Dir        int
	Start, End uint64
}

// FrameEvidence keeps every segment attributed to a session together with
// how the reassembly engine treated it.
type FrameEvidence struct {
	FrameIndex  int
	Dir         int
	From        Endpoint
	To          Endpoint
	Seq, Ack    uint32
	SYN         bool
	FIN         bool
	RST         bool
	PayloadLen  int
	Accepted    bool   // true if (part of) the payload entered reassembly
	Disposition string // syn, assembled, buffered, retransmit, conflict, late-after-close, dropped, control
	Note        string
}

// Span is one piece of a reconstructed direction: either real bytes or an
// explicit gap marker. Gaps carry no fabricated payload.
type Span struct {
	Data       []byte
	Gap        bool
	Start, End uint64 // relative sequence coordinates
}

// Session is one TCP incarnation, keyed by the 4-tuple and its SYN.
type Session struct {
	ID          int
	Client      Endpoint
	Server      Endpoint
	Key         string
	Incarnation int

	frames    []FrameEvidence
	conflicts []Conflict
	drops     []DropEvent
	dirs      [2]*direction

	openedFrame int
	closedFrame int
	closed      bool
	closeWhy    string
	finAcked    [2]bool
}

// Frames returns the raw-evidence ledger in capture order.
func (s *Session) Frames() []FrameEvidence { return s.frames }

// Conflicts returns all retransmit/overwrite evidence.
func (s *Session) Conflicts() []Conflict { return s.conflicts }

// Drops returns budget/state rejections for this session.
func (s *Session) Drops() []DropEvent { return s.drops }

// Closed reports whether the session saw a full teardown or reset.
func (s *Session) Closed() bool { return s.closed }

// CloseReason describes how the session ended.
func (s *Session) CloseReason() string { return s.closeWhy }

// OpenFrameIndex returns the frame index of the opening SYN.
func (s *Session) OpenFrameIndex() int { return s.openedFrame }

// CloseFrameIndex returns the frame index at which closure was observed.
func (s *Session) CloseFrameIndex() int { return s.closedFrame }

func tupleKey(a, b Endpoint) string {
	x := a.String()
	y := b.String()
	if y < x {
		x, y = y, x
	}
	return x + " <-> " + y
}

func (s *Session) otherInitSeen() bool {
	// server direction ISN is learned from SYN-ACK
	return s.dirs[S2C] != nil && s.dirs[S2C].isnSet
}
