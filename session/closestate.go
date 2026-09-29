package session

// closeState tracks the four-way FIN teardown per direction.
// For direction X (the side that sent FIN X):
//   finAcked[X] becomes true once the peer ACKs the FIN (ack == finSeq+1).
// The whole session is closed once each FINing side has been ACKed,
// or immediately on RST.
//
// Coordinates here treat the SYN as rel 0 and the first data byte as rel 1.
// A data-carrying segment that also has FIN sets finSeq one past the last
// data byte; since FIN itself consumes one absolute sequence number, the
// matching ACK maps to finSeq in relative data coordinates.
