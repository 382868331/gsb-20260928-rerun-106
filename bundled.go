package netforensics

import _ "embed"

//go:embed testdata/known.pcap
var bundledPCAP []byte

func BundledPCAP() []byte {
	return append([]byte(nil), bundledPCAP...)
}
