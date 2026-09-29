package session

import "net"

// ipEqual compares IPs regardless of 4- vs 16-byte representation.
func ipEqual(a, b net.IP) bool {
	return a.Equal(b)
}

func (ep Endpoint) equal(o Endpoint) bool {
	return ep.Port == o.Port && ipEqual(ep.IP, o.IP)
}
