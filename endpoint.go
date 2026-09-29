package netforensics

import (
	"net"
	"strconv"
)

func joinHostPort(ip string, port uint16) string {
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return "[" + ip + "]:" + strconv.Itoa(int(port))
	}
	return ip + ":" + strconv.Itoa(int(port))
}
