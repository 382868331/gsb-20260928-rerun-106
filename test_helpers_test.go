package netforensics

import "time"

func zeroTime(ms int64) time.Time {
	return time.Unix(1_700_001_000, ms*1_000_000).UTC()
}
