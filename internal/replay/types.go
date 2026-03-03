package replay

import "time"

type Mode string

const (
	ModeTimestamp Mode = "timestamp"
	ModeMbps      Mode = "mbps"
	ModePps       Mode = "pps"
)

type Config struct {
	InPath        string
	Iface         string
	Mode          Mode
	Mbps          float64
	Pps           float64
	Loop          int
	Limit         int
	StatsInterval time.Duration
}
