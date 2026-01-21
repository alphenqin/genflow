package replay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

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

func Replay(cfg Config) error {
	if cfg.InPath == "" || cfg.Iface == "" {
		return errors.New("input pcap and iface required")
	}
	if cfg.Mode == "" {
		cfg.Mode = ModeTimestamp
	}
	if cfg.StatsInterval <= 0 {
		cfg.StatsInterval = 1 * time.Second
	}
	if cfg.Mode == ModeMbps && cfg.Mbps <= 0 {
		return errors.New("mbps must be > 0 when mode=mbps")
	}
	if cfg.Mode == ModePps && cfg.Pps <= 0 {
		return errors.New("pps must be > 0 when mode=pps")
	}

	iface, err := net.InterfaceByName(cfg.Iface)
	if err != nil {
		return err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	addr := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: iface.Index}
	if err := unix.Bind(fd, addr); err != nil {
		return err
	}

	loop := 0
	var remaining *int
	if cfg.Limit > 0 {
		remaining = &cfg.Limit
	}
	for {
		if cfg.Loop > 0 && loop >= cfg.Loop {
			break
		}
		if err := replayOnce(fd, addr, cfg, remaining); err != nil {
			return err
		}
		loop++
		if cfg.Loop == 0 {
			continue
		}
	}
	return nil
}

func replayOnce(fd int, addr *unix.SockaddrLinklayer, cfg Config, remaining *int) error {
	file, err := os.Open(cfg.InPath)
	if err != nil {
		return err
	}
	defer file.Close()

	reader, err := pcapgo.NewReader(file)
	if err != nil {
		return err
	}

	var (
		startTime    = time.Now()
		baseTS       time.Time
		totalBits    int64
		totalPackets int64
		lastStats    = time.Now()
		lastBits     int64
		lastPackets  int64
	)

	for {
		data, ci, err := reader.ReadPacketData()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if baseTS.IsZero() {
			baseTS = ci.Timestamp
			startTime = time.Now()
		}

		if remaining != nil && *remaining == 0 {
			return nil
		}
		if remaining != nil && *remaining > 0 && int(totalPackets) >= *remaining {
			return nil
		}

		waitForSchedule(cfg, startTime, baseTS, ci.Timestamp, totalBits, totalPackets)

		if err := unix.Sendto(fd, data, 0, addr); err != nil {
			return err
		}

		totalPackets++
		totalBits += int64(len(data)) * 8
		if remaining != nil && *remaining > 0 {
			*remaining--
		}

		now := time.Now()
		if now.Sub(lastStats) >= cfg.StatsInterval {
			interval := now.Sub(lastStats).Seconds()
			bps := float64(totalBits-lastBits) / interval
			pps := float64(totalPackets-lastPackets) / interval
			fmt.Printf("%.2fs: %.2f Mbps %.2f pps total=%d\n", now.Sub(startTime).Seconds(), bps/1e6, pps, totalPackets)
			lastStats = now
			lastBits = totalBits
			lastPackets = totalPackets
		}
	}

	return nil
}

func waitForSchedule(cfg Config, startTime, baseTS, pktTS time.Time, totalBits, totalPackets int64) {
	switch cfg.Mode {
	case ModeTimestamp:
		target := startTime.Add(pktTS.Sub(baseTS))
		sleepUntil(target)
	case ModeMbps:
		target := startTime.Add(time.Duration(float64(totalBits) / (cfg.Mbps * 1e6) * float64(time.Second)))
		sleepUntil(target)
	case ModePps:
		target := startTime.Add(time.Duration(float64(totalPackets) / cfg.Pps * float64(time.Second)))
		sleepUntil(target)
	default:
		target := startTime.Add(pktTS.Sub(baseTS))
		sleepUntil(target)
	}
}

func sleepUntil(target time.Time) {
	for {
		now := time.Now()
		delta := target.Sub(now)
		if delta <= 0 {
			return
		}
		if delta > 150*time.Microsecond {
			time.Sleep(delta - 100*time.Microsecond)
			continue
		}
	}
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
