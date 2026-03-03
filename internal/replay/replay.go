//go:build linux

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

	// Increase socket buffer size for better throughput
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 16*1024*1024); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, 16*1024*1024); err != nil {
		// SO_SNDBUFFORCE may fail due to permissions, ignore
	}

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
		if remaining != nil && *remaining == 0 {
			break
		}
		if err := replayOnce(fd, addr, cfg, remaining); err != nil {
			return err
		}
		loop++
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
	defer func() {
		fmt.Printf("Done: elapsed=%.2fs total=%d packets bits=%d\n", time.Since(startTime).Seconds(), totalPackets, totalBits)
	}()

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

		target := WaitForSchedule(cfg, startTime, baseTS, ci.Timestamp, totalBits, totalPackets)
		SleepUntil(target)

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

func WaitForSchedule(cfg Config, startTime, baseTS, pktTS time.Time, totalBits, totalPackets int64) time.Time {
	switch cfg.Mode {
	case ModeTimestamp:
		return startTime.Add(pktTS.Sub(baseTS))
	case ModeMbps:
		return startTime.Add(time.Duration(float64(totalBits) / (cfg.Mbps * 1e6) * float64(time.Second)))
	case ModePps:
		return startTime.Add(time.Duration(float64(totalPackets) / cfg.Pps * float64(time.Second)))
	default:
		return startTime.Add(pktTS.Sub(baseTS))
	}
}

func SleepUntil(target time.Time) {
	now := time.Now()
	if delta := target.Sub(now); delta > 0 {
		if delta > 2*time.Millisecond {
			// For longer delays, sleep with minimal compensation
			time.Sleep(delta - 300*time.Microsecond)
		} else if delta > 500*time.Microsecond {
			// For medium delays, sleep with less compensation
			time.Sleep(delta - 100*time.Microsecond)
		} else if delta > 50*time.Microsecond {
			// For short delays, sleep with even less compensation
			time.Sleep(delta - 30*time.Microsecond)
		} else {
			// For very short delays (<50us), skip Sleep to avoid overhead
		}
		// Busy-wait for the remaining microseconds for maximum precision
		for time.Until(target) > 0 {
		}
	}
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
