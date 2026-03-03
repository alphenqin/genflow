package pcapgen

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type Config struct {
	InternalHosts  int
	ExternalHosts  int
	MinDuration    time.Duration
	MaxDuration    time.Duration
	FileCount      int
	OutDir         string
	OutFile        string
	StartTime      time.Time
	MaxSizeBytes   int
	ExactBytes     int
	Seed           int64
	FlowCount      int
	PacketsPerFlow int
	ProtoDist      ProtoDist
	TCPPortDist    PortDist
	UDPPortDist    PortDist
	PktSizeDist    SizeDist
	ResponseRatio  float64
}

func DefaultConfig() Config {
	start, _ := time.ParseInLocation("Mon Jan 2 15:04:05 2006", "Sun Oct 2 00:00:00 2016", time.Local)
	return Config{
		InternalHosts:  50,
		ExternalHosts:  500,
		MinDuration:    60 * time.Second,
		MaxDuration:    120 * time.Second,
		FileCount:      1,
		OutDir:         ".",
		OutFile:        "",
		StartTime:      start,
		MaxSizeBytes:   300000000,
		ExactBytes:     0,
		Seed:           time.Now().UnixNano(),
		FlowCount:      0,
		PacketsPerFlow: 2,
		ProtoDist:      DefaultProtoDist(),
		TCPPortDist:    DefaultTCPPortDist(),
		UDPPortDist:    DefaultUDPPortDist(),
		PktSizeDist:    DefaultPktSizeDist(),
		ResponseRatio:  0.35,
	}
}

type host struct {
	mac net.HardwareAddr
	ip  net.IP
}

func Generate(cfg Config) error {
	if cfg.InternalHosts <= 0 || cfg.ExternalHosts <= 0 {
		return errors.New("internal-hosts and external-hosts must be > 0")
	}
	if cfg.FileCount <= 0 {
		return errors.New("file-count must be > 0")
	}
	if cfg.OutFile != "" && cfg.FileCount != 1 {
		return errors.New("out-file requires file-count=1")
	}
	if cfg.ExactBytes > 0 && cfg.FileCount != 1 {
		return errors.New("exact-size requires file-count=1")
	}
	if cfg.MinDuration <= 0 || cfg.MaxDuration <= 0 || cfg.MaxDuration < cfg.MinDuration {
		return errors.New("invalid duration range")
	}
	if cfg.ExactBytes <= 0 {
		return errors.New("exact-size must be > 0")
	}
	if cfg.FlowCount < 0 {
		return errors.New("flow-count must be >= 0")
	}
	if cfg.FlowCount > 0 && cfg.PacketsPerFlow <= 0 {
		return errors.New("packets-per-flow must be > 0 when flow-count is set")
	}
	if cfg.ResponseRatio < 0 || cfg.ResponseRatio > 1 {
		return errors.New("resp-ratio must be within [0,1]")
	}

	randSrc := rand.New(rand.NewSource(cfg.Seed))

	internal := make([]host, cfg.InternalHosts)
	external := make([]host, cfg.ExternalHosts)
	if cfg.FlowCount > 0 {
		if cfg.InternalHosts > 65536 {
			return errors.New("internal-hosts exceeds 192.168.0.0/16 capacity (65536)")
		}
		if cfg.ExternalHosts > 16777216 {
			return errors.New("external-hosts exceeds 10.0.0.0/8 capacity (16777216)")
		}
		for i := 0; i < cfg.InternalHosts; i++ {
			internal[i] = host{mac: randomMAC(randSrc), ip: uniqueInternalIPv4(i)}
		}
		for i := 0; i < cfg.ExternalHosts; i++ {
			external[i] = host{mac: randomMAC(randSrc), ip: uniqueExternalIPv4(i)}
		}
	} else {
		for i := 0; i < cfg.InternalHosts; i++ {
			internal[i] = host{mac: randomMAC(randSrc), ip: randomIPv4(randSrc, 192, 168)}
		}
		for i := 0; i < cfg.ExternalHosts; i++ {
			external[i] = host{mac: randomMAC(randSrc), ip: randomIPv4(randSrc)}
		}
	}

	startTime := cfg.StartTime
	for i := 0; i < cfg.FileCount; i++ {
		path := cfg.OutFile
		if path == "" {
			name := "generated_0000.pcap"
			if cfg.FileCount > 1 {
				name = fmt.Sprintf("generated_%06d.pcap", i)
			}
			path = filepath.Join(cfg.OutDir, name)
		}

		fileSeed := mixSeed(cfg.Seed, int64(i))
		randSrc := rand.New(rand.NewSource(fileSeed))
		dur := randomDuration(randSrc, cfg.MinDuration, cfg.MaxDuration)
		if cfg.FileCount > 1 {
			next := startTime
			isWeekend := next.Weekday() == time.Saturday || next.Weekday() == time.Sunday
			decimalHour := float64(next.Hour()) + float64(next.Minute())/60 + float64(next.Second())/3600
			scale := durationScalar(decimalHour, isWeekend)
			dur = time.Duration(float64(480)*scale) * time.Second
			log.Printf("%s - duration=%s (scale=%.3f)", next.Format(time.RFC3339), dur.String(), scale)
		}

		if cfg.FlowCount > 0 {
			if err := createPcapFileFlows(path, startTime, dur, cfg, cfg.ExactBytes, fileSeed, internal, external); err != nil {
				return err
			}
		} else {
			if err := createPcapFile(path, startTime, dur, cfg, cfg.MaxSizeBytes, cfg.ExactBytes, fileSeed, internal, external); err != nil {
				return err
			}
		}
		startTime = startTime.Add(dur)
	}
	return nil
}

func createPcapFileFlows(path string, start time.Time, duration time.Duration, cfg Config, exactBytes int, fileSeed int64, internal, external []host) error {
	log.Printf("Creating %s flows=%d packetsPerFlow=%d duration=%s", path, cfg.FlowCount, cfg.PacketsPerFlow, duration)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}

	totalCapacity := 2 * len(internal) * len(external)
	if cfg.FlowCount > totalCapacity {
		return fmt.Errorf("flow-count exceeds capacity: flow-count=%d max=%d (2*internal*external)", cfg.FlowCount, totalCapacity)
	}
	totalPackets := cfg.FlowCount * cfg.PacketsPerFlow
	baseSize, totalPayload, totalCapacityBytes, minSize, err := planFlowSizing(cfg, totalPackets, fileSeed)
	if err != nil {
		return err
	}
	if exactBytes > 0 {
		if exactBytes < minSize {
			return fmt.Errorf("exact-size %d < minimum size %d; increase exact-size", exactBytes, minSize)
		}
		if exactBytes < baseSize {
			// Allow shrinking payloads down to zero where possible.
			// This keeps protocol mix while meeting smaller exact sizes.
			// baseSize here is the planned distribution size.
		}
		payloadExtra := exactBytes - baseSize
		if payloadExtra > totalCapacityBytes {
			return fmt.Errorf("exact-size requires payloadExtra=%d but max supported is %d; increase packets-per-flow or flow-count", payloadExtra, totalCapacityBytes)
		}
		_ = payloadExtra
	} else if cfg.MaxSizeBytes > 0 && baseSize > cfg.MaxSizeBytes {
		return fmt.Errorf("estimated size %d > max-size %d; increase max-size or reduce flow-count/packets-per-flow", baseSize, cfg.MaxSizeBytes)
	}

	if duration <= 0 {
		duration = 10 * time.Second
	}
	totalUsec := int(duration / time.Microsecond)
	if totalUsec <= 0 {
		totalUsec = 1
	}
	usecStep := totalUsec / totalPackets
	if usecStep < 1 {
		usecStep = 1
	}

	packetIdx := 0
	remainingPackets := totalPackets
	remainingDelta := 0
	remainingRemove := 0
	if exactBytes > 0 {
		delta := exactBytes - baseSize
		if delta >= 0 {
			remainingDelta = delta
		} else {
			remainingRemove = -delta
		}
	}
	remainingCapacity := totalCapacityBytes
	remainingPayload := totalPayload
	for flowIdx := 0; flowIdx < cfg.FlowCount; flowIdx++ {
		internalIdx, externalIdx, internalAsSource := flowIndexToHosts(flowIdx, len(internal), len(external))
		flowRand := rand.New(rand.NewSource(mixSeed(fileSeed, int64(flowIdx))))
		flowPlan := planFlow(flowRand, cfg)
		respRand := rand.New(rand.NewSource(mixSeedWithSalt(fileSeed, int64(flowIdx), 0x5bd1e995)))
		respMask := responseMask(respRand, cfg.PacketsPerFlow, cfg.ResponseRatio)
		for p := 0; p < cfg.PacketsPerFlow; p++ {
			offsetUsec := packetIdx * usecStep
			packetIdx++
			packetTime := start.Add(time.Duration(offsetUsec) * time.Microsecond)
			payloadLen, maxAdd, basePayload := planPayloadLen(flowRand, cfg, flowPlan.Proto)
			adjustedPayload := payloadLen
			if remainingDelta > 0 {
				add := allocateDelta(remainingDelta, remainingCapacity, maxAdd, remainingPackets)
				adjustedPayload += add
				remainingDelta -= add
				remainingCapacity -= maxAdd
			} else if remainingRemove > 0 {
				remove := allocateRemove(remainingRemove, remainingPayload, basePayload, remainingPackets)
				adjustedPayload -= remove
				remainingRemove -= remove
				remainingPayload -= basePayload
			}
			remainingPackets--
			payloadRand := rand.New(rand.NewSource(mixSeed(fileSeed, int64(flowIdx)<<32|int64(p))))
			isResponse := respMask[p]
			effectiveInternalAsSource := internalAsSource
			if isResponse {
				effectiveInternalAsSource = !internalAsSource
			}
			packetData, err := createPacketForHosts(payloadRand, internal[internalIdx], external[externalIdx], effectiveInternalAsSource, flowPlan, isResponse, adjustedPayload)
			if err != nil {
				return err
			}
			ci := gopacket.CaptureInfo{
				Timestamp:     packetTime,
				CaptureLength: len(packetData),
				Length:        len(packetData),
			}
			if err := writer.WritePacket(ci, packetData); err != nil {
				return err
			}
		}
		if flowIdx%100000 == 0 && flowIdx > 0 {
			log.Printf("Creating flow %d", flowIdx)
		}
	}
	if remainingDelta != 0 || remainingRemove != 0 {
		return fmt.Errorf("payload distribution bug: remainingDelta=%d remainingRemove=%d", remainingDelta, remainingRemove)
	}
	log.Printf("Done %s packets=%d exactBytes=%d", path, totalPackets, exactBytes)

	return nil
}

func createPcapFile(path string, start time.Time, duration time.Duration, cfg Config, maxSize int, exactBytes int, fileSeed int64, internal, external []host) error {
	log.Printf("Creating %s duration=%s", path, duration)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}

	if exactBytes > 0 {
		const (
			sizeFileHeader       = 24
			sizePacketPlusHeader = 78
		)
		if exactBytes < sizeFileHeader+sizePacketPlusHeader {
			return errors.New("exact-size too small for packet generation")
		}
		totalPackets := (exactBytes - sizeFileHeader) / sizePacketPlusHeader
		if totalPackets <= 0 {
			return errors.New("exact-size too small for packet generation")
		}
		baseSize, totalPayload, totalCapacityBytes, minSize, err := planPacketSizing(cfg, totalPackets, fileSeed)
		if err != nil {
			return err
		}
		if exactBytes < minSize {
			return fmt.Errorf("exact-size %d < minimum size %d; increase exact-size", exactBytes, minSize)
		}
		payloadExtra := exactBytes - baseSize
		if payloadExtra > totalCapacityBytes {
			return fmt.Errorf("exact-size requires payloadExtra=%d but max supported is %d", payloadExtra, totalCapacityBytes)
		}

		startSec := start.Unix()
		endSec := startSec + int64(duration.Seconds()) - 1
		offsetUsec := 0

		remainingPackets := totalPackets
		remainingDelta := 0
		remainingRemove := 0
		if payloadExtra >= 0 {
			remainingDelta = payloadExtra
		} else {
			remainingRemove = -payloadExtra
		}
		remainingCapacity := totalCapacityBytes
		remainingPayload := totalPayload

		for i := 0; i < totalPackets; i++ {
			if i%100000 == 0 {
				log.Printf("Creating packet %d", i)
			}

			packetTime := time.Unix(startSec, int64(offsetUsec)*1000)
			planRand := rand.New(rand.NewSource(mixSeed(fileSeed, int64(i))))
			packetPlan := planPacket(planRand, cfg)
			respRand := rand.New(rand.NewSource(mixSeedWithSalt(fileSeed, int64(i), 0x5bd1e995)))
			isResponse := respRand.Float64() < cfg.ResponseRatio
			payloadLen, maxAdd, basePayload := planPayloadLen(planRand, cfg, packetPlan.Proto)
			adjustedPayload := payloadLen
			if remainingDelta > 0 {
				add := allocateDelta(remainingDelta, remainingCapacity, maxAdd, remainingPackets)
				adjustedPayload += add
				remainingDelta -= add
				remainingCapacity -= maxAdd
			} else if remainingRemove > 0 {
				remove := allocateRemove(remainingRemove, remainingPayload, basePayload, remainingPackets)
				adjustedPayload -= remove
				remainingRemove -= remove
				remainingPayload -= basePayload
			}
			remainingPackets--
			payloadRand := rand.New(rand.NewSource(mixSeedWithSalt(fileSeed, int64(i), 0x9e3779b97f4a7c15)))
			packetData, err := createPacket(payloadRand, internal, external, packetPlan, isResponse, adjustedPayload)
			if err != nil {
				return err
			}
			ci := gopacket.CaptureInfo{
				Timestamp:     packetTime,
				CaptureLength: len(packetData),
				Length:        len(packetData),
			}
			if err := writer.WritePacket(ci, packetData); err != nil {
				return err
			}

			remaining := float64(endSec - int64(startSec))
			if remaining <= 0 {
				remaining = 1
			}
			interPacket := int((remaining / float64(totalPackets-i)) * 1_000_000)
			if interPacket < 1 {
				interPacket = 1
			}
			offsetUsec += planRand.Intn(interPacket + 1)
			if offsetUsec >= 1_000_000 {
				startSec++
				offsetUsec -= 1_000_000
			}
		}

		if remainingDelta != 0 || remainingRemove != 0 {
			return fmt.Errorf("payload distribution bug: remainingDelta=%d remainingRemove=%d", remainingDelta, remainingRemove)
		}

		return nil
	}

	sizeFileHeader := 24
	sizePacketPlusHeader := 78
	numPackets := (maxSize - sizeFileHeader) / sizePacketPlusHeader
	if numPackets <= 0 {
		return errors.New("max-size too small for packet generation")
	}

	startSec := start.Unix()
	endSec := startSec + int64(duration.Seconds()) - 1
	offsetUsec := 0

	for i := 0; i < numPackets-1; i++ {
		if i%100000 == 0 {
			log.Printf("Creating packet %d", i)
		}

		packetTime := time.Unix(startSec, int64(offsetUsec)*1000)
		planRand := rand.New(rand.NewSource(mixSeed(fileSeed, int64(i))))
		packetPlan := planPacket(planRand, cfg)
		respRand := rand.New(rand.NewSource(mixSeedWithSalt(fileSeed, int64(i), 0x5bd1e995)))
		isResponse := respRand.Float64() < cfg.ResponseRatio
		payloadRand := rand.New(rand.NewSource(mixSeedWithSalt(fileSeed, int64(i), 0x9e3779b97f4a7c15)))
		payloadLen, _, _ := planPayloadLen(planRand, cfg, packetPlan.Proto)
		packetData, err := createPacket(payloadRand, internal, external, packetPlan, isResponse, payloadLen)
		if err != nil {
			return err
		}
		ci := gopacket.CaptureInfo{
			Timestamp:     packetTime,
			CaptureLength: len(packetData),
			Length:        len(packetData),
		}
		if err := writer.WritePacket(ci, packetData); err != nil {
			return err
		}

		remaining := float64(endSec - int64(startSec))
		if remaining <= 0 {
			remaining = 1
		}
		interPacket := int((remaining / float64(numPackets-i)) * 1_000_000)
		if interPacket < 1 {
			interPacket = 1
		}
		offsetUsec += planRand.Intn(interPacket + 1)
		if offsetUsec >= 1_000_000 {
			startSec++
			offsetUsec -= 1_000_000
		}
	}

	return nil
}

func createPacket(randSrc *rand.Rand, internal, external []host, plan PacketPlan, isResponse bool, payloadLen int) ([]byte, error) {
	internalAsSource := randSrc.Intn(2) == 1
	var src, dst host
	if internalAsSource {
		src = internal[randSrc.Intn(len(internal))]
		dst = external[randSrc.Intn(len(external))]
	} else {
		src = external[randSrc.Intn(len(external))]
		dst = internal[randSrc.Intn(len(internal))]
	}
	return buildPacket(randSrc, src, dst, plan, isResponse, payloadLen)
}

func flowIndexToHosts(idx, internalCount, externalCount int) (int, int, bool) {
	totalPair := internalCount * externalCount
	if idx < totalPair {
		return idx / externalCount, idx % externalCount, true
	}
	idx -= totalPair
	return idx / externalCount, idx % externalCount, false
}

func createPacketForHosts(randSrc *rand.Rand, internalHost, externalHost host, internalAsSource bool, plan PacketPlan, isResponse bool, payloadLen int) ([]byte, error) {
	var src, dst host
	if internalAsSource {
		src = internalHost
		dst = externalHost
	} else {
		src = externalHost
		dst = internalHost
	}
	return buildPacket(randSrc, src, dst, plan, isResponse, payloadLen)
}

func buildPacket(randSrc *rand.Rand, src host, dst host, plan PacketPlan, isResponse bool, payloadLen int) ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       src.mac,
		DstMAC:       dst.mac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      128,
		Protocol: plan.Proto,
		SrcIP:    src.ip,
		DstIP:    dst.ip,
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	payload := []byte(nil)
	if payloadLen > 0 {
		payload = buildAppPayload(randSrc, plan, isResponse, payloadLen)
		if len(payload) == 0 {
			payload = make([]byte, payloadLen)
			if _, err := randSrc.Read(payload); err != nil {
				return nil, err
			}
		}
	}

	switch plan.Proto {
	case layers.IPProtocolUDP:
		srcPort, dstPort := plan.SrcPort, plan.DstPort
		if isResponse {
			srcPort, dstPort = dstPort, srcPort
		}
		udp := layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		if err := udp.SetNetworkLayerForChecksum(&ip); err != nil {
			return nil, err
		}
		if payloadLen > 0 {
			if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		} else {
			if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp); err != nil {
				return nil, err
			}
		}
	case layers.IPProtocolICMPv4:
		icmpType := plan.ICMPType
		icmpCode := plan.ICMPCode
		if isResponse && icmpType == layers.ICMPv4TypeEchoRequest {
			icmpType = layers.ICMPv4TypeEchoReply
			icmpCode = 0
		}
		icmp := layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(icmpType, icmpCode),
			Id:       uint16(randSrc.Intn(65535)),
			Seq:      uint16(randSrc.Intn(65535)),
		}
		if payloadLen > 0 {
			if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &icmp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		} else {
			if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &icmp); err != nil {
				return nil, err
			}
		}
	case layers.IPProtocolTCP:
		fallthrough
	default:
		srcPort, dstPort := plan.SrcPort, plan.DstPort
		if isResponse {
			srcPort, dstPort = dstPort, srcPort
		}
		flags := pickTCPFlags(randSrc, isResponse, payloadLen)
		tcp := layers.TCP{
			SrcPort:    layers.TCPPort(srcPort),
			DstPort:    layers.TCPPort(dstPort),
			Seq:        randSrc.Uint32(),
			Ack:        0,
			Window:     8760,
			FIN:        flags.FIN,
			SYN:        flags.SYN,
			RST:        flags.RST,
			PSH:        flags.PSH,
			ACK:        flags.ACK,
			URG:        false,
			ECE:        false,
			CWR:        false,
			NS:         false,
			DataOffset: 7,
			Options: []layers.TCPOption{
				{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xB4}},
				{OptionType: layers.TCPOptionKindNop},
				{OptionType: layers.TCPOptionKindNop},
				{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			},
		}
		if err := tcp.SetNetworkLayerForChecksum(&ip); err != nil {
			return nil, err
		}
		if payloadLen > 0 {
			if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp, gopacket.Payload(payload)); err != nil {
				return nil, err
			}
		} else {
			if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &tcp); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

func randomMAC(randSrc *rand.Rand) net.HardwareAddr {
	return net.HardwareAddr{
		byte(randSrc.Intn(256)),
		byte(randSrc.Intn(256)),
		byte(randSrc.Intn(256)),
		byte(randSrc.Intn(256)),
		byte(randSrc.Intn(256)),
		byte(randSrc.Intn(256)),
	}
}

func randomIPv4(randSrc *rand.Rand, prefix ...int) net.IP {
	ip := make(net.IP, 4)
	if len(prefix) >= 1 {
		ip[0] = byte(prefix[0])
	} else {
		ip[0] = byte(randSrc.Intn(255) + 1)
	}
	if len(prefix) >= 2 {
		ip[1] = byte(prefix[1])
	} else {
		ip[1] = byte(randSrc.Intn(256))
	}
	ip[2] = byte(randSrc.Intn(256))
	ip[3] = byte(randSrc.Intn(256))
	return ip
}

func uniqueInternalIPv4(idx int) net.IP {
	ip := make(net.IP, 4)
	ip[0] = 192
	ip[1] = 168
	ip[2] = byte(idx / 256)
	ip[3] = byte(idx % 256)
	return ip
}

func uniqueExternalIPv4(idx int) net.IP {
	ip := make(net.IP, 4)
	ip[0] = 10
	ip[1] = byte((idx >> 16) & 0xFF)
	ip[2] = byte((idx >> 8) & 0xFF)
	ip[3] = byte(idx & 0xFF)
	return ip
}

func randomDuration(randSrc *rand.Rand, min, max time.Duration) time.Duration {
	if min == max {
		return min
	}
	delta := max - min
	return min + time.Duration(randSrc.Int63n(int64(delta)))
}
