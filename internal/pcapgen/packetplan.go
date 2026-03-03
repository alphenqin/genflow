package pcapgen

import (
	"fmt"
	"math"
	"math/rand"

	"github.com/google/gopacket/layers"
)

type PacketPlan struct {
	Proto    layers.IPProtocol
	SrcPort  uint16
	DstPort  uint16
	ICMPType uint8
	ICMPCode uint8
}

type tcpFlags struct {
	SYN bool
	ACK bool
	PSH bool
	FIN bool
	RST bool
}

func planFlow(r *rand.Rand, cfg Config) PacketPlan {
	return planPacket(r, cfg)
}

func planPacket(r *rand.Rand, cfg Config) PacketPlan {
	proto := cfg.ProtoDist.Pick(r)
	plan := PacketPlan{Proto: proto}
	switch proto {
	case layers.IPProtocolTCP:
		plan.DstPort = cfg.TCPPortDist.Pick(r)
		plan.SrcPort = randomEphemeralPort(r)
	case layers.IPProtocolUDP:
		plan.DstPort = cfg.UDPPortDist.Pick(r)
		plan.SrcPort = randomEphemeralPort(r)
	case layers.IPProtocolICMPv4:
		plan.ICMPType = layers.ICMPv4TypeEchoRequest
		plan.ICMPCode = 0
	default:
		plan.Proto = layers.IPProtocolTCP
		plan.DstPort = cfg.TCPPortDist.Pick(r)
		plan.SrcPort = randomEphemeralPort(r)
	}
	return plan
}

func planPayloadLen(r *rand.Rand, cfg Config, proto layers.IPProtocol) (payloadLen int, maxAdd int, basePayload int) {
	target := cfg.PktSizeDist.Pick(r)
	base := basePacketLen(proto)
	if target < base {
		target = base
	}
	payloadLen = target - base
	maxPayload := maxPayloadLen(proto)
	maxAdd = maxPayload - payloadLen
	if maxAdd < 0 {
		maxAdd = 0
	}
	basePayload = payloadLen
	return payloadLen, maxAdd, basePayload
}

func basePacketLen(proto layers.IPProtocol) int {
	switch proto {
	case layers.IPProtocolUDP:
		return 14 + 20 + 8
	case layers.IPProtocolICMPv4:
		return 14 + 20 + 8
	case layers.IPProtocolTCP:
		fallthrough
	default:
		return 14 + 20 + 28
	}
}

func maxPayloadLen(proto layers.IPProtocol) int {
	base := basePacketLen(proto)
	const maxCaptureLen = 65535
	return maxCaptureLen - base
}

func randomEphemeralPort(r *rand.Rand) uint16 {
	return uint16(49152 + r.Intn(65535-49152+1))
}

func pickTCPFlags(r *rand.Rand, isResponse bool, payloadLen int) tcpFlags {
	if isResponse {
		if payloadLen > 0 {
			return tcpFlags{PSH: true, ACK: true}
		}
		return tcpFlags{ACK: true}
	}
	roll := r.Float64()
	switch {
	case roll < 0.08:
		return tcpFlags{SYN: true}
	case roll < 0.10:
		return tcpFlags{FIN: true, ACK: true}
	case roll < 0.12:
		return tcpFlags{RST: true}
	default:
		if payloadLen > 0 {
			return tcpFlags{PSH: true, ACK: true}
		}
		return tcpFlags{ACK: true}
	}
}

func responseMask(r *rand.Rand, packetsPerFlow int, responseRatio float64) []bool {
	mask := make([]bool, packetsPerFlow)
	if packetsPerFlow <= 1 {
		return mask
	}
	if responseRatio <= 0 {
		return mask
	}
	if responseRatio > 1 {
		responseRatio = 1
	}
	responseCount := int(math.Round(float64(packetsPerFlow-1) * responseRatio))
	if responseCount <= 0 {
		return mask
	}
	indices := make([]int, packetsPerFlow-1)
	for i := 1; i < packetsPerFlow; i++ {
		indices[i-1] = i
	}
	for i := len(indices) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		indices[i], indices[j] = indices[j], indices[i]
	}
	if responseCount > len(indices) {
		responseCount = len(indices)
	}
	for i := 0; i < responseCount; i++ {
		mask[indices[i]] = true
	}
	return mask
}

func planFlowSizing(cfg Config, totalPackets int, fileSeed int64) (baseSize int, totalPayload int, totalCapacity int, minSize int, err error) {
	if totalPackets <= 0 {
		return 0, 0, 0, 0, fmt.Errorf("totalPackets must be > 0")
	}
	for flowIdx := 0; flowIdx < cfg.FlowCount; flowIdx++ {
		flowRand := rand.New(rand.NewSource(mixSeed(fileSeed, int64(flowIdx))))
		flowPlan := planFlow(flowRand, cfg)
		for p := 0; p < cfg.PacketsPerFlow; p++ {
			payloadLen, maxAdd, basePayload := planPayloadLen(flowRand, cfg, flowPlan.Proto)
			baseLen := basePacketLen(flowPlan.Proto)
			minSize += baseLen
			baseSize += baseLen + payloadLen
			totalPayload += basePayload
			totalCapacity += maxAdd
		}
	}
	return baseSize, totalPayload, totalCapacity, minSize, nil
}

func planPacketSizing(cfg Config, totalPackets int, fileSeed int64) (baseSize int, totalPayload int, totalCapacity int, minSize int, err error) {
	if totalPackets <= 0 {
		return 0, 0, 0, 0, fmt.Errorf("totalPackets must be > 0")
	}
	for i := 0; i < totalPackets; i++ {
		planRand := rand.New(rand.NewSource(mixSeed(fileSeed, int64(i))))
		packetPlan := planPacket(planRand, cfg)
		payloadLen, maxAdd, basePayload := planPayloadLen(planRand, cfg, packetPlan.Proto)
		baseLen := basePacketLen(packetPlan.Proto)
		minSize += baseLen
		baseSize += baseLen + payloadLen
		totalPayload += basePayload
		totalCapacity += maxAdd
	}
	return baseSize, totalPayload, totalCapacity, minSize, nil
}

func allocateDelta(remainingDelta int, remainingCapacity int, maxAdd int, remainingPackets int) int {
	if remainingDelta <= 0 || maxAdd <= 0 {
		return 0
	}
	if remainingCapacity <= 0 {
		return 0
	}
	add := (remainingDelta*maxAdd + remainingCapacity - 1) / remainingCapacity
	if add > maxAdd {
		add = maxAdd
	}
	if add > remainingDelta {
		add = remainingDelta
	}
	return add
}

func allocateRemove(remainingRemove int, remainingPayload int, basePayload int, remainingPackets int) int {
	if remainingRemove <= 0 || basePayload <= 0 {
		return 0
	}
	if remainingPayload <= 0 {
		return 0
	}
	remove := (remainingRemove*basePayload + remainingPayload - 1) / remainingPayload
	if remove > basePayload {
		remove = basePayload
	}
	if remove > remainingRemove {
		remove = remainingRemove
	}
	return remove
}

func mixSeed(seed int64, idx int64) int64 {
	const seedMix uint64 = 0x9e3779b97f4a7c15
	x := uint64(seed) ^ (uint64(idx) + seedMix)
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return int64(x)
}

func mixSeedWithSalt(seed int64, idx int64, salt uint64) int64 {
	return mixSeed(seed, idx) ^ int64(salt&0x7fffffffffffffff)
}
