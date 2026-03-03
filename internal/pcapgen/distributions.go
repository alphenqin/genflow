package pcapgen

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/google/gopacket/layers"
)

type ProtoDist struct {
	Items []WeightedProto
	Total int
}

type WeightedProto struct {
	Proto  layers.IPProtocol
	Weight int
}

func (d ProtoDist) Pick(r *rand.Rand) layers.IPProtocol {
	if d.Total <= 0 || len(d.Items) == 0 {
		return layers.IPProtocolTCP
	}
	n := r.Intn(d.Total)
	for _, item := range d.Items {
		if n < item.Weight {
			return item.Proto
		}
		n -= item.Weight
	}
	return d.Items[len(d.Items)-1].Proto
}

func DefaultProtoDist() ProtoDist {
	items := []WeightedProto{
		{Proto: layers.IPProtocolTCP, Weight: 70},
		{Proto: layers.IPProtocolUDP, Weight: 25},
		{Proto: layers.IPProtocolICMPv4, Weight: 5},
	}
	dist, _ := buildProtoDist(items)
	return dist
}

func ParseProtoDist(value string) (ProtoDist, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return ProtoDist{}, fmt.Errorf("empty proto dist")
	}
	parts := strings.Split(value, ",")
	items := make([]WeightedProto, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pieces := strings.Split(part, "=")
		if len(pieces) != 2 {
			return ProtoDist{}, fmt.Errorf("invalid proto item: %q", part)
		}
		name := strings.ToLower(strings.TrimSpace(pieces[0]))
		weight, err := parseWeight(pieces[1])
		if err != nil {
			return ProtoDist{}, err
		}
		var proto layers.IPProtocol
		switch name {
		case "tcp":
			proto = layers.IPProtocolTCP
		case "udp":
			proto = layers.IPProtocolUDP
		case "icmp", "icmpv4":
			proto = layers.IPProtocolICMPv4
		default:
			return ProtoDist{}, fmt.Errorf("unknown proto %q", name)
		}
		items = append(items, WeightedProto{Proto: proto, Weight: weight})
	}
	return buildProtoDist(items)
}

func buildProtoDist(items []WeightedProto) (ProtoDist, error) {
	total := 0
	for _, item := range items {
		if item.Weight <= 0 {
			return ProtoDist{}, fmt.Errorf("proto weight must be > 0")
		}
		total += item.Weight
	}
	if total == 0 {
		return ProtoDist{}, fmt.Errorf("proto dist has no weights")
	}
	return ProtoDist{Items: items, Total: total}, nil
}

type PortDist struct {
	Items []WeightedPort
	Total int
}

type PortRange struct {
	Min uint16
	Max uint16
}

type WeightedPort struct {
	Range  PortRange
	Weight int
}

func (d PortDist) Pick(r *rand.Rand) uint16 {
	if d.Total <= 0 || len(d.Items) == 0 {
		return uint16(80)
	}
	n := r.Intn(d.Total)
	for _, item := range d.Items {
		if n < item.Weight {
			if item.Range.Min == item.Range.Max {
				return item.Range.Min
			}
			return uint16(item.Range.Min + uint16(r.Intn(int(item.Range.Max-item.Range.Min+1))))
		}
		n -= item.Weight
	}
	last := d.Items[len(d.Items)-1].Range
	if last.Min == last.Max {
		return last.Min
	}
	return uint16(last.Min + uint16(r.Intn(int(last.Max-last.Min+1))))
}

func DefaultTCPPortDist() PortDist {
	items := []WeightedPort{
		{Range: PortRange{Min: 443, Max: 443}, Weight: 40},
		{Range: PortRange{Min: 80, Max: 80}, Weight: 20},
		{Range: PortRange{Min: 8080, Max: 8080}, Weight: 5},
		{Range: PortRange{Min: 8443, Max: 8443}, Weight: 5},
		{Range: PortRange{Min: 22, Max: 22}, Weight: 3},
		{Range: PortRange{Min: 3389, Max: 3389}, Weight: 3},
		{Range: PortRange{Min: 445, Max: 445}, Weight: 3},
		{Range: PortRange{Min: 53, Max: 53}, Weight: 2},
		{Range: PortRange{Min: 25, Max: 25}, Weight: 2},
		{Range: PortRange{Min: 110, Max: 110}, Weight: 1},
		{Range: PortRange{Min: 143, Max: 143}, Weight: 1},
		{Range: PortRange{Min: 3306, Max: 3306}, Weight: 2},
		{Range: PortRange{Min: 5432, Max: 5432}, Weight: 1},
		{Range: PortRange{Min: 6379, Max: 6379}, Weight: 1},
		{Range: PortRange{Min: 5900, Max: 5900}, Weight: 1},
		{Range: PortRange{Min: 1194, Max: 1194}, Weight: 1},
		{Range: PortRange{Min: 1024, Max: 65535}, Weight: 10},
	}
	dist, _ := buildPortDist(items)
	return dist
}

func DefaultUDPPortDist() PortDist {
	items := []WeightedPort{
		{Range: PortRange{Min: 443, Max: 443}, Weight: 25},
		{Range: PortRange{Min: 53, Max: 53}, Weight: 30},
		{Range: PortRange{Min: 123, Max: 123}, Weight: 5},
		{Range: PortRange{Min: 3478, Max: 3478}, Weight: 5},
		{Range: PortRange{Min: 500, Max: 500}, Weight: 4},
		{Range: PortRange{Min: 4500, Max: 4500}, Weight: 4},
		{Range: PortRange{Min: 1900, Max: 1900}, Weight: 4},
		{Range: PortRange{Min: 5353, Max: 5353}, Weight: 4},
		{Range: PortRange{Min: 67, Max: 67}, Weight: 2},
		{Range: PortRange{Min: 68, Max: 68}, Weight: 2},
		{Range: PortRange{Min: 161, Max: 161}, Weight: 2},
		{Range: PortRange{Min: 1024, Max: 65535}, Weight: 13},
	}
	dist, _ := buildPortDist(items)
	return dist
}

func ParsePortDist(value string) (PortDist, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return PortDist{}, fmt.Errorf("empty port dist")
	}
	parts := strings.Split(value, ",")
	items := make([]WeightedPort, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pieces := strings.Split(part, "=")
		if len(pieces) != 2 {
			return PortDist{}, fmt.Errorf("invalid port item: %q", part)
		}
		rng, err := parsePortRange(pieces[0])
		if err != nil {
			return PortDist{}, err
		}
		weight, err := parseWeight(pieces[1])
		if err != nil {
			return PortDist{}, err
		}
		items = append(items, WeightedPort{Range: rng, Weight: weight})
	}
	return buildPortDist(items)
}

func buildPortDist(items []WeightedPort) (PortDist, error) {
	total := 0
	for _, item := range items {
		if item.Weight <= 0 {
			return PortDist{}, fmt.Errorf("port weight must be > 0")
		}
		if item.Range.Min == 0 || item.Range.Max == 0 || item.Range.Min > item.Range.Max {
			return PortDist{}, fmt.Errorf("invalid port range %d-%d", item.Range.Min, item.Range.Max)
		}
		if item.Range.Max > 65535 {
			return PortDist{}, fmt.Errorf("port range exceeds 65535: %d-%d", item.Range.Min, item.Range.Max)
		}
		total += item.Weight
	}
	if total == 0 {
		return PortDist{}, fmt.Errorf("port dist has no weights")
	}
	return PortDist{Items: items, Total: total}, nil
}

func parsePortRange(value string) (PortRange, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return PortRange{}, fmt.Errorf("empty port range")
	}
	if value == "ephemeral" {
		return PortRange{Min: 49152, Max: 65535}, nil
	}
	if value == "any" {
		return PortRange{Min: 1, Max: 65535}, nil
	}
	if strings.Contains(value, "-") {
		pieces := strings.Split(value, "-")
		if len(pieces) != 2 {
			return PortRange{}, fmt.Errorf("invalid port range: %q", value)
		}
		min, err := strconv.Atoi(strings.TrimSpace(pieces[0]))
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid port range min: %v", err)
		}
		max, err := strconv.Atoi(strings.TrimSpace(pieces[1]))
		if err != nil {
			return PortRange{}, fmt.Errorf("invalid port range max: %v", err)
		}
		if min <= 0 || max <= 0 || min > 65535 || max > 65535 {
			return PortRange{}, fmt.Errorf("port range out of bounds: %d-%d", min, max)
		}
		return PortRange{Min: uint16(min), Max: uint16(max)}, nil
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return PortRange{}, fmt.Errorf("invalid port: %v", err)
	}
	if port <= 0 || port > 65535 {
		return PortRange{}, fmt.Errorf("port out of bounds: %d", port)
	}
	return PortRange{Min: uint16(port), Max: uint16(port)}, nil
}

type SizeDist struct {
	Items []WeightedSize
	Total int
}

type WeightedSize struct {
	Size   int
	Weight int
}

func (d SizeDist) Pick(r *rand.Rand) int {
	if d.Total <= 0 || len(d.Items) == 0 {
		return 512
	}
	n := r.Intn(d.Total)
	for _, item := range d.Items {
		if n < item.Weight {
			return item.Size
		}
		n -= item.Weight
	}
	return d.Items[len(d.Items)-1].Size
}

func DefaultPktSizeDist() SizeDist {
	items := []WeightedSize{
		{Size: 64, Weight: 25},
		{Size: 128, Weight: 15},
		{Size: 256, Weight: 15},
		{Size: 512, Weight: 15},
		{Size: 1024, Weight: 10},
		{Size: 1500, Weight: 20},
	}
	dist, _ := buildSizeDist(items)
	return dist
}

func ParseSizeDist(value string) (SizeDist, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return SizeDist{}, fmt.Errorf("empty size dist")
	}
	parts := strings.Split(value, ",")
	items := make([]WeightedSize, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		pieces := strings.Split(part, "=")
		if len(pieces) != 2 {
			return SizeDist{}, fmt.Errorf("invalid size item: %q", part)
		}
		size, err := strconv.Atoi(strings.TrimSpace(pieces[0]))
		if err != nil {
			return SizeDist{}, fmt.Errorf("invalid size: %v", err)
		}
		if size <= 0 {
			return SizeDist{}, fmt.Errorf("size must be > 0")
		}
		weight, err := parseWeight(pieces[1])
		if err != nil {
			return SizeDist{}, err
		}
		items = append(items, WeightedSize{Size: size, Weight: weight})
	}
	return buildSizeDist(items)
}

func buildSizeDist(items []WeightedSize) (SizeDist, error) {
	total := 0
	for _, item := range items {
		if item.Weight <= 0 {
			return SizeDist{}, fmt.Errorf("size weight must be > 0")
		}
		if item.Size <= 0 {
			return SizeDist{}, fmt.Errorf("size must be > 0")
		}
		if item.Size > 65535 {
			return SizeDist{}, fmt.Errorf("size exceeds 65535: %d", item.Size)
		}
		total += item.Weight
	}
	if total == 0 {
		return SizeDist{}, fmt.Errorf("size dist has no weights")
	}
	return SizeDist{Items: items, Total: total}, nil
}

func parseWeight(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("missing weight")
	}
	weight, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid weight: %v", err)
	}
	if weight <= 0 {
		return 0, fmt.Errorf("weight must be > 0")
	}
	return weight, nil
}
