package main

import (
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"genflux/internal/pcapgen"
	"genflux/internal/replay"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "pcap":
		handlePcap(os.Args[2:])
	case "replay":
		handleReplay(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("genflux - pcap generation and replay")
	fmt.Println("")
	fmt.Println("Usage:")
	fmt.Println("  genflux pcap gen [flags]")
	fmt.Println("  genflux replay [flags]")
}

func handlePcap(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "missing pcap subcommand")
		usage()
		os.Exit(1)
	}
	switch args[0] {
	case "gen":
		pcapGen(args[1:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown pcap subcommand: %s\n", args[0])
		usage()
		os.Exit(1)
	}
}

func pcapGen(args []string) {
	cfg := pcapgen.DefaultConfig()
	fs := flag.NewFlagSet("genflux pcap gen", flag.ExitOnError)
	internal := fs.Int("internal-hosts", cfg.InternalHosts, "number of internal hosts")
	external := fs.Int("external-hosts", cfg.ExternalHosts, "number of external hosts")
	minDur := fs.Int("min-duration", int(cfg.MinDuration.Seconds()), "min duration seconds")
	maxDur := fs.Int("max-duration", int(cfg.MaxDuration.Seconds()), "max duration seconds")
	fileCount := fs.Int("file-count", cfg.FileCount, "number of files to generate")
	outDir := fs.String("out-dir", cfg.OutDir, "output directory")
	outFile := fs.String("out-file", cfg.OutFile, "output file path (requires file-count=1)")
	startTime := fs.String("start-time", cfg.StartTime.Format("Mon Jan 2 15:04:05 2006"), "start time (Mon Jan 2 15:04:05 2006 or RFC3339)")
	exactSize := fs.String("exact-size", "", "exact total file size with unit (e.g. 1g, 0.5gb, 1024m; uses 1024-based units)")
	seed := fs.Int64("seed", cfg.Seed, "random seed (int64)")
	flowCount := fs.Int("flow-count", cfg.FlowCount, "number of unique 5-tuples to generate (0=disabled)")
	packetsPerFlow := fs.Int("packets-per-flow", cfg.PacketsPerFlow, "packets per 5-tuple when flow-count is set")
	_ = fs.Parse(args)

	parsedStart, err := parseTime(*startTime)
	if err != nil {
		log.Fatalf("invalid start-time: %v", err)
	}

	cfg.InternalHosts = *internal
	cfg.ExternalHosts = *external
	cfg.MinDuration = time.Duration(*minDur) * time.Second
	cfg.MaxDuration = time.Duration(*maxDur) * time.Second
	cfg.FileCount = *fileCount
	cfg.OutDir = *outDir
	cfg.OutFile = *outFile
	cfg.StartTime = parsedStart
	cfg.Seed = *seed
	cfg.FlowCount = *flowCount
	cfg.PacketsPerFlow = *packetsPerFlow
	if *exactSize != "" {
		size, err := parseSize(*exactSize)
		if err != nil {
			log.Fatalf("invalid exact-size: %v", err)
		}
		if size > math.MaxInt {
			log.Fatalf("exact-size too large: %d", size)
		}
		cfg.ExactBytes = int(size)
	}
	if cfg.ExactBytes <= 0 {
		log.Fatal("exact-size is required")
	}

	if err := pcapgen.Generate(cfg); err != nil {
		log.Fatal(err)
	}
}

func handleReplay(args []string) {
	fs := flag.NewFlagSet("genflux replay", flag.ExitOnError)
	inPath := fs.String("in", "", "input pcap path")
	iface := fs.String("iface", "", "network interface (e.g. eth0)")
	mode := fs.String("mode", string(replay.ModeTimestamp), "timestamp|mbps|pps")
	mbps := fs.Float64("mbps", 0, "rate limit in Mbps (mode=mbps)")
	pps := fs.Float64("pps", 0, "rate limit in packets per second (mode=pps)")
	loop := fs.Int("loop", 1, "loop count (0=infinite)")
	limit := fs.Int("limit", 0, "packet limit across all loops (0=unlimited)")
	stats := fs.Int("stats-interval", 1, "stats interval in seconds")
	_ = fs.Parse(args)

	cfg := replay.Config{
		InPath:        *inPath,
		Iface:         *iface,
		Mode:          replay.Mode(*mode),
		Mbps:          *mbps,
		Pps:           *pps,
		Loop:          *loop,
		Limit:         *limit,
		StatsInterval: time.Duration(*stats) * time.Second,
	}
	if err := replay.Replay(cfg); err != nil {
		log.Fatal(err)
	}
}

func parseTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.ParseInLocation("Mon Jan 2 15:04:05 2006", value, time.Local)
}

func parseSize(value string) (int64, error) {
	v := strings.TrimSpace(strings.ToLower(value))
	if v == "" {
		return 0, fmt.Errorf("empty size")
	}

	mult := int64(1)
	switch {
	case strings.HasSuffix(v, "tib"):
		mult = 1024 * 1024 * 1024 * 1024
		v = strings.TrimSuffix(v, "tib")
	case strings.HasSuffix(v, "tb"), strings.HasSuffix(v, "t"):
		mult = 1024 * 1024 * 1024 * 1024
		v = strings.TrimSuffix(strings.TrimSuffix(v, "tb"), "t")
	case strings.HasSuffix(v, "gib"):
		mult = 1024 * 1024 * 1024
		v = strings.TrimSuffix(v, "gib")
	case strings.HasSuffix(v, "gb"), strings.HasSuffix(v, "g"):
		mult = 1024 * 1024 * 1024
		v = strings.TrimSuffix(strings.TrimSuffix(v, "gb"), "g")
	case strings.HasSuffix(v, "mib"):
		mult = 1024 * 1024
		v = strings.TrimSuffix(v, "mib")
	case strings.HasSuffix(v, "mb"), strings.HasSuffix(v, "m"):
		mult = 1024 * 1024
		v = strings.TrimSuffix(strings.TrimSuffix(v, "mb"), "m")
	case strings.HasSuffix(v, "kib"):
		mult = 1024
		v = strings.TrimSuffix(v, "kib")
	case strings.HasSuffix(v, "kb"), strings.HasSuffix(v, "k"):
		mult = 1024
		v = strings.TrimSuffix(strings.TrimSuffix(v, "kb"), "k")
	case strings.HasSuffix(v, "b"):
		mult = 1
		v = strings.TrimSuffix(v, "b")
	}

	v = strings.TrimSpace(v)
	if v == "" {
		return 0, fmt.Errorf("missing numeric value")
	}

	num, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, err
	}
	if num <= 0 {
		return 0, fmt.Errorf("size must be > 0")
	}
	return int64(math.Round(num * float64(mult))), nil
}
