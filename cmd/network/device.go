package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

const procNetRoutePath = "/proc/net/route"
const rtfGateway = 0x2

func discoverNetworks() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", fmt.Errorf("open %s: %w", procNetRoutePath, err)
	}
	defer f.Close()
	return parseDefaultNIC(f)
}

func parseDefaultNIC(r io.Reader) (string, error) {
	scanner := bufio.NewScanner(r)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read %s: %w", procNetRoutePath, err)
		}
		return "", fmt.Errorf("no default route found in %s (empty table)", procNetRoutePath)
	}

	bestNIC := ""
	bestMetric := uint64(math.MaxUint64)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		iface := fields[0]
		destination := fields[1]
		flagsHex := fields[3]
		metricStr := fields[6]

		if destination != "00000000" {
			continue
		}

		flags, err := strconv.ParseUint(flagsHex, 16, 32)
		if err != nil {
			continue
		}
		if flags&rtfGateway == 0 {
			continue
		}

		metric, err := strconv.ParseUint(metricStr, 10, 64)
		if err != nil {
			continue
		}

		if metric < bestMetric {
			bestMetric = metric
			bestNIC = iface
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan %s: %w", procNetRoutePath, err)
	}

	if bestNIC == "" {
		return "", fmt.Errorf("no default route found in %s", procNetRoutePath)
	}
	return bestNIC, nil
}
