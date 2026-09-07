package main

import (
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

type srttHistogramCollector struct {
	m    *ebpf.Map
	desc *prometheus.Desc
}

func (c *srttHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *srttHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	counts, err := readPerCPUBuckets(c.m, srttNumBuckets)
	if err != nil {
		slog.Warn("read srtt map", "err", err)
		return
	}

	buckets := make(map[float64]uint64, srttNumBuckets-1)
	var cumulative uint64
	for i := 0; i < srttNumBuckets; i++ {
		cumulative += counts[i]
		if i == srttNumBuckets-1 {
			break
		}
		// Bucket i covers scaled srtt_us in [2^i, 2^(i+1)). Scaled = actual_us × 8.
		leSeconds := float64(uint64(1)<<(i+1)) / 8.0 / 1e6
		buckets[leSeconds] = cumulative
	}

	ch <- prometheus.MustNewConstHistogram(c.desc, cumulative, 0, buckets)
}

type dnsLatencyHistogramCollector struct {
	m    *ebpf.Map
	desc *prometheus.Desc
}

func (c *dnsLatencyHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *dnsLatencyHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	counts, err := readPerCPUBuckets(c.m, dnsNumBuckets)
	if err != nil {
		slog.Warn("read dns latency map", "err", err)
		return
	}

	buckets := make(map[float64]uint64, dnsNumBuckets-1)
	var cumulative uint64
	for i := 0; i < dnsNumBuckets; i++ {
		cumulative += counts[i]
		if i == dnsNumBuckets-1 {
			break
		}
		// Bucket i covers latency_us in [2^i, 2^(i+1)); no kernel scaling.
		leSeconds := float64(uint64(1)<<(i+1)) / 1e6
		buckets[leSeconds] = cumulative
	}

	ch <- prometheus.MustNewConstHistogram(c.desc, cumulative, 0, buckets)
}

func readPerCPUBuckets(m *ebpf.Map, n int) ([]uint64, error) {
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		key := uint32(i)
		var values []uint64
		if err := m.Lookup(&key, &values); err != nil {
			return nil, err
		}
		for _, v := range values {
			out[i] += v
		}
	}
	return out, nil
}
