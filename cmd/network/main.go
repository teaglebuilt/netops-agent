package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	netops "github.com/teaglebuilt/netops/internal/bpf"
)

const (
	metricsListenAddr     = ":9101"
	mapKey                = uint32(0)
	ciliumIngressProgName = "cil_from_netdev"
	ifaceEnvVar           = "NETOPS_DEVICE"
	srttNumBuckets        = 24
	dnsNumBuckets         = 24
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if err := run(); err != nil {
		slog.Error("netops exiting", "err", err)
		os.Exit(1)
	}
}

func run() error {
	ifaceName, source, err := resolveIface()
	if err != nil {
		return err
	}
	slog.Info("resolved interface", "iface", ifaceName, "source", source)

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface %q (%s): %w", ifaceName, source, err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netops.Object))
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	slog.Info("formed collection", "collection", coll)

	if err != nil {
		return fmt.Errorf("new bpf collection: %w", err)
	}
	defer coll.Close()

	prog := coll.Programs["count_rx"]
	if prog == nil {
		return errors.New("program count_rx not found in collection")
	}

	rxMap := coll.Maps["netops_rx_bytes"]
	if rxMap == nil {
		return errors.New("map netops_rx_bytes not found in collection")
	}

	retransmitProg := coll.Programs["count_tcp_retransmit"]
	if retransmitProg == nil {
		return errors.New("program count_tcp_retransmit not found in collection")
	}

	retransmitMap := coll.Maps["netops_tcp_retransmits"]
	if retransmitMap == nil {
		return errors.New("map netops_tcp_retransmits not found in collection")
	}

	srttProg := coll.Programs["record_tcp_srtt"]
	if srttProg == nil {
		return errors.New("program record_tcp_srtt not found in collection")
	}

	srttMap := coll.Maps["netops_tcp_srtt_buckets"]
	if srttMap == nil {
		return errors.New("map netops_tcp_srtt_buckets not found in collection")
	}

	if got := srttMap.MaxEntries(); got != srttNumBuckets {
		return fmt.Errorf("srtt bucket count drift: bpf map max_entries=%d, go srttNumBuckets=%d", got, srttNumBuckets)
	}

	dnsQueryProg := coll.Programs["record_dns_query"]
	if dnsQueryProg == nil {
		return errors.New("program record_dns_query not found in collection")
	}

	dnsResponseProg := coll.Programs["record_dns_response"]
	if dnsResponseProg == nil {
		return errors.New("program record_dns_response not found in collection")
	}

	dnsLatencyMap := coll.Maps["netops_dns_latency_buckets"]
	if dnsLatencyMap == nil {
		return errors.New("map netops_dns_latency_buckets not found in collection")
	}

	if got := dnsLatencyMap.MaxEntries(); got != dnsNumBuckets {
		return fmt.Errorf("dns bucket count drift: bpf map max_entries=%d, go dnsNumBuckets=%d", got, dnsNumBuckets)
	}

	opts := link.TCXOptions{
		Interface: iface.Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	}
	ciliumID, err := findProgramByName(ciliumIngressProgName)
	switch {
	case err == nil:
		slog.Info("anchoring before cilium ingress program", "name", ciliumIngressProgName, "id", ciliumID)
		opts.Anchor = link.BeforeProgramByID(ciliumID)
	case errors.Is(err, os.ErrNotExist):
		slog.Info("no cilium ingress program found; attaching with default ordering")
	default:
		// e.g. EPERM if CAP_SYS_ADMIN is missing. Surface it loudly rather
		// than silently degrading to default ordering — that's exactly the
		// failure mode this PR is trying to prevent.
		return fmt.Errorf("discover cilium program: %w", err)
	}

	tcxLink, err := link.AttachTCX(opts)
	if err != nil {
		return fmt.Errorf("attach tcx ingress on %s: %w", iface.Name, err)
	}
	defer tcxLink.Close()

	slog.Info("attached", "iface", iface.Name, "ifindex", iface.Index)

	retransmitLink, err := link.AttachTracing(link.TracingOptions{
		Program:    retransmitProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("attach fentry tcp_retransmit_skb: %w", err)
	}
	defer retransmitLink.Close()

	slog.Info("attached fentry", "program", "tcp_retransmit_skb")

	srttLink, err := link.AttachTracing(link.TracingOptions{
		Program:    srttProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("attach fentry tcp_rcv_established: %w", err)
	}
	defer srttLink.Close()

	slog.Info("attached fentry", "program", "tcp_rcv_established")

	dnsQueryLink, err := link.AttachTracing(link.TracingOptions{
		Program:    dnsQueryProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		return fmt.Errorf("attach fentry udp_sendmsg: %w", err)
	}
	defer dnsQueryLink.Close()

	slog.Info("attached fentry", "program", "udp_sendmsg")

	dnsResponseLink, err := link.AttachTracing(link.TracingOptions{
		Program:    dnsResponseProg,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		return fmt.Errorf("attach fexit udp_recvmsg: %w", err)
	}
	defer dnsResponseLink.Close()

	slog.Info("attached fexit", "program", "udp_recvmsg")

	rxBytes := prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name:        "netops_rx_bytes_total",
			Help:        "Total bytes received on the host's primary interface, observed at tcx ingress.",
			ConstLabels: prometheus.Labels{"iface": iface.Name},
		},
		func() float64 {
			total, err := readPerCPUSum(rxMap)
			if err != nil {
				slog.Warn("read map", "err", err)
				return 0
			}
			return float64(total)
		},
	)
	prometheus.MustRegister(rxBytes)

	retransmitCounter := prometheus.NewCounterFunc(
		prometheus.CounterOpts{
			Name: "netops_tcp_retransmits_total",
			Help: "Total TCP retransmits observed via fentry on tcp_retransmit_skb.",
		},
		func() float64 {
			total, err := readPerCPUSum(retransmitMap)
			if err != nil {
				slog.Warn("read retransmit map", "err", err)
				return 0
			}
			return float64(total)
		},
	)
	prometheus.MustRegister(retransmitCounter)

	prometheus.MustRegister(&srttHistogramCollector{
		m: srttMap,
		desc: prometheus.NewDesc(
			"netops_tcp_srtt_microseconds",
			"TCP smoothed-RTT histogram observed via fentry on tcp_rcv_established. "+
				"Buckets are powers of two on the kernel's scaled srtt_us value "+
				"(actual µs × 8); le labels are converted to seconds.",
			nil, nil,
		),
	})

	prometheus.MustRegister(&dnsLatencyHistogramCollector{
		m: dnsLatencyMap,
		desc: prometheus.NewDesc(
			"netops_dns_query_microseconds",
			"DNS query latency histogram. Measured as the wall-clock interval "+
				"from udp_sendmsg (sk_dport == 53) to a successful udp_recvmsg "+
				"return on the same 4-tuple. Buckets are powers of two on µs; "+
				"le labels are converted to seconds.",
			nil, nil,
		),
	})

	var probeMap, removeMap *ebpf.Map
	pciProg, err := setupPCI()
	if err != nil {
		slog.Warn("pci fabric bpf unavailable; sysfs metrics only", "err", err)
	} else {
		defer pciProg.Close()
		probeMap = pciProg.probeMap
		removeMap = pciProg.removeMap
	}

	sysfs := sysfsRoot()
	slog.Info("pci fabric collector", "sysfs", sysfs)
	prometheus.MustRegister(newPCICollector(sysfs, probeMap, removeMap))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:              metricsListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("metrics server listening", "addr", metricsListenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("metrics server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Warn("server shutdown", "err", err)
	}
	return nil
}

func resolveIface() (name, source string, err error) {
	if v := os.Getenv(ifaceEnvVar); v != "" {
		return v, "env:" + ifaceEnvVar, nil
	}
	iface, err := discoverNetworks()
	if err != nil {
		return "", "", fmt.Errorf("discover default-route interface (set %s to override): %w", ifaceEnvVar, err)
	}
	return iface, "default-route", nil
}

func readPerCPUSum(m *ebpf.Map) (uint64, error) {
	key := mapKey
	var values []uint64
	if err := m.Lookup(&key, &values); err != nil {
		return 0, err
	}
	var sum uint64
	for _, v := range values {
		sum += v
	}
	return sum, nil
}
