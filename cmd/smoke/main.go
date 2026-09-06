package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	netops "github.com/teaglebuilt/netops/internal/bpf"
)

type attachStep struct {
	progName string
	describe string
	attach   func(prog *ebpf.Program) (link.Link, error)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "cismoke: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "cismoke: rlimit.RemoveMemlock failed (continuing, kernel >= 5.11 doesn't need it): %v\n", err)
	}

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netops.Object))
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}

	expected := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		expected = append(expected, name)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		printVerifierError(err)
		return fmt.Errorf("new bpf collection: %w", err)
	}
	defer coll.Close()

	fmt.Printf("LOAD: ok (%d programs verified)\n", len(expected))
	for _, name := range expected {
		fmt.Printf("  - %s\n", name)
	}

	loIface, err := net.InterfaceByName("lo")
	if err != nil {
		return fmt.Errorf("lookup loopback interface: %w", err)
	}

	if loIface.Index == 0 {
		return fmt.Errorf("loopback interface returned zero ifindex (unexpected on Linux)")
	}

	steps := []attachStep{
		{
			progName: "count_rx",
			describe: "tcx/ingress on lo",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTCX(link.TCXOptions{
					Interface: loIface.Index,
					Program:   prog,
					Attach:    ebpf.AttachTCXIngress,
				})
			},
		},
		{
			progName: "count_tcp_retransmit",
			describe: "fentry tcp_retransmit_skb",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFEntry,
				})
			},
		},
		{
			progName: "record_tcp_srtt",
			describe: "fentry tcp_rcv_established",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFEntry,
				})
			},
		},
		{
			progName: "record_dns_query",
			describe: "fentry udp_sendmsg",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFEntry,
				})
			},
		},
		{
			progName: "record_dns_response",
			describe: "fexit udp_recvmsg",
			attach: func(prog *ebpf.Program) (link.Link, error) {
				return link.AttachTracing(link.TracingOptions{
					Program:    prog,
					AttachType: ebpf.AttachTraceFExit,
				})
			},
		},
	}

	covered := make(map[string]struct{}, len(steps))
	for _, s := range steps {
		covered[s.progName] = struct{}{}
	}
	var missing []string
	for _, name := range expected {
		if _, ok := covered[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("smoke test missing attach coverage for programs: %s "+
			"(add an entry to steps in cmd/cismoke/main.go)", strings.Join(missing, ", "))
	}

	var failures int
	for _, step := range steps {
		prog := coll.Programs[step.progName]
		if prog == nil {
			fmt.Printf("FAIL %s: program not present in collection\n", step.progName)
			failures++
			continue
		}
		l, err := step.attach(prog)
		if err != nil {
			fmt.Printf("FAIL %s (%s): %v\n", step.progName, step.describe, err)
			failures++
			continue
		}
		fmt.Printf("ATTACH %s (%s): ok\n", step.progName, step.describe)

		if cerr := l.Close(); cerr != nil {
			fmt.Printf("WARN %s: close link: %v\n", step.progName, cerr)
		}
	}

	if failures > 0 {
		return fmt.Errorf("%d program(s) failed to load or attach", failures)
	}
	fmt.Println("OK: all programs verified and attached")
	return nil
}

func printVerifierError(err error) {
	var verr *ebpf.VerifierError
	if errors.As(err, &verr) {
		fmt.Fprintln(os.Stderr, "--- verifier log ---")
		for _, line := range verr.Log {
			fmt.Fprintln(os.Stderr, line)
		}
		fmt.Fprintln(os.Stderr, "--- end verifier log ---")
	}
}
