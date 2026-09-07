package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	netops "github.com/teaglebuilt/netops/internal/bpf"
)

const sysfsEnvVar = "NETOPS_SYSFS"

func sysfsRoot() string {
	if v := os.Getenv(sysfsEnvVar); v != "" {
		return v
	}
	return "/sys"
}

type pciPrograms struct {
	coll       *ebpf.Collection
	addLink    link.Link
	removeLink link.Link
	probeMap   *ebpf.Map
	removeMap  *ebpf.Map
}

func (p *pciPrograms) Close() {
	if p == nil {
		return
	}
	if p.addLink != nil {
		_ = p.addLink.Close()
	}
	if p.removeLink != nil {
		_ = p.removeLink.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
}

// setupPCI loads and attaches the optional GPU-class PCI lifecycle programs.
// Failure is returned to the caller so the agent can keep serving network
// metrics on nodes without these symbols.
func setupPCI() (*pciPrograms, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(netops.PCIeObject))
	if err != nil {
		return nil, fmt.Errorf("load pci bpf spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new pci bpf collection: %w", err)
	}

	addProg := coll.Programs["count_pci_add"]
	if addProg == nil {
		coll.Close()
		return nil, fmt.Errorf("program count_pci_add not found in pci collection")
	}
	removeProg := coll.Programs["count_pci_remove"]
	if removeProg == nil {
		coll.Close()
		return nil, fmt.Errorf("program count_pci_remove not found in pci collection")
	}
	probeMap := coll.Maps["netops_pci_probe_total"]
	if probeMap == nil {
		coll.Close()
		return nil, fmt.Errorf("map netops_pci_probe_total not found in pci collection")
	}
	removeMap := coll.Maps["netops_pci_remove_total"]
	if removeMap == nil {
		coll.Close()
		return nil, fmt.Errorf("map netops_pci_remove_total not found in pci collection")
	}

	addLink, err := link.AttachTracing(link.TracingOptions{
		Program:    addProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach fentry pci_bus_add_device: %w", err)
	}

	removeLink, err := link.AttachTracing(link.TracingOptions{
		Program:    removeProg,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		_ = addLink.Close()
		coll.Close()
		return nil, fmt.Errorf("attach fentry pci_stop_and_remove_bus_device: %w", err)
	}

	slog.Info("attached fentry", "program", "pci_bus_add_device")
	slog.Info("attached fentry", "program", "pci_stop_and_remove_bus_device")

	return &pciPrograms{
		coll:       coll,
		addLink:    addLink,
		removeLink: removeLink,
		probeMap:   probeMap,
		removeMap:  removeMap,
	}, nil
}
