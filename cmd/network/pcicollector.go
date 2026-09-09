package main

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/teaglebuilt/netops/internal/pci"
)

type pciCollector struct {
	sysfs     string
	role      role
	probeMap  *ebpf.Map
	removeMap *ebpf.Map

	present     *prometheus.Desc
	linkSpeed   *prometheus.Desc
	linkWidth   *prometheus.Desc
	maxSpeed    *prometheus.Desc
	maxWidth    *prometheus.Desc
	aer         *prometheus.Desc
	probeTotal  *prometheus.Desc
	removeTotal *prometheus.Desc
	tbAuth      *prometheus.Desc

	mu      sync.Mutex
	seenPCI map[string]pci.Device
	seenTB  map[string]pci.ThunderboltDevice
}

func newPCICollector(sysfs string, r role, probeMap, removeMap *ebpf.Map) *pciCollector {
	deviceLabels := []string{"slot", "vendor", "device", "driver"}
	return &pciCollector{
		sysfs:     sysfs,
		role:      r,
		probeMap:  probeMap,
		removeMap: removeMap,
		present: prometheus.NewDesc(
			"netops_pci_device_present",
			"1 if a GPU-class PCI function is present on the host bus (display or processing accelerator).",
			deviceLabels, nil,
		),
		linkSpeed: prometheus.NewDesc(
			"netops_pci_link_speed_gtps",
			"Negotiated PCIe link speed in GT/s from sysfs current_link_speed.",
			deviceLabels, nil,
		),
		linkWidth: prometheus.NewDesc(
			"netops_pci_link_width",
			"Negotiated PCIe link width in lanes from sysfs current_link_width.",
			deviceLabels, nil,
		),
		maxSpeed: prometheus.NewDesc(
			"netops_pci_link_speed_max_gtps",
			"Maximum PCIe link speed in GT/s advertised by the function.",
			deviceLabels, nil,
		),
		maxWidth: prometheus.NewDesc(
			"netops_pci_link_width_max",
			"Maximum PCIe link width in lanes advertised by the function.",
			deviceLabels, nil,
		),
		aer: prometheus.NewDesc(
			"netops_pci_aer_errors",
			"PCIe Advanced Error Reporting status from sysfs aer_dev_* files (snapshot, not a scrape counter).",
			[]string{"slot", "vendor", "device", "driver", "severity"}, nil,
		),
		probeTotal: prometheus.NewDesc(
			"netops_pci_probe_total",
			"GPU-class PCI functions observed via fentry on pci_bus_add_device.",
			nil, nil,
		),
		removeTotal: prometheus.NewDesc(
			"netops_pci_remove_total",
			"GPU-class PCI functions observed via fentry on pci_stop_and_remove_bus_device.",
			nil, nil,
		),
		tbAuth: prometheus.NewDesc(
			"netops_thunderbolt_authorized",
			"1 if the Thunderbolt/USB4 device is authorized. Missing devices emit 0 after first observation.",
			[]string{"id", "name"}, nil,
		),
		seenPCI: make(map[string]pci.Device),
		seenTB:  make(map[string]pci.ThunderboltDevice),
	}
}

func (c *pciCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.present
	// Link, AER and Thunderbolt state only exists at the hypervisor. See role.
	if c.role.exportsHostFabricState() {
		ch <- c.linkSpeed
		ch <- c.linkWidth
		ch <- c.maxSpeed
		ch <- c.maxWidth
		ch <- c.aer
		ch <- c.tbAuth
	}
	if c.probeMap != nil {
		ch <- c.probeTotal
	}
	if c.removeMap != nil {
		ch <- c.removeTotal
	}
}

func (c *pciCollector) Collect(ch chan<- prometheus.Metric) {
	devs, err := pci.ScanGPUs(c.sysfs)
	if err != nil {
		slog.Warn("pci sysfs scan", "err", err)
	}
	var tb []pci.ThunderboltDevice
	if c.role.exportsHostFabricState() {
		var tbErr error
		tb, tbErr = pci.ScanThunderbolt(c.sysfs)
		if tbErr != nil {
			slog.Warn("thunderbolt sysfs scan", "err", tbErr)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	live := make(map[string]struct{}, len(devs))
	for _, d := range devs {
		live[d.Slot] = struct{}{}
		c.seenPCI[d.Slot] = d
		c.emitDevice(ch, d, 1)
	}
	for slot, d := range c.seenPCI {
		if _, ok := live[slot]; ok {
			continue
		}
		c.emitDevice(ch, d, 0)
	}

	liveTB := make(map[string]struct{}, len(tb))
	for _, d := range tb {
		liveTB[d.ID] = struct{}{}
		c.seenTB[d.ID] = d
		c.emitTB(ch, d)
	}
	for id, d := range c.seenTB {
		if _, ok := liveTB[id]; ok {
			continue
		}
		d.Authorized = false
		c.emitTB(ch, d)
	}

	if c.probeMap != nil {
		if total, err := readPerCPUSum(c.probeMap); err != nil {
			slog.Warn("read pci probe map", "err", err)
		} else {
			ch <- prometheus.MustNewConstMetric(c.probeTotal, prometheus.CounterValue, float64(total))
		}
	}
	if c.removeMap != nil {
		if total, err := readPerCPUSum(c.removeMap); err != nil {
			slog.Warn("read pci remove map", "err", err)
		} else {
			ch <- prometheus.MustNewConstMetric(c.removeTotal, prometheus.CounterValue, float64(total))
		}
	}
}

func (c *pciCollector) emitDevice(ch chan<- prometheus.Metric, d pci.Device, present float64) {
	labels := []string{d.Slot, fmt.Sprintf("0x%04x", d.Vendor), fmt.Sprintf("0x%04x", d.Device), d.Driver}
	ch <- prometheus.MustNewConstMetric(c.present, prometheus.GaugeValue, present, labels...)
	// In a guest the remaining registers are QEMU's invention, not the device's.
	// Presence is the one fact this vantage point actually establishes.
	if !c.role.exportsHostFabricState() {
		return
	}
	if present == 0 {
		// device_present already carries the fact. Publishing 0 GT/s for a device
		// that is simply gone would be indistinguishable from a trained-down link.
		return
	}
	// Only publish link state the kernel actually reported. A Thunderbolt-tunnelled
	// endpoint has no native PCIe link: current_link_* read EINVAL and max_link_*
	// return "Unknown"/255. Those are absent measurements, not slow ones.
	if d.HasLink {
		ch <- prometheus.MustNewConstMetric(c.linkSpeed, prometheus.GaugeValue, d.LinkSpeedGTPS, labels...)
		ch <- prometheus.MustNewConstMetric(c.linkWidth, prometheus.GaugeValue, float64(d.LinkWidth), labels...)
	}
	if d.HasMaxLink {
		ch <- prometheus.MustNewConstMetric(c.maxSpeed, prometheus.GaugeValue, d.MaxLinkSpeedGTPS, labels...)
		ch <- prometheus.MustNewConstMetric(c.maxWidth, prometheus.GaugeValue, float64(d.MaxLinkWidth), labels...)
	}
	if d.HasAER {
		ch <- prometheus.MustNewConstMetric(c.aer, prometheus.GaugeValue, float64(d.AERCorrectable), d.Slot, fmt.Sprintf("0x%04x", d.Vendor), fmt.Sprintf("0x%04x", d.Device), d.Driver, "correctable")
		ch <- prometheus.MustNewConstMetric(c.aer, prometheus.GaugeValue, float64(d.AERNonFatal), d.Slot, fmt.Sprintf("0x%04x", d.Vendor), fmt.Sprintf("0x%04x", d.Device), d.Driver, "nonfatal")
		ch <- prometheus.MustNewConstMetric(c.aer, prometheus.GaugeValue, float64(d.AERFatal), d.Slot, fmt.Sprintf("0x%04x", d.Vendor), fmt.Sprintf("0x%04x", d.Device), d.Driver, "fatal")
	}
}

func (c *pciCollector) emitTB(ch chan<- prometheus.Metric, d pci.ThunderboltDevice) {
	auth := 0.0
	if d.Authorized {
		auth = 1
	}
	ch <- prometheus.MustNewConstMetric(c.tbAuth, prometheus.GaugeValue, auth, d.ID, d.Name)
}
