package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPCICollectorReportsGPUAndUnplug(t *testing.T) {
	root := t.TempDir()
	writePCIDev(t, root, "0000:c1:00.0", map[string]string{
		"vendor":             "0x10de",
		"device":             "0x2684",
		"class":              "0x030000",
		"current_link_speed": "8.0 GT/s PCIe",
		"current_link_width": "4",
		"max_link_speed":     "16.0 GT/s PCIe",
		"max_link_width":     "16",
	})
	if err := os.Symlink("/sys/bus/pci/drivers/vfio-pci",
		filepath.Join(root, "bus", "pci", "devices", "0000:c1:00.0", "driver")); err != nil {
		t.Fatal(err)
	}

	c := newPCICollector(root, roleHost, nil, nil)

	wantPresent := `
# HELP netops_pci_device_present 1 if a GPU-class PCI function is present on the host bus (display or processing accelerator).
# TYPE netops_pci_device_present gauge
netops_pci_device_present{device="0x2684",driver="vfio-pci",slot="0000:c1:00.0",vendor="0x10de"} 1
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(wantPresent), "netops_pci_device_present"); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(filepath.Join(root, "bus", "pci", "devices", "0000:c1:00.0")); err != nil {
		t.Fatal(err)
	}

	wantGone := `
# HELP netops_pci_device_present 1 if a GPU-class PCI function is present on the host bus (display or processing accelerator).
# TYPE netops_pci_device_present gauge
netops_pci_device_present{device="0x2684",driver="vfio-pci",slot="0000:c1:00.0",vendor="0x10de"} 0
`
	if err := testutil.CollectAndCompare(c, strings.NewReader(wantGone), "netops_pci_device_present"); err != nil {
		t.Fatal(err)
	}
}

func writePCIDev(t *testing.T, root, slot string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, "bus", "pci", "devices", slot)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A guest VM reads QEMU's synthesised PCIe config space for a passed-through
// function: on mlops-work-00 a healthy card reports 0 GT/s and 63 lanes.
// Presence is the one fact the guest establishes, so it is the only one it
// may publish -- otherwise every "link degraded" alert fires on healthy nodes.
func TestPCICollectorGuestPublishesPresenceOnly(t *testing.T) {
	root := t.TempDir()
	writePCIDev(t, root, "0000:01:00.0", map[string]string{
		"vendor":             "0x10de",
		"device":             "0x2783",
		"class":              "0x030000",
		"current_link_speed": "Unknown",
		"current_link_width": "63",
		"max_link_speed":     "16.0 GT/s PCIe",
		"max_link_width":     "63",
	})

	c := newPCICollector(root, roleGuest, nil, nil)

	if n := testutil.CollectAndCount(c, "netops_pci_device_present"); n != 1 {
		t.Errorf("device_present series = %d, want 1", n)
	}
	for _, m := range []string{
		"netops_pci_link_speed_gtps",
		"netops_pci_link_width",
		"netops_pci_link_speed_max_gtps",
		"netops_pci_link_width_max",
		"netops_pci_aer_errors",
	} {
		if n := testutil.CollectAndCount(c, m); n != 0 {
			t.Errorf("%s = %d series in guest role, want 0", m, n)
		}
	}
}

// The host vantage point publishes the full set, including the link registers
// the guest had to withhold.
func TestPCICollectorHostPublishesLinkState(t *testing.T) {
	root := t.TempDir()
	writePCIDev(t, root, "0000:c1:00.0", map[string]string{
		"vendor":             "0x10de",
		"device":             "0x2783",
		"class":              "0x030000",
		"current_link_speed": "2.5 GT/s PCIe",
		"current_link_width": "4",
		"max_link_speed":     "16.0 GT/s PCIe",
		"max_link_width":     "16",
	})

	c := newPCICollector(root, roleHost, nil, nil)

	for _, m := range []string{"netops_pci_link_speed_gtps", "netops_pci_link_width_max"} {
		if n := testutil.CollectAndCount(c, m); n != 1 {
			t.Errorf("%s = %d series in host role, want 1", m, n)
		}
	}
}

// Every QEMU guest presents a Bochs VGA adapter at 0x1234:0x1111 in display
// class. Without the vendor denylist it is indistinguishable from a real GPU,
// so a class-only scan reports one on every VM in the fleet.
func TestPCICollectorIgnoresEmulatedVGA(t *testing.T) {
	root := t.TempDir()
	writePCIDev(t, root, "0000:00:01.0", map[string]string{
		"vendor": "0x1234",
		"device": "0x1111",
		"class":  "0x030000",
	})

	c := newPCICollector(root, roleHost, nil, nil)

	if n := testutil.CollectAndCount(c, "netops_pci_device_present"); n != 0 {
		t.Errorf("device_present = %d series for emulated VGA, want 0", n)
	}
}

// Real reading from pve2: an eGPU reached over a Thunderbolt PCIe tunnel has no
// native link, so the kernel returns EINVAL for current_link_* and the unknown
// sentinels for max_link_*. Publishing 0 GT/s and 255 lanes would read as a
// catastrophically degraded link on a perfectly healthy card.
func TestPCICollectorSuppressesUnreadableLink(t *testing.T) {
	root := t.TempDir()
	writePCIDev(t, root, "0000:2e:00.0", map[string]string{
		"vendor":         "0x10de",
		"device":         "0x2783",
		"class":          "0x030000",
		"max_link_speed": "Unknown",
		"max_link_width": "255",
	})

	c := newPCICollector(root, roleHost, nil, nil)

	if n := testutil.CollectAndCount(c, "netops_pci_device_present"); n != 1 {
		t.Errorf("device_present = %d, want 1 (the device is genuinely there)", n)
	}
	for _, m := range []string{
		"netops_pci_link_speed_gtps",
		"netops_pci_link_width",
		"netops_pci_link_speed_max_gtps",
		"netops_pci_link_width_max",
	} {
		if n := testutil.CollectAndCount(c, m); n != 0 {
			t.Errorf("%s = %d series, want 0 when the kernel reports it unknown", m, n)
		}
	}
}

// An unplugged device reports presence 0 and nothing else -- a zeroed link
// gauge would be indistinguishable from one that trained down to nothing.
func TestPCICollectorUnplugPublishesPresenceOnly(t *testing.T) {
	root := t.TempDir()
	writePCIDev(t, root, "0000:c1:00.0", map[string]string{
		"vendor":             "0x10de",
		"device":             "0x2783",
		"class":              "0x030000",
		"current_link_speed": "8.0 GT/s PCIe",
		"current_link_width": "4",
	})
	c := newPCICollector(root, roleHost, nil, nil)
	if n := testutil.CollectAndCount(c, "netops_pci_link_speed_gtps"); n != 1 {
		t.Fatalf("link_speed = %d before unplug, want 1", n)
	}
	if err := os.RemoveAll(filepath.Join(root, "bus", "pci", "devices", "0000:c1:00.0")); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(c, "netops_pci_link_speed_gtps"); n != 0 {
		t.Errorf("link_speed = %d after unplug, want 0", n)
	}
	if n := testutil.CollectAndCount(c, "netops_pci_device_present"); n != 1 {
		t.Errorf("device_present = %d after unplug, want 1 (reporting 0)", n)
	}
}
