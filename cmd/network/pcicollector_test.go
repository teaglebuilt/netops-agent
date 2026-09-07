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

	c := newPCICollector(root, nil, nil)

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
