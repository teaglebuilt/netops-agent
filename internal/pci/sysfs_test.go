package pci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsGPUClass(t *testing.T) {
	t.Parallel()
	cases := []struct {
		class uint32
		want  bool
	}{
		{0x030000, true},  // VGA
		{0x030200, true},  // 3D
		{0x120000, true},  // processing accelerator
		{0x040300, false}, // HD audio on the same card
		{0x0c0330, false}, // USB
		{0x060400, false}, // PCI bridge
	}
	for _, tc := range cases {
		if got := IsGPUClass(tc.class); got != tc.want {
			t.Errorf("IsGPUClass(0x%06x) = %v, want %v", tc.class, got, tc.want)
		}
	}
}

func TestParseLinkSpeed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want float64
	}{
		{"8.0 GT/s PCIe", 8},
		{"2.5 GT/s", 2.5},
		{"16.0 GT/s PCIe\n", 16},
		{"Unknown", 0},
		{"", 0},
		{"not a speed", 0},
	}
	for _, tc := range cases {
		if got := ParseLinkSpeed(tc.in); got != tc.want {
			t.Errorf("ParseLinkSpeed(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestScanGPUs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePCI(t, root, "0000:c1:00.0", map[string]string{
		"vendor":              "0x10de",
		"device":              "0x2684",
		"class":               "0x030000",
		"current_link_speed":  "8.0 GT/s PCIe",
		"current_link_width":  "4",
		"max_link_speed":      "16.0 GT/s PCIe",
		"max_link_width":      "16",
		"aer_dev_correctable": "0xa",
		"aer_dev_nonfatal":    "0",
		"aer_dev_fatal":       "1",
	})
	mustSymlink(t, filepath.Join(root, "bus", "pci", "devices", "0000:c1:00.0", "driver"),
		"/sys/bus/pci/drivers/vfio-pci")

	writePCI(t, root, "0000:c1:00.1", map[string]string{
		"vendor": "0x10de",
		"device": "0x22bb",
		"class":  "0x040300",
	})

	devs, err := ScanGPUs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 1 {
		t.Fatalf("got %d devices, want 1 GPU (audio function should be skipped)", len(devs))
	}
	d := devs[0]
	if d.Slot != "0000:c1:00.0" {
		t.Errorf("slot = %q", d.Slot)
	}
	if d.Vendor != 0x10de || d.Device != 0x2684 {
		t.Errorf("ids = 0x%04x:0x%04x", d.Vendor, d.Device)
	}
	if d.Driver != "vfio-pci" {
		t.Errorf("driver = %q, want vfio-pci", d.Driver)
	}
	if d.LinkSpeedGTPS != 8 || d.LinkWidth != 4 {
		t.Errorf("link = %v GT/s x%d", d.LinkSpeedGTPS, d.LinkWidth)
	}
	if d.MaxLinkSpeedGTPS != 16 || d.MaxLinkWidth != 16 {
		t.Errorf("max link = %v GT/s x%d", d.MaxLinkSpeedGTPS, d.MaxLinkWidth)
	}
	if !d.HasAER || d.AERCorrectable != 10 || d.AERFatal != 1 {
		t.Errorf("aer = %+v", d)
	}
}

func TestScanGPUsMissingSysfs(t *testing.T) {
	t.Parallel()
	devs, err := ScanGPUs(filepath.Join(t.TempDir(), "nope"))
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 0 {
		t.Fatalf("got %d devices, want none", len(devs))
	}
}

func TestScanThunderbolt(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTB(t, root, "0-0", map[string]string{
		"device_name": "Host Controller",
	})
	writeTB(t, root, "0-1", map[string]string{
		"authorized":  "1",
		"device_name": "eGPU Enclosure",
	})
	writeTB(t, root, "0-3", map[string]string{
		"authorized":  "0",
		"device_name": "Unauthorized Dock",
	})

	devs, err := ScanThunderbolt(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 {
		t.Fatalf("got %d thunderbolt devices, want 2 with authorized files", len(devs))
	}
	byID := map[string]ThunderboltDevice{}
	for _, d := range devs {
		byID[d.ID] = d
	}
	if !byID["0-1"].Authorized || byID["0-1"].Name != "eGPU Enclosure" {
		t.Errorf("0-1 = %+v", byID["0-1"])
	}
	if byID["0-3"].Authorized {
		t.Errorf("0-3 should not be authorized: %+v", byID["0-3"])
	}
}

func writePCI(t *testing.T, root, slot string, files map[string]string) {
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

func writeTB(t *testing.T, root, id string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, "bus", "thunderbolt", "devices", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func mustSymlink(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
