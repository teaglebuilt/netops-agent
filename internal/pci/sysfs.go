package pci

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	pciBaseClassDisplay         = 0x03
	pciBaseClassProcessingAccel = 0x12
)

// Device is a display or processing-accelerator PCI function observed via sysfs.
type Device struct {
	Slot             string
	Vendor           uint16
	Device           uint16
	Class            uint32
	Driver           string
	LinkSpeedGTPS    float64
	LinkWidth        uint32
	MaxLinkSpeedGTPS float64
	MaxLinkWidth     uint32
	AERCorrectable   uint64
	AERNonFatal      uint64
	AERFatal         uint64
	HasAER           bool
}

// ThunderboltDevice is a Thunderbolt/USB4 device with an authorization state.
type ThunderboltDevice struct {
	ID         string
	Name       string
	Authorized bool
}

// ScanGPUs lists GPU-class PCI functions under sysfsRoot (usually /sys or /host/sys).
func ScanGPUs(sysfsRoot string) ([]Device, error) {
	dir := filepath.Join(sysfsRoot, "bus", "pci", "devices")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var out []Device
	for _, e := range entries {
		slot := e.Name()
		devDir := filepath.Join(dir, slot)
		class, err := readHexFile(filepath.Join(devDir, "class"), 24)
		if err != nil {
			continue
		}
		if !IsGPUClass(uint32(class)) {
			continue
		}
		vendor, err := readHexFile(filepath.Join(devDir, "vendor"), 16)
		if err != nil {
			continue
		}
		device, err := readHexFile(filepath.Join(devDir, "device"), 16)
		if err != nil {
			continue
		}

		d := Device{
			Slot:   slot,
			Vendor: uint16(vendor),
			Device: uint16(device),
			Class:  uint32(class),
			Driver: readDriver(devDir),
		}
		d.LinkSpeedGTPS = readLinkSpeed(filepath.Join(devDir, "current_link_speed"))
		d.MaxLinkSpeedGTPS = readLinkSpeed(filepath.Join(devDir, "max_link_speed"))
		d.LinkWidth = readUintFile(filepath.Join(devDir, "current_link_width"))
		d.MaxLinkWidth = readUintFile(filepath.Join(devDir, "max_link_width"))

		corr, corrOK := tryReadUintFile(filepath.Join(devDir, "aer_dev_correctable"))
		nonfatal, nfOK := tryReadUintFile(filepath.Join(devDir, "aer_dev_nonfatal"))
		fatal, fatalOK := tryReadUintFile(filepath.Join(devDir, "aer_dev_fatal"))
		if corrOK || nfOK || fatalOK {
			d.HasAER = true
			d.AERCorrectable = corr
			d.AERNonFatal = nonfatal
			d.AERFatal = fatal
		}
		out = append(out, d)
	}
	return out, nil
}

// ScanThunderbolt lists Thunderbolt/USB4 devices that expose an authorized file.
func ScanThunderbolt(sysfsRoot string) ([]ThunderboltDevice, error) {
	dir := filepath.Join(sysfsRoot, "bus", "thunderbolt", "devices")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	var out []ThunderboltDevice
	for _, e := range entries {
		id := e.Name()
		devDir := filepath.Join(dir, id)
		authPath := filepath.Join(devDir, "authorized")
		raw, err := os.ReadFile(authPath)
		if err != nil {
			continue
		}
		authorized := strings.TrimSpace(string(raw)) == "1"
		name := strings.TrimSpace(readStringFile(filepath.Join(devDir, "device_name")))
		if name == "" {
			name = strings.TrimSpace(readStringFile(filepath.Join(devDir, "device")))
		}
		out = append(out, ThunderboltDevice{
			ID:         id,
			Name:       name,
			Authorized: authorized,
		})
	}
	return out, nil
}

// IsGPUClass reports whether a PCI class code is a display controller or
// processing accelerator (the functions an eGPU actually presents).
func IsGPUClass(class uint32) bool {
	base := (class >> 16) & 0xff
	return base == pciBaseClassDisplay || base == pciBaseClassProcessingAccel
}

// ParseLinkSpeed extracts GT/s from a sysfs current_link_speed value such as
// "8.0 GT/s PCIe". Unknown or empty values return 0.
func ParseLinkSpeed(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "Unknown") {
		return 0
	}
	field, _, _ := strings.Cut(s, " ")
	v, err := strconv.ParseFloat(field, 64)
	if err != nil {
		return 0
	}
	return v
}

func readHexFile(path string, bits int) (uint64, error) {
	s := strings.TrimSpace(readStringFile(path))
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	if s == "" {
		return 0, fmt.Errorf("empty %s", path)
	}
	return strconv.ParseUint(s, 16, bits)
}

func readLinkSpeed(path string) float64 {
	return ParseLinkSpeed(readStringFile(path))
}

func readUintFile(path string) uint32 {
	v, _ := tryReadUintFile(path)
	return uint32(v)
}

func tryReadUintFile(path string) (uint64, bool) {
	s := strings.TrimSpace(readStringFile(path))
	if s == "" {
		return 0, false
	}
	field, _, _ := strings.Cut(s, " ")
	base := 10
	if rest, found := strings.CutPrefix(field, "0x"); found {
		field, base = rest, 16
	} else if rest, found := strings.CutPrefix(field, "0X"); found {
		field, base = rest, 16
	}
	v, err := strconv.ParseUint(field, base, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func readDriver(devDir string) string {
	target, err := os.Readlink(filepath.Join(devDir, "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(target)
}

func readStringFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}
