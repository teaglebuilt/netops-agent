package main

import (
	"log/slog"
	"os"
	"strings"
)

const roleEnvVar = "NETOPS_ROLE"

// role is the vantage point the agent observes the PCI fabric from. It matters
// because the VFIO passthrough boundary splits the signals in two, and neither
// side can see the other's.
//
// On a hypervisor (roleHost) sysfs exposes the real PCIe config space: trained
// link speed and width, AER status registers, and the Thunderbolt bus an eGPU
// enclosure attaches over. None of that reaches a guest.
//
// Inside a guest VM (roleGuest) the passed-through function's link and AER
// registers are synthesised by QEMU. A healthy card reports 0 GT/s and 63
// lanes -- values that would trip any "link degraded" alert built on them. The
// guest knows exactly one thing the host cannot: whether the device actually
// arrived in the VM. So roleGuest exports presence and suppresses the rest
// rather than publishing fiction.
type role string

const (
	roleHost  role = "host"
	roleGuest role = "guest"
)

// exportsLinkState reports whether the PCIe link, AER and Thunderbolt series
// are meaningful from this vantage point.
func (r role) exportsLinkState() bool { return r == roleHost }

// agentRole resolves NETOPS_ROLE. Defaults to host: that is the full-fidelity
// reading, and a deployment that forgets to set it should lose no data. The
// Helm chart sets guest explicitly, because the DaemonSet runs on Talos VMs.
func agentRole() role {
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(roleEnvVar))); v {
	case "guest", "vm":
		return roleGuest
	case "", "host", "hypervisor":
		return roleHost
	default:
		slog.Warn("unknown role, defaulting to host", "env", roleEnvVar, "value", v)
		return roleHost
	}
}
