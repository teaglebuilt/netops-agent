package main

import (
	"log/slog"
	"os"
	"strings"
)

const roleEnvVar = "NETOPS_ROLE"

type role string

const (
	roleHost  role = "host"
	roleGuest role = "guest"
)

func (r role) exportsHostFabricState() bool { return r == roleHost }

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
