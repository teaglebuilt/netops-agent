package bpf

import _ "embed"

//go:embed netops.bpf.o
var Object []byte

//go:embed trace_pcie.bpf.o
var PCIeObject []byte
