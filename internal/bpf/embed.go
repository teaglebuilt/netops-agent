package bpf

import _ "embed"

//go:embed netops.bpf.o
var Object []byte
