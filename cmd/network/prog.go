package main

import (
	"errors"
	"os"

	"github.com/cilium/ebpf"
)

func findProgramByName(name string) (ebpf.ProgramID, error) {
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			return 0, os.ErrNotExist
		}
		if err != nil {
			return 0, err
		}

		prog, err := ebpf.NewProgramFromID(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				id = next
				continue
			}
			return 0, err
		}

		info, err := prog.Info()
		prog.Close()
		if err != nil {
			return 0, err
		}
		if info.Name == name {
			return next, nil
		}
		id = next
	}
}
