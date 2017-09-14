package snitch

import (
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/kernel"
)

func NewSnitch() *Snitch {
	s := &Snitch{
		useFtrace: kernel.HasFtrace(),
	}

	if s.useFtrace {
		s.procMon = kernel.NewProcMon()
		s.procMon.Disable()
		s.procMon.Enable()
		go s.procMon.Slurp()
	} else {
		fmt.Fprintf(os.Stderr, "Warning: your kernel lacks ftrace support, falling back to /proc")
	}

	return s
}
