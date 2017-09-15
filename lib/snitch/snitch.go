package snitch

import (
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/ftrace"
	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/procfs"
)

func NewEngine(l *logger.Logger) (*Engine, error) {
	log = l

	s := &Engine{
		useFtrace: ftrace.HasFtrace(),
		procfs: procfs.NewProcFS(l),
	}

	if s.useFtrace {
		s.ftrace = ftrace.NewFtraceProbe(l)
		s.ftrace.Disable()
		s.ftrace.Enable()
		go s.ftrace.Slurp()
	} else {
		fmt.Fprintf(os.Stderr, "Warning: your kernel lacks ftrace support, falling back to /proc")
	}

	return s, nil
}
