package snitch

import (
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/ftrace"
	"github.com/r3boot/go-snitch/lib/logger"
)

func NewEngine(l *logger.Logger) (*Engine, error) {
	log = l

	s := &Engine{
		useFtrace: ftrace.HasFtrace(),
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
