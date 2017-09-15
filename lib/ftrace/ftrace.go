package ftrace

import "github.com/r3boot/go-snitch/lib/logger"

func NewFtraceProbe(l *logger.Logger) *Ftrace {
	log = l

	return &Ftrace{
		procmap: make(map[string]*Proc, MAX_PROCS),
	}
}
