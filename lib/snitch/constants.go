package snitch

import (
	"github.com/r3boot/go-snitch/lib/ftrace"
	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/procfs"
)

const (

)

type Engine struct {
	useFtrace bool
	ftrace    *ftrace.Ftrace
	procfs    *procfs.ProcFS
}

var (
	log *logger.Logger
)
