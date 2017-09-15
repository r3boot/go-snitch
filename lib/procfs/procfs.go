package procfs

import "github.com/r3boot/go-snitch/lib/logger"

func NewProcFS(l *logger.Logger) *ProcFS {
	return &ProcFS{}
}
