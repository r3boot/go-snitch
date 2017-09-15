package daemonipc

import (
	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/rules"
)

type DaemonIPCService struct {
	conn    *dbus.Conn
	handler dbus.BusObject
}

type DaemonBus int

var (
	log       *logger.Logger
	ruleCache *rules.RuleCache
)
