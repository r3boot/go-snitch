package handleripc

import (
	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/request"
)

type HandlerIPCService struct {
	conn   *dbus.Conn
	daemon dbus.BusObject
}

type HandlerBus int

var (
	rw           *request.RequestWindow
	sessionCache *rules.SessionCache
	log          *logger.Logger
)
