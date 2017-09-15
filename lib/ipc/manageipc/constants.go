package manageipc

import (
	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/logger"
)

type ManageIPCService struct {
	conn   *dbus.Conn
	client dbus.BusObject
	daemon dbus.BusObject
}

type ManageBus int

var (
	log *logger.Logger
)
