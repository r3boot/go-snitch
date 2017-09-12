package manageipc

import "github.com/godbus/dbus"

type ManageIPCService struct {
	conn   *dbus.Conn
	client dbus.BusObject
	daemon dbus.BusObject
}

type ManageBus int
