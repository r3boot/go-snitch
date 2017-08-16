package dbus

import (
	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/ui"
)

const (
	NAME   string          = "net.as65342.GoSnitch"
	PATH   dbus.ObjectPath = "/net/as65342/GoSnitch"
	PATH_S string          = "/net/as65342/GoSnitch"
)

type DBusClient struct {
	conn *dbus.Conn
	obj  dbus.BusObject
}

type DBusServer struct {
	conn   *dbus.Conn
	dialog *ui.DialogWindow
}

type Verdict int
