package ipc

import (
	"github.com/godbus/dbus"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/request"
)

const (
	UI_NAME   string          = "net.as65342.GoSnitch.Ui"
	UI_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Ui"
	UI_PATH_S string          = "/net/as65342/GoSnitch/Ui"

	DAEMON_NAME   string          = "net.as65342.GoSnitch.Daemon"
	DAEMON_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Daemon"
	DAEMON_PATH_S string          = "/net/as65342/GoSnitch/Daemon"
)

type IPCService struct {
	conn   *dbus.Conn
	daemon dbus.BusObject
}

type UiBus int

var rw *request.RequestWindow
var sessionCache *rules.SessionCache
