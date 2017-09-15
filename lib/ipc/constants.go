package ipc

import "github.com/godbus/dbus"

const (
	DAEMON_NAME   string          = "net.as65342.GoSnitch.Daemon"
	DAEMON_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Daemon"
	DAEMON_PATH_S string          = "/net/as65342/GoSnitch/Daemon"

	UI_NAME   string          = "net.as65342.GoSnitch.Ui"
	UI_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Ui"
	UI_PATH_S string          = "/net/as65342/GoSnitch/Ui"
)
