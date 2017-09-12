package ipc

import (
	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/rules"
)

const (
	DAEMON_NAME   string          = "net.as65342.GoSnitch.Daemon"
	DAEMON_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Daemon"
	DAEMON_PATH_S string          = "/net/as65342/GoSnitch/Daemon"

	UI_NAME   string          = "net.as65342.GoSnitch.Ui"
	UI_PATH   dbus.ObjectPath = "/net/as65342/GoSnitch/Ui"
	UI_PATH_S string          = "/net/as65342/GoSnitch/Ui"
)

type DBusDaemon struct {
	conn *dbus.Conn
	ui   dbus.BusObject
}

type Ruleset []rules.RuleItem

type Base int
