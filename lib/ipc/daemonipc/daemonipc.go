package daemonipc

import (
	"fmt"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/r3boot/go-snitch/lib/ipc"
	"github.com/r3boot/go-snitch/lib/logger"
	"github.com/r3boot/go-snitch/lib/rules"
)

func NewDaemonIPCService(l *logger.Logger, cache *rules.RuleCache) (*DaemonIPCService, error) {
	var err error

	log = l
	ruleCache = cache

	daemonipc := &DaemonIPCService{}

	if daemonipc.conn, err = dbus.SystemBus(); err != nil {
		return nil, fmt.Errorf("NewDaemonIPCService: Failed to connect to systembus: %v", err)
	}

	daemonipc.handler = daemonipc.conn.Object(ipc.UI_NAME, ipc.UI_PATH)

	reply, err := daemonipc.conn.RequestName(ipc.DAEMON_NAME, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, fmt.Errorf("NewDaemonIPCService: Failed to request name %s: %v", ipc.DAEMON_NAME, err)
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, fmt.Errorf("NewDaemonIPCService: Name already taken")
	}

	ruleset := DaemonBus(0)
	daemonipc.conn.Export(ruleset, ipc.DAEMON_PATH, ipc.DAEMON_NAME)

	introNode := &introspect.Node{
		Name: ipc.DAEMON_PATH_S,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    ipc.DAEMON_NAME,
				Methods: introspect.Methods(ruleset),
			},
		},
	}

	err = daemonipc.conn.Export(introspect.NewIntrospectable(introNode), ipc.DAEMON_PATH,
		"org.freedesktop.DBus.Introspectable")
	if err != nil {
		return nil, fmt.Errorf("NewDaemonIPCService: Failed to export introspected functions: %v", err)
	}

	return daemonipc, nil
}
