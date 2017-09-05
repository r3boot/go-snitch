package ipc

import (
	"fmt"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/request"
)

func NewIPCService(requestWindow *request.RequestWindow, cache *rules.SessionCache) (*IPCService, error) {
	var err error

	rw = requestWindow
	sessionCache = cache

	du := &IPCService{}

	du.conn, err = dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("NewIPCService failed to connect to system bus: %v", err)
	}

	du.daemon = du.conn.Object(DAEMON_NAME, DAEMON_PATH)

	reply, err := du.conn.RequestName(UI_NAME, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, fmt.Errorf("NewIPCService failed to request name: %v", err)
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, fmt.Errorf("NewIPCService name already taken")
	}

	bus := UiBus(0)
	du.conn.Export(bus, UI_PATH, UI_NAME)

	introNode := &introspect.Node{
		Name: UI_PATH_S,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    UI_NAME,
				Methods: introspect.Methods(bus),
			},
		},
	}

	du.conn.Export(introspect.NewIntrospectable(introNode), UI_PATH,
		"org.freedesktop.DBus.Introspectable")

	return du, nil
}
