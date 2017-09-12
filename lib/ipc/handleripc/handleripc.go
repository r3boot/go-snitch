package handleripc

import (
	"fmt"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/r3boot/go-snitch/lib/ipc"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/ui/request"
)

func NewHandlerIPCService(requestWindow *request.RequestWindow, cache *rules.SessionCache) (*HandlerIPCService, error) {
	var err error

	rw = requestWindow
	sessionCache = cache

	handleripc := &HandlerIPCService{}

	handleripc.conn, err = dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("NewIPCService failed to connect to system bus: %v", err)
	}

	handleripc.daemon = handleripc.conn.Object(ipc.DAEMON_NAME, ipc.DAEMON_PATH)

	reply, err := handleripc.conn.RequestName(ipc.UI_NAME, dbus.NameFlagDoNotQueue)
	if err != nil {
		return nil, fmt.Errorf("NewIPCService failed to request name: %v", err)
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		return nil, fmt.Errorf("NewIPCService name already taken")
	}

	bus := HandlerBus(0)
	handleripc.conn.Export(bus, ipc.UI_PATH, ipc.UI_NAME)

	introNode := &introspect.Node{
		Name: ipc.UI_PATH_S,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    ipc.UI_NAME,
				Methods: introspect.Methods(bus),
			},
		},
	}

	handleripc.conn.Export(introspect.NewIntrospectable(introNode), ipc.UI_PATH,
		"org.freedesktop.DBus.Introspectable")

	return handleripc, nil
}
