package manageipc

import (
	"fmt"

	"github.com/godbus/dbus"
	"github.com/r3boot/go-snitch/lib/ipc"
)

func NewManageIPCService() (*ManageIPCService, error) {
	var err error

	manageipc := &ManageIPCService{}

	manageipc.conn, err = dbus.SystemBus()
	if err != nil {
		return nil, fmt.Errorf("NewIPCService failed to connect to system bus: %v", err)
	}

	manageipc.daemon = manageipc.conn.Object(ipc.DAEMON_NAME, ipc.DAEMON_PATH)

	manageipc.client = manageipc.conn.Object(ipc.UI_NAME, ipc.UI_PATH)

	return manageipc, nil
}
