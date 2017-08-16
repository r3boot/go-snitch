package dbus

import (
	"fmt"

	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/snitch"
)

func (dc *DBusClient) Connect() (err error) {
	if dc.conn, err = dbus.SystemBus(); err != nil {
		dc.conn = nil
		return err
	}

	dc.obj = dc.conn.Object(NAME, PATH)

	return nil
}

func (dc *DBusClient) GetVerdict(r snitch.ConnRequest) (verdict int, err error) {
	var (
		methodName string
	)

	methodName = fmt.Sprintf("%s.GetVerdict", NAME)

	verdict = snitch.DROP_CONN_ONCE

	fmt.Printf("%v\n", r)

	if err = dc.obj.Call(methodName, 0, r).Store(&verdict); err != nil {
		return snitch.DROP_CONN_ONCE, err
	}

	return verdict, nil
}
