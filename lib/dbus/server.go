package dbus

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

var dw *ui.DialogWindow

func (ds *DBusServer) Connect(dialog *ui.DialogWindow) (err error) {
	var (
		reply     dbus.RequestNameReply
		verdict   Verdict
		introNode *introspect.Node
	)

	if ds.conn, err = dbus.SystemBus(); err != nil {
		ds.conn = nil
		return err
	}

	reply, err = ds.conn.RequestName(NAME,
		dbus.NameFlagDoNotQueue)
	if err != nil {
		ds.conn = nil
		return err
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		ds.conn = nil
		err = errors.New("name already taken")
		return err
	}

	verdict = Verdict(0)
	ds.conn.Export(verdict, PATH, NAME)

	introNode = &introspect.Node{
		Name: PATH_S,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    NAME,
				Methods: introspect.Methods(verdict),
			},
		},
	}

	ds.conn.Export(introspect.NewIntrospectable(introNode), PATH,
		"org.freedesktop.DBus.Introspectable")

	dw = dialog

	return nil
}

func (verdict Verdict) GetVerdict(r snitch.ConnRequest) (int, *dbus.Error) {
	// Spawn gui
	fmt.Printf("Got verdict request: %v\n", r)
	dw.SetValues(r)
	dw.Show()
	response := <-dw.Verdict
	return response, nil
}
