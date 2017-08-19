package dbus

import (
	"errors"
	"fmt"
	"os"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

var dw *ui.DialogWindow

var sessionCache *rules.SessionCache

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

	sessionCache = rules.NewSessionCache()

	return nil
}

func (verdict Verdict) GetVerdict(r snitch.ConnRequest) (int, *dbus.Error) {
	// Check if we have a session rule
	sessionVerdict, err := sessionCache.GetVerdict(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sessionCache: Failed to get verdict: %v\n", err)
		os.Exit(1)
	}

	if sessionVerdict != snitch.UNKNOWN {
		fmt.Printf("Verdict by session rule\n")
		return int(sessionVerdict), nil
	}

	dw.SetValues(r)
	dw.Show()
	response := <-dw.Verdict

	switch response {
	case snitch.DROP_CONN_SESSION:
		{
			fmt.Printf("adding drop conn once rule\n")
			sessionCache.AddConnRule(r, snitch.DROP_CONN_ONCE)
		}
	case snitch.ACCEPT_CONN_SESSION:
		{
			fmt.Printf("adding accept conn once rule\n")
			sessionCache.AddConnRule(r, snitch.ACCEPT_CONN_ONCE)
		}
	case snitch.DROP_APP_SESSION:
		{
			fmt.Printf("adding drop app once rule\n")
			sessionCache.AddAppRule(r, snitch.DROP_APP_ONCE)
		}
	case snitch.ACCEPT_APP_SESSION:
		{
			fmt.Printf("adding accept app once rule\n")
			sessionCache.AddAppRule(r, snitch.ACCEPT_APP_ONCE)
		}
	}

	return response, nil
}
