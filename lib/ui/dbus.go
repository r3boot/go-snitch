package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
)

var dw *DialogWindow

var sessionCache *rules.SessionCache

func (du *DBusUi) Connect(dialog *DialogWindow, cache *rules.SessionCache) (err error) {
	var (
		reply     dbus.RequestNameReply
		verdict   Verdict
		introNode *introspect.Node
	)

	sessionCache = cache

	if du.conn, err = dbus.SystemBus(); err != nil {
		du.conn = nil
		return err
	}

	du.daemon = du.conn.Object(DAEMON_NAME, DAEMON_PATH)

	reply, err = du.conn.RequestName(UI_NAME,
		dbus.NameFlagDoNotQueue)
	if err != nil {
		du.conn = nil
		return err
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		du.conn = nil
		err = errors.New("name already taken")
		return err
	}

	verdict = Verdict(0)
	du.conn.Export(verdict, UI_PATH, UI_NAME)

	introNode = &introspect.Node{
		Name: UI_PATH_S,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    UI_NAME,
				Methods: introspect.Methods(verdict),
			},
		},
	}

	du.conn.Export(introspect.NewIntrospectable(introNode), UI_PATH,
		"org.freedesktop.DBus.Introspectable")

	dw = dialog

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
	case snitch.DROP_CONN_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.DROP_CONN_ONCE_USER)
		}
	case snitch.DROP_CONN_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.DROP_CONN_ONCE_SYSTEM)
		}
	case snitch.ACCEPT_CONN_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_CONN_ONCE_USER)
		}
	case snitch.ACCEPT_CONN_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_CONN_ONCE_SYSTEM)
		}
	case snitch.DROP_APP_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.DROP_APP_ONCE_USER)
		}
	case snitch.DROP_APP_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.DROP_APP_ONCE_SYSTEM)
		}
	case snitch.ACCEPT_APP_SESSION_USER:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_APP_ONCE_USER)
		}
	case snitch.ACCEPT_APP_SESSION_SYSTEM:
		{
			sessionCache.AddRule(r, snitch.ACCEPT_APP_ONCE_SYSTEM)
		}
	}

	return response, nil
}

func (du *DBusUi) GetRules() (ruleset []rules.RuleItem, err error) {
	methodName := fmt.Sprintf("%s.GetRules", DAEMON_NAME)

	var data string

	if err = du.daemon.Call(methodName, 0).Store(&data); err != nil {
		fmt.Fprintf(os.Stderr, "Error in calling dbus: %v\n", err)
	}

	if err = json.Unmarshal([]byte(data), &ruleset); err != nil {
		return
	}

	return
}

func (du *DBusUi) UpdateRule(newRule rules.RuleDetail) error {
	methodName := fmt.Sprintf("%s.UpdateRule", DAEMON_NAME)

	data, err := json.Marshal(newRule)
	if err != nil {
		return fmt.Errorf("ui.UpdateRule: Failed to marshal json: %v", err)
	}

	var response string
	if err = du.daemon.Call(methodName, 0, string(data)).Store(&response); err != nil {
		return fmt.Errorf("ui.UpdateRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("ui.UpdateRule: Failed to update rule: %s", response)
	}

	return nil
}

func (du *DBusUi) DeleteRule(id int) error {
	methodName := fmt.Sprintf("%s.DeleteRule", DAEMON_NAME)

	var response string
	if err := du.daemon.Call(methodName, 0, id).Store(&response); err != nil {
		return fmt.Errorf("ui.DeleteRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("ui.DeleteRule: Failed to delete rule: %s", response)
	}

	return nil
}
