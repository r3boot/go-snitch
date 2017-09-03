package dbus

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/godbus/dbus"
	"github.com/godbus/dbus/introspect"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
)

var ruleCache *rules.RuleCache

func (dd *DBusDaemon) Connect(cache *rules.RuleCache) (err error) {
	if dd.conn, err = dbus.SystemBus(); err != nil {
		dd.conn = nil
		return err
	}

	dd.ui = dd.conn.Object(UI_NAME, UI_PATH)

	reply, err := dd.conn.RequestName(DAEMON_NAME, dbus.NameFlagDoNotQueue)
	if err != nil {
		dd.conn = nil
		return err
	}

	if reply != dbus.RequestNameReplyPrimaryOwner {
		dd.conn = nil
		return fmt.Errorf("dbus: Name already taken")
	}

	ruleset := Base(0)
	dd.conn.Export(ruleset, DAEMON_PATH, DAEMON_NAME)

	introNode := &introspect.Node{
		Name: DAEMON_PATH_S,
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name:    DAEMON_NAME,
				Methods: introspect.Methods(ruleset),
			},
		},
	}

	err = dd.conn.Export(introspect.NewIntrospectable(introNode), DAEMON_PATH,
		"org.freedesktop.DBus.Introspectable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dbus: Failed to export introspect: %v\n", err)
		return
	}

	ruleCache = cache

	return nil
}

func (b Base) GetRules() (string, *dbus.Error) {
	ruleset := ruleCache.GetRules()
	data, err := json.Marshal(ruleset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode json: %v\n", err)
		return "", nil
	}

	return string(data), nil
}

func (b Base) UpdateRule(data string) (string, *dbus.Error) {
	newRule := rules.RuleDetail{}

	if err := json.Unmarshal([]byte(data), &newRule); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to unmarshal json: %v", err)
		return err.Error(), nil
	}

	if err := ruleCache.UpdateRule(newRule); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update rule: %v", err)
		return err.Error(), nil
	}

	return "ok", nil
}

func (b Base) DeleteRule(id int) (string, *dbus.Error) {

	if err := ruleCache.DeleteRule(id); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to delete rule: %v\n", err)
		return err.Error(), nil
	}

	return "ok", nil
}

func (dd *DBusDaemon) GetVerdict(r snitch.ConnRequest) (verdict int, err error) {
	methodName := fmt.Sprintf("%s.GetVerdict", UI_NAME)

	verdict = snitch.DROP_CONN_ONCE_USER
	if r.Command == "" {
		err = fmt.Errorf("dbus.GetVerdict: Got request without command")
		return
	}

	if err = dd.ui.Call(methodName, 0, r).Store(&verdict); err != nil {
		fmt.Fprintf(os.Stderr, "Error in calling dbus: %v\n", err)
		return snitch.DROP_CONN_ONCE_USER, err
	}

	return verdict, nil
}
