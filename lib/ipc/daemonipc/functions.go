package daemonipc

import (
	"encoding/json"
	"fmt"

	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/common"
	"github.com/r3boot/go-snitch/lib/ipc"
	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
)

func (b DaemonBus) GetRules() (string, *dbus.Error) {
	ruleset := ruleCache.GetRules()

	data, err := json.Marshal(ruleset)
	if err != nil {
		log.Warningf("DaemonBus.GetRules: Failed to encode json: %v\n", err)
		return "", nil
	}

	return string(data), nil
}

func (b DaemonBus) UpdateRule(data string) (string, *dbus.Error) {
	newRule := rules.RuleDetail{}

	if err := json.Unmarshal([]byte(data), &newRule); err != nil {
		log.Warningf("DaemonBus.UpdateRule: Failed to unmarshal json: %v", err)
		return err.Error(), nil
	}

	if err := ruleCache.UpdateRule(newRule); err != nil {
		log.Warningf("DaemonBus.UpdateRule: Failed to update rule: %v", err)
		return err.Error(), nil
	}

	return "ok", nil
}

func (b DaemonBus) DeleteRule(id int) (string, *dbus.Error) {
	if err := ruleCache.DeleteRule(id); err != nil {
		log.Warningf("Failed to delete rule: %v", err)
		return err.Error(), nil
	}

	return "ok", nil
}

func (dd *DaemonIPCService) GetVerdict(r common.ConnRequest) (int, error) {
	var err error

	methodName := fmt.Sprintf("%s.GetVerdict", ipc.UI_NAME)

	verdict := snitch.DROP_CONN_ONCE_USER
	if r.Command == "" {
		return verdict, fmt.Errorf("DaemonIPCService.GetVerdict: Got request without command")
	}

	data, err := json.Marshal(r)
	if err != nil {
		return verdict, fmt.Errorf("DaemonIPCService.GetVerdict: Failed to encode json: %v", err)
	}

	if err = dd.handler.Call(methodName, 0, string(data)).Store(&verdict); err != nil {
		return snitch.DROP_CONN_ONCE_USER, fmt.Errorf("DaemonIPCService.GetVerdict: Error in calling dbus: %v\n", err)
	}

	return verdict, nil
}
