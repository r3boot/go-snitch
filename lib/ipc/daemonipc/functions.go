package daemonipc

import (
	"encoding/json"
	"fmt"

	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/ipc"
)

func (b DaemonBus) GetRules() (string, *dbus.Error) {
	ruleset := ruleCache.GetRules()

	data, err := json.Marshal(ruleset)
	if err != nil {
		log.Warningf("DaemonBus.GetRules: Failed to encode json: %v", err)
		return "", nil
	}

	return string(data), nil
}

func (b DaemonBus) UpdateRule(data string) (string, *dbus.Error) {
	newRule := datastructures.RuleDetail{}

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
		log.Warningf("DaemonBus.DeleteRule: Failed to delete rule: %v", err)
		return err.Error(), nil
	}

	return "ok", nil
}

func (dd *DaemonIPCService) GetVerdict(r datastructures.ConnRequest) (datastructures.ResponseType, error) {
	var err error

	methodName := fmt.Sprintf("%s.GetVerdict", ipc.UI_NAME)

	verdict := datastructures.DROP_CONN_ONCE_USER
	if r.Command == "" {
		return verdict, fmt.Errorf("DaemonIPCService.GetVerdict: Got request without command")
	}

	data, err := json.Marshal(r)
	if err != nil {
		return verdict, fmt.Errorf("DaemonIPCService.GetVerdict: Failed to encode json: %v", err)
	}

	if err = dd.handler.Call(methodName, 0, string(data)).Store(&verdict); err != nil {
		return datastructures.DROP_CONN_ONCE_USER, fmt.Errorf("DaemonIPCService.GetVerdict: Error in calling dbus: %v", err)
	}

	return verdict, nil
}
