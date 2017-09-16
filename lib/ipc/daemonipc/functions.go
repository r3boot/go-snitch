package daemonipc

import (
	"encoding/json"
	"fmt"

	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
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

func (dd *DaemonIPCService) GetVerdict(r datastructures.ConnRequest) (datastructures.Response, error) {
	var err error

	methodName := fmt.Sprintf("%s.GetVerdict", ipc.UI_NAME)

	response := datastructures.Response{}
	responseData := ""

	if r.Command == "" {
		response.Verdict = netfilter.NF_UNDEF
		return response, fmt.Errorf("DaemonIPCService.GetVerdict: Got request without command")
	}

	data, err := json.Marshal(r)
	if err != nil {
		response.Verdict = netfilter.NF_UNDEF
		return response, fmt.Errorf("DaemonIPCService.GetVerdict: Failed to encode json: %v", err)
	}

	log.Debugf("Requesting response from UI")
	if err = dd.handler.Call(methodName, 0, string(data)).Store(&responseData); err != nil {
		response.Verdict = netfilter.NF_UNDEF
		return response, fmt.Errorf("DaemonIPCService.GetVerdict: Error in calling dbus: %v", err)
	}

	err = json.Unmarshal([]byte(responseData), &response)
	if err != nil {
		response := datastructures.Response{
			Verdict: netfilter.NF_UNDEF,
		}
		return response, fmt.Errorf("DaemonIPCService.GetVerdict: Failed to unmarshal data: %v", err)
	}

	log.Debugf("DaemonIPCService.GetVerdict: got response from ui: %v", response.String())

	return response, nil
}
