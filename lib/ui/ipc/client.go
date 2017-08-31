package ipc

import (
	"encoding/json"
	"fmt"
	"github.com/r3boot/go-snitch/lib/rules"
	"os"
)

func (du *IPCService) GetRules() (ruleset []rules.RuleItem, err error) {
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

func (du *IPCService) UpdateRule(newRule rules.RuleDetail) error {
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

func (du *IPCService) DeleteRule(id int) error {
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
