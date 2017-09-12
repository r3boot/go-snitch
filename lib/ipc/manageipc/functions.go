package manageipc

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/ipc"
	"github.com/r3boot/go-snitch/lib/rules"
)

func (mipc *ManageIPCService) GetDBRules() (ruleset []rules.RuleItem, err error) {
	methodName := fmt.Sprintf("%s.GetRules", ipc.DAEMON_NAME)

	var data string

	if err = mipc.daemon.Call(methodName, 0).Store(&data); err != nil {
		fmt.Fprintf(os.Stderr, "mipc.GetDBRules: error in calling dbus: %v\n", err)
	}

	if err = json.Unmarshal([]byte(data), &ruleset); err != nil {
		return
	}

	return
}

func (mipc *ManageIPCService) UpdateDBRule(newRule rules.RuleDetail) error {
	methodName := fmt.Sprintf("%s.UpdateRule", ipc.DAEMON_NAME)

	data, err := json.Marshal(newRule)
	if err != nil {
		return fmt.Errorf("mipc.UpdateDBRule: Failed to marshal json: %v", err)
	}

	var response string
	if err = mipc.daemon.Call(methodName, 0, string(data)).Store(&response); err != nil {
		return fmt.Errorf("mipc.UpdateDBRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("mipc.UpdateDBRule: Failed to update rule: %s", response)
	}

	return nil
}

func (mipc *ManageIPCService) DeleteDBRule(id int) error {
	methodName := fmt.Sprintf("%s.DeleteRule", ipc.DAEMON_NAME)

	var response string
	if err := mipc.daemon.Call(methodName, 0, id).Store(&response); err != nil {
		return fmt.Errorf("mipc.DeleteDBRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("mipc.DeleteDBRule: Failed to delete rule: %s", response)
	}

	return nil
}

func (mipc *ManageIPCService) GetClientRules() (ruleset []rules.RuleItem, err error) {
	methodName := fmt.Sprintf("%s.GetRules", ipc.UI_NAME)

	var data string

	if err = mipc.client.Call(methodName, 0).Store(&data); err != nil {
		fmt.Fprintf(os.Stderr, "mipc.GetClientRules: Error in calling dbus: %v\n", err)
	}

	if err = json.Unmarshal([]byte(data), &ruleset); err != nil {
		return
	}

	return
}

func (mipc *ManageIPCService) UpdateClientRule(newRule rules.RuleDetail) error {
	methodName := fmt.Sprintf("%s.UpdateRule", ipc.UI_NAME)

	data, err := json.Marshal(newRule)
	if err != nil {
		return fmt.Errorf("mipc.UpdateClientRule: Failed to marshal json: %v", err)
	}

	var response string
	if err = mipc.client.Call(methodName, 0, string(data)).Store(&response); err != nil {
		return fmt.Errorf("mipc.UpdateClientRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("mipc.UpdateClientRule: Failed to update rule: %s", response)
	}

	return nil
}

func (mipc *ManageIPCService) DeleteClientRule(id int) error {
	methodName := fmt.Sprintf("%s.DeleteRule", ipc.UI_NAME)

	var response string
	if err := mipc.client.Call(methodName, 0, id).Store(&response); err != nil {
		return fmt.Errorf("mipc.DeleteClientRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("mipc.DeleteClientRule: Failed to delete rule: %s", response)
	}

	return nil
}
