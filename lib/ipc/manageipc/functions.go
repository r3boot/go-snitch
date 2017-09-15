package manageipc

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/r3boot/go-snitch/lib/datastructures"
	"github.com/r3boot/go-snitch/lib/ipc"
)

func (mipc *ManageIPCService) GetDBRules() (ruleset datastructures.Ruleset, err error) {
	methodName := fmt.Sprintf("%s.GetRules", ipc.DAEMON_NAME)

	var data string

	if err = mipc.daemon.Call(methodName, 0).Store(&data); err != nil {
		fmt.Fprintf(os.Stderr, "ManageIPCService.GetDBRules: error in calling dbus: %v\n", err)
	}

	if err = json.Unmarshal([]byte(data), &ruleset); err != nil {
		return
	}

	return
}

func (mipc *ManageIPCService) UpdateDBRule(newRule datastructures.RuleDetail) error {
	methodName := fmt.Sprintf("%s.UpdateRule", ipc.DAEMON_NAME)

	data, err := json.Marshal(newRule)
	if err != nil {
		return fmt.Errorf("ManageIPCService.UpdateDBRule: Failed to marshal json: %v", err)
	}

	var response string
	if err = mipc.daemon.Call(methodName, 0, string(data)).Store(&response); err != nil {
		return fmt.Errorf("ManageIPCService.UpdateDBRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("ManageIPCService.UpdateDBRule: Failed to update rule: %s", response)
	}

	return nil
}

func (mipc *ManageIPCService) DeleteDBRule(id int) error {
	methodName := fmt.Sprintf("%s.DeleteRule", ipc.DAEMON_NAME)

	var response string
	if err := mipc.daemon.Call(methodName, 0, id).Store(&response); err != nil {
		return fmt.Errorf("ManageIPCService.DeleteDBRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("ManageIPCService.DeleteDBRule: Failed to delete rule: %s", response)
	}

	return nil
}

func (mipc *ManageIPCService) GetClientRules() (ruleset datastructures.Ruleset, err error) {
	methodName := fmt.Sprintf("%s.GetRules", ipc.UI_NAME)

	var data string

	if err = mipc.client.Call(methodName, 0).Store(&data); err != nil {
		fmt.Fprintf(os.Stderr, "ManageIPCService.GetClientRules: Error in calling dbus: %v\n", err)
	}

	if err = json.Unmarshal([]byte(data), &ruleset); err != nil {
		return
	}

	return
}

func (mipc *ManageIPCService) UpdateClientRule(newRule datastructures.RuleDetail) error {
	methodName := fmt.Sprintf("%s.UpdateRule", ipc.UI_NAME)

	data, err := json.Marshal(newRule)
	if err != nil {
		return fmt.Errorf("ManageIPCService.UpdateClientRule: Failed to marshal json: %v", err)
	}

	var response string
	if err = mipc.client.Call(methodName, 0, string(data)).Store(&response); err != nil {
		return fmt.Errorf("ManageIPCService.UpdateClientRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("ManageIPCService.UpdateClientRule: Failed to update rule: %s", response)
	}

	return nil
}

func (mipc *ManageIPCService) DeleteClientRule(id int) error {
	methodName := fmt.Sprintf("%s.DeleteRule", ipc.UI_NAME)

	var response string
	if err := mipc.client.Call(methodName, 0, id).Store(&response); err != nil {
		return fmt.Errorf("ManageIPCService.DeleteClientRule: Error in calling dbus: %v", err)
	}

	if response != "ok" {
		return fmt.Errorf("ManageIPCService.DeleteClientRule: Failed to delete rule: %s", response)
	}

	return nil
}
