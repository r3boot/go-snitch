package handleripc

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/rules"
	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/go-snitch/lib/ui"
)

func (bus HandlerBus) GetRules() (string, *dbus.Error) {
	ruleset, err := sessionCache.GetAllRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hipc.GetRules: failed to fetch session rules: %v", err)
		return "", nil
	}

	data, err := json.Marshal(ruleset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hipc.GetRules: failed to encode json: %v\n", err)
		return "", nil
	}

	fmt.Printf("session ruleset: %v\n", ruleset)

	return string(data), nil
}

func (bus HandlerBus) UpdateRule(data string) (string, *dbus.Error) {
	newRule := rules.RuleDetail{}

	if err := json.Unmarshal([]byte(data), &newRule); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to unmarshal json: %v", err)
		return err.Error(), nil
	}

	sessionCache.UpdateRule(newRule)

	return "ok", nil
}

func (bus HandlerBus) DeleteRule(id int) (string, *dbus.Error) {

	sessionCache.DeleteRule(id)

	return "ok", nil
}

func (bus HandlerBus) GetVerdict(data string) (int, *dbus.Error) {
	newRequest := snitch.ConnRequest{}

	if err := json.Unmarshal([]byte(data), &newRequest); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to unmarshal json: %v", err)
		return snitch.DROP_CONN_ONCE_USER, nil
	}

	fmt.Printf("Got verdict request: %v\n", newRequest)

	// Check if we have a session rule
	sessionVerdict, err := sessionCache.GetVerdict(newRequest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sessionCache: Failed to get verdict: %v\n", err)
		os.Exit(1)
	}

	if sessionVerdict != snitch.UNKNOWN {
		fmt.Printf("Verdict by session rule\n")
		return int(sessionVerdict), nil
	}

	response := rw.HandleRequest(newRequest)

	response.Dump()

	result := snitch.DROP_CONN_ONCE_USER
	switch response.Scope {
	case ui.SCOPE_ONCE:
		{
			if response.User == ui.USER_SYSTEM {
				switch response.Action {
				case ui.ACTION_WHITELIST:
					result = snitch.ACCEPT_APP_ONCE_SYSTEM
				case ui.ACTION_BLOCK:
					result = snitch.DROP_APP_ONCE_SYSTEM
				case ui.ACTION_ALLOW:
					result = snitch.ACCEPT_CONN_ONCE_SYSTEM
				case ui.ACTION_DENY:
					result = snitch.DROP_CONN_ONCE_SYSTEM
				}
			} else {
				switch response.Action {
				case ui.ACTION_WHITELIST:
					result = snitch.ACCEPT_APP_ONCE_USER
				case ui.ACTION_BLOCK:
					result = snitch.DROP_APP_ONCE_USER
				case ui.ACTION_ALLOW:
					result = snitch.ACCEPT_CONN_ONCE_SYSTEM
				case ui.ACTION_DENY:
					result = snitch.DROP_CONN_ONCE_SYSTEM
				}
			}
		}
	case ui.SCOPE_SESSION:
		{
			if response.User == ui.USER_SYSTEM {
				switch response.Action {
				case ui.ACTION_WHITELIST:
					{
						result = snitch.ACCEPT_APP_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, snitch.ACCEPT_APP_ONCE_SYSTEM)
					}
				case ui.ACTION_BLOCK:
					{
						result = snitch.DROP_APP_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, snitch.DROP_APP_ONCE_SYSTEM)
					}
				case ui.ACTION_ALLOW:
					{
						result = snitch.ACCEPT_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, snitch.ACCEPT_CONN_ONCE_SYSTEM)
					}
				case ui.ACTION_DENY:
					{
						result = snitch.DROP_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, snitch.DROP_CONN_ONCE_SYSTEM)
					}
				}
			} else {
				switch response.Action {
				case ui.ACTION_WHITELIST:
					{
						result = snitch.ACCEPT_APP_ONCE_USER
						sessionCache.AddRule(newRequest, snitch.ACCEPT_APP_ONCE_USER)
					}
				case ui.ACTION_BLOCK:
					{
						result = snitch.DROP_APP_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, snitch.DROP_APP_ONCE_USER)
					}
				case ui.ACTION_ALLOW:
					{
						result = snitch.ACCEPT_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, snitch.ACCEPT_CONN_ONCE_USER)
					}
				case ui.ACTION_DENY:
					{
						result = snitch.DROP_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, snitch.DROP_CONN_ONCE_USER)
					}
				}
			}
		}
	case ui.SCOPE_FOREVER:
		{
			if response.User == ui.USER_SYSTEM {
				switch response.Action {
				case ui.ACTION_WHITELIST:
					result = snitch.ACCEPT_APP_ALWAYS_SYSTEM
				case ui.ACTION_BLOCK:
					result = snitch.DROP_APP_ALWAYS_SYSTEM
				case ui.ACTION_ALLOW:
					result = snitch.ACCEPT_CONN_ALWAYS_SYSTEM
				case ui.ACTION_DENY:
					result = snitch.DROP_CONN_ALWAYS_SYSTEM
				}
			} else {
				switch response.Action {
				case ui.ACTION_WHITELIST:
					result = snitch.ACCEPT_APP_ALWAYS_USER
				case ui.ACTION_BLOCK:
					result = snitch.DROP_APP_ALWAYS_USER
				case ui.ACTION_ALLOW:
					result = snitch.ACCEPT_CONN_ALWAYS_USER
				case ui.ACTION_DENY:
					result = snitch.DROP_CONN_ALWAYS_USER
				}
			}
		}
	}

	return result, nil
}
