package handleripc

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/datastructures"
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
	newRule := datastructures.RuleDetail{}

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

func (bus HandlerBus) GetVerdict(data string) (datastructures.ResponseType, *dbus.Error) {
	newRequest := datastructures.ConnRequest{}

	if err := json.Unmarshal([]byte(data), &newRequest); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to unmarshal json: %v", err)
		return datastructures.RESPONSE_UNKNOWN, nil
	}

	fmt.Printf("Got verdict request: %v\n", newRequest)

	// Check if we have a session rule
	sessionVerdict, err := sessionCache.GetVerdict(newRequest)
	if err != nil {
		log.Warningf("HandlerBus.GetVerdict: %v", err)
	}

	if sessionVerdict != datastructures.RESPONSE_UNKNOWN {
		log.Debugf("Verdict by session rule\n")
		return sessionVerdict, nil
	}

	response := rw.HandleRequest(newRequest)

	log.Debugf(response.String())

	result := datastructures.DROP_CONN_ONCE_USER
	switch response.Scope {
	case datastructures.SCOPE_ONCE:
		{
			if response.User == datastructures.USER_SYSTEM {
				switch response.Action {
				case datastructures.ACTION_WHITELIST:
					result = datastructures.ACCEPT_APP_ONCE_SYSTEM
				case datastructures.ACTION_BLOCK:
					result = datastructures.DROP_APP_ONCE_SYSTEM
				case datastructures.ACTION_ALLOW:
					result = datastructures.ACCEPT_CONN_ONCE_SYSTEM
				case datastructures.ACTION_DENY:
					result = datastructures.DROP_CONN_ONCE_SYSTEM
				}
			} else {
				switch response.Action {
				case datastructures.ACTION_WHITELIST:
					result = datastructures.ACCEPT_APP_ONCE_USER
				case datastructures.ACTION_BLOCK:
					result = datastructures.DROP_APP_ONCE_USER
				case datastructures.ACTION_ALLOW:
					result = datastructures.ACCEPT_CONN_ONCE_SYSTEM
				case datastructures.ACTION_DENY:
					result = datastructures.DROP_CONN_ONCE_SYSTEM
				}
			}
		}
	case datastructures.SCOPE_SESSION:
		{
			if response.User == datastructures.USER_SYSTEM {
				switch response.Action {
				case datastructures.ACTION_WHITELIST:
					{
						result = datastructures.ACCEPT_APP_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, datastructures.ACCEPT_APP_ONCE_SYSTEM)
					}
				case datastructures.ACTION_BLOCK:
					{
						result = datastructures.DROP_APP_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, datastructures.DROP_APP_ONCE_SYSTEM)
					}
				case datastructures.ACTION_ALLOW:
					{
						result = datastructures.ACCEPT_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, datastructures.ACCEPT_CONN_ONCE_SYSTEM)
					}
				case datastructures.ACTION_DENY:
					{
						result = datastructures.DROP_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, datastructures.DROP_CONN_ONCE_SYSTEM)
					}
				}
			} else {
				switch response.Action {
				case datastructures.ACTION_WHITELIST:
					{
						result = datastructures.ACCEPT_APP_ONCE_USER
						sessionCache.AddRule(newRequest, datastructures.ACCEPT_APP_ONCE_USER)
					}
				case datastructures.ACTION_BLOCK:
					{
						result = datastructures.DROP_APP_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, datastructures.DROP_APP_ONCE_USER)
					}
				case datastructures.ACTION_ALLOW:
					{
						result = datastructures.ACCEPT_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, datastructures.ACCEPT_CONN_ONCE_USER)
					}
				case datastructures.ACTION_DENY:
					{
						result = datastructures.DROP_CONN_ONCE_SYSTEM
						sessionCache.AddRule(newRequest, datastructures.DROP_CONN_ONCE_USER)
					}
				}
			}
		}
	case datastructures.SCOPE_FOREVER:
		{
			if response.User == datastructures.USER_SYSTEM {
				switch response.Action {
				case datastructures.ACTION_WHITELIST:
					result = datastructures.ACCEPT_APP_ALWAYS_SYSTEM
				case datastructures.ACTION_BLOCK:
					result = datastructures.DROP_APP_ALWAYS_SYSTEM
				case datastructures.ACTION_ALLOW:
					result = datastructures.ACCEPT_CONN_ALWAYS_SYSTEM
				case datastructures.ACTION_DENY:
					result = datastructures.DROP_CONN_ALWAYS_SYSTEM
				}
			} else {
				switch response.Action {
				case datastructures.ACTION_WHITELIST:
					result = datastructures.ACCEPT_APP_ALWAYS_USER
				case datastructures.ACTION_BLOCK:
					result = datastructures.DROP_APP_ALWAYS_USER
				case datastructures.ACTION_ALLOW:
					result = datastructures.ACCEPT_CONN_ALWAYS_USER
				case datastructures.ACTION_DENY:
					result = datastructures.DROP_CONN_ALWAYS_USER
				}
			}
		}
	}

	return result, nil
}
