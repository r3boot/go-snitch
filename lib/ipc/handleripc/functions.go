package handleripc

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/godbus/dbus"

	"github.com/r3boot/go-snitch/lib/3rdparty/go-netfilter-queue"
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

func (bus HandlerBus) GetVerdict(data string) (string, *dbus.Error) {
	request := datastructures.ConnRequest{}
	response := datastructures.Response{}

	if err := json.Unmarshal([]byte(data), &request); err != nil {
		msg := fmt.Sprintf("HandlerBus.GetVerdict: Failed to unmarshal json: %v", err)
		log.Warningf(msg)
		response.Verdict = netfilter.NF_UNDEF
		return response.ToJSON(), dbus.NewError(msg, nil)
	}

	// Check if we have a session rule
	sessionVerdict, err := sessionCache.GetVerdict(request)
	if err != nil {
		msg := fmt.Sprintf("HandlerBus.GetVerdict: %v", err)
		log.Warningf(msg)
	}

	if sessionVerdict != netfilter.NF_UNDEF {
		log.Debugf("HandlerBus.GetVerdict: verdict by session rule")
		response.Verdict = sessionVerdict
		return response.ToJSON(), nil
	}

	response = rw.HandleRequest(request)

	switch response.Scope {
	case datastructures.SCOPE_ONCE, datastructures.SCOPE_FOREVER:
		{
			log.Debugf("HandlerBus.GetVerdict: sending response: %s", response)
			return response.ToJSON(), nil
		}
	case datastructures.SCOPE_SESSION:
		{
			sessionCache.AddRule(request, response)
			log.Debugf("HandlerBus.GetVerdict: sending response: %s", response)
			return response.ToJSON(), nil
		}
	}

	response.Verdict = netfilter.NF_UNDEF
	return response.ToJSON(), nil
}
