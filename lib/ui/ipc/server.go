package ipc

import (
	"fmt"
	"os"

	"github.com/godbus/dbus"
	"github.com/r3boot/go-snitch/lib/snitch"
	"github.com/r3boot/test/lib/ui"
)

func (bus UiBus) GetVerdict(r snitch.ConnRequest) (int, *dbus.Error) {
	// Check if we have a session rule
	sessionVerdict, err := sessionCache.GetVerdict(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sessionCache: Failed to get verdict: %v\n", err)
		os.Exit(1)
	}

	if sessionVerdict != snitch.UNKNOWN {
		fmt.Printf("Verdict by session rule\n")
		return int(sessionVerdict), nil
	}

	response := rw.HandleRequest(r)

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
						sessionCache.AddRule(r, snitch.ACCEPT_APP_ONCE_SYSTEM)
					}
				case ui.ACTION_BLOCK:
					{
						result = snitch.DROP_APP_ONCE_SYSTEM
						sessionCache.AddRule(r, snitch.DROP_APP_ONCE_SYSTEM)
					}
				case ui.ACTION_ALLOW:
					{
						result = snitch.ACCEPT_CONN_ONCE_SYSTEM
						sessionCache.AddRule(r, snitch.ACCEPT_CONN_ONCE_SYSTEM)
					}
				case ui.ACTION_DENY:
					{
						result = snitch.DROP_CONN_ONCE_SYSTEM
						sessionCache.AddRule(r, snitch.DROP_CONN_ONCE_SYSTEM)
					}
				}
			} else {
				switch response.Action {
				case ui.ACTION_WHITELIST:
					{
						result = snitch.ACCEPT_APP_ONCE_USER
						sessionCache.AddRule(r, snitch.ACCEPT_APP_ONCE_USER)
					}
				case ui.ACTION_BLOCK:
					{
						result = snitch.DROP_APP_ONCE_SYSTEM
						sessionCache.AddRule(r, snitch.DROP_APP_ONCE_USER)
					}
				case ui.ACTION_ALLOW:
					{
						result = snitch.ACCEPT_CONN_ONCE_SYSTEM
						sessionCache.AddRule(r, snitch.ACCEPT_CONN_ONCE_USER)
					}
				case ui.ACTION_DENY:
					{
						result = snitch.DROP_CONN_ONCE_SYSTEM
						sessionCache.AddRule(r, snitch.DROP_CONN_ONCE_USER)
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
